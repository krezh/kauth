package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/oauth"
	"kauth/pkg/session"

	"golang.org/x/oauth2"
)

type RefreshHandler struct {
	provider        *oauth.Provider
	jwtManager      *jwt.Manager
	sessionClient   *session.Client
	kubeconfigGen   *KubeconfigGenerator
	refreshTokenTTL time.Duration
	allowedGroups   []string // if non-empty, user must belong to at least one group
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	RequestID    string `json:"request_id,omitempty"`
}

type RefreshResponse struct {
	IDToken      string `json:"id_token"`      // New ID token for management API calls
	RefreshToken string `json:"refresh_token"` // New rotated refresh token
	ExpiresIn    int64  `json:"expires_in"`    // ID token expiry in seconds
	TokenType    string `json:"token_type"`    // Always "Bearer"
	Kubeconfig   string `json:"kubeconfig"`    // Updated kubeconfig
}

func NewRefreshHandler(
	provider *oauth.Provider,
	jwtManager *jwt.Manager,
	sessionClient *session.Client,
	clusterName, clusterServer, clusterCA string,
	refreshTokenTTL time.Duration,
	allowedGroups []string,
) *RefreshHandler {
	return &RefreshHandler{
		provider:      provider,
		jwtManager:    jwtManager,
		sessionClient: sessionClient,
		kubeconfigGen: &KubeconfigGenerator{
			ClusterName:   clusterName,
			ClusterServer: clusterServer,
			ClusterCA:     clusterCA,
		},
		refreshTokenTTL: refreshTokenTTL,
		allowedGroups:   allowedGroups,
	}
}

func (h *RefreshHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "Missing refresh_token", http.StatusBadRequest)
		return
	}
	if req.RequestID != "" && (len(req.RequestID) < 20 || len(req.RequestID) > 128) {
		http.Error(w, "Invalid request_id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Decode the credential; the server-side session is the lifetime authority.
	refreshToken, err := h.jwtManager.DecodeRefreshToken(req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrInvalidSignature):
			slog.WarnContext(ctx, "refresh: invalid signature")
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		default:
			slog.WarnContext(ctx, "refresh: invalid token", "error", err)
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		}
		return
	}

	slog.DebugContext(ctx, "refresh attempt", "user", refreshToken.UserEmail, "rotation_counter", refreshToken.RotationCounter, "session", refreshToken.SessionID)

	// Refresh the OIDC token using the provider
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = ctx2

	if refreshToken.SessionID == "" {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	if req.RequestID != "" {
		sess, encryptedResult, resultErr := h.sessionClient.GetRefreshResult(ctx, refreshToken.SessionID, h.refreshTokenTTL)
		if resultErr == nil {
			result, decodeErr := h.jwtManager.DecodeRefreshResult(encryptedResult)
			if decodeErr == nil &&
				subtle.ConstantTimeCompare([]byte(result.RequestID), []byte(req.RequestID)) == 1 &&
				subtle.ConstantTimeCompare([]byte(result.PreviousRefreshToken), []byte(req.RefreshToken)) == 1 {
				if subtle.ConstantTimeCompare([]byte(result.RefreshToken), []byte(sess.Status.RefreshToken)) == 1 {
					h.writeRefreshResponse(w, result.IDToken, result.RefreshToken, result.IDTokenExpiresAt, result.Email, result.Username)
					return
				}
				if subtle.ConstantTimeCompare([]byte(result.PreviousRefreshToken), []byte(sess.Status.RefreshToken)) == 1 {
					lockID, claimErr := h.sessionClient.ClaimRefreshToken(ctx, refreshToken.SessionID, req.RefreshToken, time.Minute, h.refreshTokenTTL)
					if claimErr != nil {
						http.Error(w, "Refresh recovery is already in progress", http.StatusConflict)
						return
					}
					defer h.releaseRefreshClaim(refreshToken.SessionID, lockID)
					if err := h.sessionClient.ExtendRefreshTokenClaim(ctx, refreshToken.SessionID, lockID, h.refreshTokenTTL); err != nil {
						http.Error(w, "Session is no longer active", http.StatusUnauthorized)
						return
					}
					if err := h.sessionClient.RotateRefreshToken(ctx, refreshToken.SessionID, req.RefreshToken, lockID, v1alpha1.OAuthSessionStatus{
						Phase:        v1alpha1.SessionActive,
						Email:        result.Email,
						Username:     result.Username,
						RefreshToken: result.RefreshToken,
						Groups:       result.Groups,
					}); err != nil {
						http.Error(w, "Failed to complete refresh recovery", http.StatusInternalServerError)
						return
					}
					h.writeRefreshResponse(w, result.IDToken, result.RefreshToken, result.IDTokenExpiresAt, result.Email, result.Username)
					return
				}
			}
		} else if !errors.Is(resultErr, session.ErrPreconditionFailed) {
			slog.ErrorContext(ctx, "refresh: failed to check prior result", "error", resultErr)
			http.Error(w, "Failed to refresh token", http.StatusInternalServerError)
			return
		}
	}
	lockID, err := h.sessionClient.ClaimRefreshToken(ctx, refreshToken.SessionID, req.RefreshToken, time.Minute, h.refreshTokenTTL)
	if err != nil {
		if errors.Is(err, session.ErrPreconditionFailed) {
			slog.WarnContext(ctx, "refresh: stale, inactive, or concurrent session", "user", refreshToken.UserEmail)
			http.Error(w, "Session is no longer active", http.StatusUnauthorized)
		} else {
			slog.ErrorContext(ctx, "refresh: failed to claim session", "user", refreshToken.UserEmail, "error", err)
			http.Error(w, "Failed to refresh token", http.StatusInternalServerError)
		}
		return
	}
	defer h.releaseRefreshClaim(refreshToken.SessionID, lockID)

	// Create oauth2 token from stored refresh token
	oldToken := &oauth2.Token{
		RefreshToken: refreshToken.OIDCRefreshToken,
	}

	httpClient := oauth.NewMetricsHTTPClient("token_refresh")
	ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	// Use the provider to refresh
	newToken, err := h.provider.OAuth2Config.TokenSource(ctxWithClient, oldToken).Token()
	if err != nil {
		slog.WarnContext(ctx, "refresh: OIDC token refresh failed", "user", refreshToken.UserEmail, "error", err)
		http.Error(w, "Failed to refresh token", http.StatusUnauthorized)
		return
	}
	// Once the provider may have rotated its token, finish persisting the result
	// even if the client disconnects and cancels the request context.
	commitCtx, commitCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer commitCancel()

	// Extract new ID token
	idToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		slog.ErrorContext(ctx, "refresh: no ID token in response", "user", refreshToken.UserEmail)
		http.Error(w, "No ID token in refresh response", http.StatusInternalServerError)
		return
	}

	// Verify the new ID token and extract claims
	claims, verifiedIDToken, err := VerifyAndExtractClaims(commitCtx, h.provider, idToken)
	if err != nil {
		slog.WarnContext(ctx, "refresh: ID token verification failed", "user", refreshToken.UserEmail, "error", err)
		http.Error(w, "Token verification failed", http.StatusInternalServerError)
		return
	}

	// Verify the user email matches (security check)
	if claims.Email != refreshToken.UserEmail {
		slog.WarnContext(ctx, "refresh: user mismatch", "token_user", refreshToken.UserEmail, "claimed_email", claims.Email)
		http.Error(w, "Token user mismatch", http.StatusUnauthorized)
		return
	}

	// Re-check group membership so that users removed from allowed groups
	// cannot continue refreshing indefinitely until session expiry.
	if len(h.allowedGroups) > 0 {
		authorized := false
		for _, g := range claims.Groups {
			if slices.Contains(h.allowedGroups, g) {
				authorized = true
				break
			}
		}
		if !authorized {
			audit.AuthorizationDeny(ctx, r, claims.Email, claims.Groups, h.allowedGroups)
			slog.WarnContext(ctx, "refresh: user no longer in allowed groups", "user", claims.Email, "groups", claims.Groups)
			http.Error(w, "Forbidden: user not in allowed groups", http.StatusForbidden)
			return
		}
	}
	if err := h.sessionClient.ExtendRefreshTokenClaim(commitCtx, refreshToken.SessionID, lockID, h.refreshTokenTTL); err != nil {
		slog.WarnContext(ctx, "refresh: session expired during refresh", "user", claims.Email, "error", err)
		http.Error(w, "Session is no longer active", http.StatusUnauthorized)
		return
	}

	// Create new rotated refresh token with incremented counter
	newRefreshToken, err := h.jwtManager.CreateRefreshToken(
		claims.Email,
		newToken.RefreshToken,
		refreshToken.SessionID,
		refreshToken.RotationCounter+1,
		h.refreshTokenTTL,
	)
	if err != nil {
		slog.ErrorContext(ctx, "refresh: failed to create refresh token", "user", claims.Email, "error", err)
		http.Error(w, "Failed to create new refresh token", http.StatusInternalServerError)
		return
	}
	idTokenExpiry := verifiedIDToken.Expiry
	if req.RequestID != "" {
		encryptedResult, err := h.jwtManager.CreateRefreshResult(jwt.RefreshResult{
			RequestID:            req.RequestID,
			PreviousRefreshToken: req.RefreshToken,
			RefreshToken:         newRefreshToken,
			IDToken:              idToken,
			IDTokenExpiresAt:     idTokenExpiry,
			Email:                claims.Email,
			Username:             claims.PreferredUsername,
			Groups:               claims.Groups,
		})
		if err != nil {
			http.Error(w, "Failed to stage refresh result", http.StatusInternalServerError)
			return
		}
		if err := h.sessionClient.StageRefreshResult(commitCtx, refreshToken.SessionID, lockID, encryptedResult); err != nil {
			slog.ErrorContext(ctx, "refresh: failed to stage retry result", "error", err)
			http.Error(w, "Failed to stage refresh result", http.StatusInternalServerError)
			return
		}
	}
	// Commit rotation before returning the new credential. A concurrent refresh,
	// revoke, or expiry causes the exact-token precondition to fail.
	err = h.sessionClient.RotateRefreshToken(commitCtx, refreshToken.SessionID, req.RefreshToken, lockID, v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		Email:        claims.Email,
		Username:     claims.PreferredUsername,
		RefreshToken: newRefreshToken,
		Groups:       claims.Groups,
	})
	if err != nil {
		if errors.Is(err, session.ErrPreconditionFailed) {
			slog.WarnContext(ctx, "refresh: concurrent rotation rejected", "user", claims.Email)
			http.Error(w, "Token replay detected", http.StatusUnauthorized)
		} else {
			slog.ErrorContext(ctx, "refresh: failed to persist rotation", "user", claims.Email, "error", err)
			http.Error(w, "Failed to rotate refresh token", http.StatusInternalServerError)
		}
		return
	}
	expiresIn := max(int64(time.Until(idTokenExpiry).Seconds()), 0)

	slog.InfoContext(ctx, "refresh: success",
		"user", claims.Email,
		"name", claims.Name,
		"sub", claims.Sub,
		"groups", claims.Groups,
		"rotation_counter", refreshToken.RotationCounter+1,
		"cluster", h.kubeconfigGen.ClusterName,
		"expires_in", fmt.Sprintf("%ds", expiresIn),
	)

	h.writeRefreshResponse(w, idToken, newRefreshToken, idTokenExpiry, claims.Email, claims.PreferredUsername)
}

func (h *RefreshHandler) releaseRefreshClaim(sessionID, lockID string) {
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer releaseCancel()
	if err := h.sessionClient.ReleaseRefreshTokenClaim(releaseCtx, sessionID, lockID); err != nil {
		slog.Error("refresh: failed to release session claim", "session", sessionID, "error", err)
	}
}

func (h *RefreshHandler) writeRefreshResponse(w http.ResponseWriter, idToken, refreshToken string, idTokenExpiry time.Time, email, username string) {
	expiresIn := max(int64(time.Until(idTokenExpiry).Seconds()), 0)
	writeJSON(w, RefreshResponse{
		IDToken:      idToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
		Kubeconfig:   h.kubeconfigGen.Generate(email, username),
	})
}
