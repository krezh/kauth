package handlers

import (
	"context"
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
	rotationWindow  int      // max rotation counter lag to accept (replay-attack window)
	allowedGroups   []string // if non-empty, user must belong to at least one group
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	IDToken      string `json:"id_token"`      // New ID token for Kubernetes
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
	rotationWindow int,
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
		rotationWindow:  rotationWindow,
		allowedGroups:   allowedGroups,
	}
}

func (h *RefreshHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "Missing refresh_token", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Validate and decrypt refresh token
	refreshToken, err := h.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpiredToken):
			slog.WarnContext(ctx, "refresh: token expired")
			http.Error(w, "Refresh token expired", http.StatusUnauthorized)
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

	if refreshToken.SessionID != "" {
		// Update last-used before validating so the expiry goroutine sees fresh
		// activity and does not race to expire a session that is actively in use.
		_ = h.sessionClient.UpdateLastUsed(ctx, refreshToken.SessionID)
		if err := h.sessionClient.ValidateSession(ctx, refreshToken.SessionID, v1alpha1.SessionActive); err != nil {
			slog.WarnContext(ctx, "refresh: session invalid", "user", refreshToken.UserEmail, "error", err)
			http.Error(w, "Session is no longer active", http.StatusUnauthorized)
			return
		}

		// Replay-attack check: the session CRD stores the latest valid refresh token.
		// If the incoming counter is behind the stored counter, a rotated-away token
		// is being replayed.
		if sess, err := h.sessionClient.Get(ctx, refreshToken.SessionID); err == nil && sess.Status.RefreshToken != "" {
			if stored, err := h.jwtManager.DecodeRefreshToken(sess.Status.RefreshToken); err == nil {
				if refreshToken.RotationCounter < stored.RotationCounter ||
					refreshToken.RotationCounter > stored.RotationCounter+h.rotationWindow {
					slog.WarnContext(ctx, "refresh: replay attack detected",
						"user", refreshToken.UserEmail,
						"incoming_counter", refreshToken.RotationCounter,
						"stored_counter", stored.RotationCounter,
					)
					http.Error(w, "Token replay detected", http.StatusUnauthorized)
					return
				}
			}
		}
	}

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

	// Extract new ID token
	idToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		slog.ErrorContext(ctx, "refresh: no ID token in response", "user", refreshToken.UserEmail)
		http.Error(w, "No ID token in refresh response", http.StatusInternalServerError)
		return
	}

	// Verify the new ID token and extract claims
	claims, _, err := VerifyAndExtractClaims(ctx, h.provider, idToken)
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

	// Update session with new refresh token
	if refreshToken.SessionID != "" {
		_ = h.sessionClient.UpdateStatus(ctx, refreshToken.SessionID, v1alpha1.OAuthSessionStatus{
			Phase:        v1alpha1.SessionActive,
			Email:        claims.Email,
			Username:     claims.PreferredUsername,
			RefreshToken: newRefreshToken,
			Groups:       claims.Groups,
		})
	}

	expiresIn := int64(0)
	if !newToken.Expiry.IsZero() {
		expiresIn = int64(time.Until(newToken.Expiry).Seconds())
	}

	slog.InfoContext(ctx, "refresh: success",
		"user", claims.Email,
		"name", claims.Name,
		"sub", claims.Sub,
		"groups", claims.Groups,
		"rotation_counter", refreshToken.RotationCounter+1,
		"cluster", h.kubeconfigGen.ClusterName,
		"expires_in", fmt.Sprintf("%ds", expiresIn),
	)

	writeJSON(w, RefreshResponse{
		IDToken:      idToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
		Kubeconfig:   h.kubeconfigGen.Generate(claims.Email, claims.PreferredUsername),
	})
}
