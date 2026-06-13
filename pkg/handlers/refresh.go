package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
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
	rotationWindow  int // max rotation counter lag to accept (replay-attack window)
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
) *RefreshHandler {
	return &RefreshHandler{
		provider:   provider,
		jwtManager: jwtManager,
		sessionClient: sessionClient,
		kubeconfigGen: &KubeconfigGenerator{
			ClusterName:   clusterName,
			ClusterServer: clusterServer,
			ClusterCA:     clusterCA,
		},
		refreshTokenTTL: refreshTokenTTL,
		rotationWindow:  rotationWindow,
	}
}

func (h *RefreshHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "Missing refresh_token", http.StatusBadRequest)
		return
	}

	// Validate and decrypt refresh token
	refreshToken, err := h.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		switch err {
		case jwt.ErrExpiredToken:
			log.Printf("REFRESH_FAILURE: reason=token_expired")
			http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		case jwt.ErrInvalidSignature:
			log.Printf("REFRESH_FAILURE: reason=invalid_signature")
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		default:
			log.Printf("REFRESH_FAILURE: reason=invalid_token error=%q", err)
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		}
		return
	}

	log.Printf("REFRESH_ATTEMPT: user=%q rotation_counter=%d session=%q", refreshToken.UserEmail, refreshToken.RotationCounter, refreshToken.SessionID)

	// Refresh the OIDC token using the provider
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if refreshToken.SessionID != "" {
		// Update last-used before validating so the expiry goroutine sees fresh
		// activity and does not race to expire a session that is actively in use.
		_ = h.sessionClient.UpdateLastUsed(ctx, refreshToken.SessionID)
		if err := h.sessionClient.ValidateSession(ctx, refreshToken.SessionID, v1alpha1.SessionActive); err != nil {
			log.Printf("REFRESH_FAILURE: user=%q reason=session_invalid error=%q", refreshToken.UserEmail, err)
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
					log.Printf("REFRESH_FAILURE: user=%q reason=replay_attack incoming_counter=%d stored_counter=%d",
						refreshToken.UserEmail, refreshToken.RotationCounter, stored.RotationCounter)
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
		log.Printf("REFRESH_FAILURE: user=%q reason=oidc_refresh_failed error=%q", refreshToken.UserEmail, err)
		http.Error(w, fmt.Sprintf("Failed to refresh token: %v", err), http.StatusUnauthorized)
		return
	}

	// Extract new ID token
	idToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		log.Printf("REFRESH_FAILURE: user=%q reason=no_id_token", refreshToken.UserEmail)
		http.Error(w, "No ID token in refresh response", http.StatusInternalServerError)
		return
	}

	// Verify the new ID token and extract claims
	claims, _, err := VerifyAndExtractClaims(ctx, h.provider, idToken)
	if err != nil {
		log.Printf("REFRESH_FAILURE: user=%q reason=id_token_verification_failed error=%q", refreshToken.UserEmail, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify the user email matches (security check)
	if claims.Email != refreshToken.UserEmail {
		log.Printf("REFRESH_FAILURE: user=%q reason=user_mismatch claimed_email=%q", refreshToken.UserEmail, claims.Email)
		http.Error(w, "Token user mismatch", http.StatusUnauthorized)
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
		log.Printf("REFRESH_FAILURE: user=%q reason=create_refresh_token_failed error=%q", claims.Email, err)
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
		})
	}

	// Calculate expires_in
	expiresIn := int64(0)
	if !newToken.Expiry.IsZero() {
		expiresIn = int64(time.Until(newToken.Expiry).Seconds())
	}

	// Log successful token refresh
	log.Printf("REFRESH_SUCCESS: user=%q name=%q sub=%q groups=%v rotation_counter=%d cluster=%q expires_in=%ds",
		claims.Email, claims.Name, claims.Sub, claims.Groups, refreshToken.RotationCounter+1, h.kubeconfigGen.ClusterName, expiresIn)

	// Generate updated kubeconfig
	kubeconfig := h.kubeconfigGen.Generate(claims.Email, claims.PreferredUsername)

	resp := RefreshResponse{
		IDToken:      idToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
		Kubeconfig:   kubeconfig,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
