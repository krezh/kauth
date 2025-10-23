package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"kauth/pkg/jwt"
	"kauth/pkg/oauth"

	"golang.org/x/oauth2"
)

type RefreshHandler struct {
	provider        *oauth.Provider
	jwtManager      *jwt.Manager
	clusterName     string
	clusterServer   string
	clusterCA       string
	refreshTokenTTL time.Duration
	rotationWindow  int // Number of previous tokens to accept
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
	clusterName, clusterServer, clusterCA string,
	refreshTokenTTL time.Duration,
	rotationWindow int,
) *RefreshHandler {
	return &RefreshHandler{
		provider:        provider,
		jwtManager:      jwtManager,
		clusterName:     clusterName,
		clusterServer:   clusterServer,
		clusterCA:       clusterCA,
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
	refreshToken, err := h.jwtManager.ValidateRefreshToken(req.RefreshToken, h.rotationWindow)
	if err != nil {
		switch err {
		case jwt.ErrExpiredToken:
			http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		case jwt.ErrInvalidSignature:
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		default:
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		}
		return
	}

	// Refresh the OIDC token using the provider
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Create oauth2 token from stored refresh token
	oldToken := &oauth2.Token{
		RefreshToken: refreshToken.OIDCRefreshToken,
	}

	// Use the provider to refresh
	newToken, err := h.provider.OAuth2Config.TokenSource(ctx, oldToken).Token()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to refresh token: %v", err), http.StatusUnauthorized)
		return
	}

	// Extract new ID token
	idToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID token in refresh response", http.StatusInternalServerError)
		return
	}

	// Verify the new ID token
	verified, err := h.provider.VerifyIDToken(ctx, idToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("ID token verification failed: %v", err), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := verified.Claims(&claims); err != nil {
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	// Verify the user email matches (security check)
	if claims.Email != refreshToken.UserEmail {
		http.Error(w, "Token user mismatch", http.StatusUnauthorized)
		return
	}

	// Create new rotated refresh token with incremented counter
	newRefreshToken, err := h.jwtManager.CreateRefreshToken(
		claims.Email,
		newToken.RefreshToken, // New OIDC refresh token
		refreshToken.RotationCounter+1,
		h.refreshTokenTTL,
	)
	if err != nil {
		http.Error(w, "Failed to create new refresh token", http.StatusInternalServerError)
		return
	}

	// Calculate expires_in
	expiresIn := int64(0)
	if !newToken.Expiry.IsZero() {
		expiresIn = int64(time.Until(newToken.Expiry).Seconds())
	}

	// Generate updated kubeconfig
	kubeconfig := h.generateKubeconfig(claims.Email, idToken)

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

func (h *RefreshHandler) generateKubeconfig(email, idToken string) string {
	// Generate kubeconfig with exec credential plugin
	// This ensures automatic token refresh without manual intervention
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %s
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: %s
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kauth
      args:
      - get-token
      interactiveMode: Never
contexts:
- name: %s
  context:
    cluster: %s
    user: %s
current-context: %s
`, h.clusterName, h.clusterServer, h.clusterCA,
		email,
		h.clusterName, h.clusterName, email,
		h.clusterName)
}
