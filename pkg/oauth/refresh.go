package oauth

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

// RefreshToken attempts to refresh an expired token using the refresh token
func (p *Provider) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	if token == nil {
		return nil, fmt.Errorf("token is nil")
	}

	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Create a token source that will automatically refresh
	tokenSource := p.OAuth2Config.TokenSource(ctx, token)

	// Get a fresh token (this will refresh if needed)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}

// GetValidToken returns a valid token, refreshing if necessary
func (p *Provider) GetValidToken(ctx context.Context, cachedToken *oauth2.Token) (*oauth2.Token, bool, error) {
	if cachedToken == nil {
		return nil, false, nil // No cached token, need to authenticate
	}

	// Check if ID token exists
	if _, ok := cachedToken.Extra("id_token").(string); !ok {
		return nil, false, fmt.Errorf("cached token missing id_token")
	}

	// Token is still valid (with 1 minute buffer)
	if cachedToken.Valid() && time.Until(cachedToken.Expiry) > time.Minute {
		return cachedToken, false, nil // Token is valid, no refresh needed
	}

	// Token expired, try to refresh
	if cachedToken.RefreshToken != "" {
		newToken, err := p.RefreshToken(ctx, cachedToken)
		if err != nil {
			// Refresh failed, need to re-authenticate
			return nil, false, fmt.Errorf("token refresh failed: %w", err)
		}
		return newToken, true, nil // Token refreshed successfully
	}

	// No refresh token available, need to re-authenticate
	return nil, false, fmt.Errorf("token expired and no refresh token available")
}
