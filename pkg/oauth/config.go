package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds the OAuth2 and OIDC configuration
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Provider wraps the OAuth2 config and OIDC provider
type Provider struct {
	OAuth2Config    *oauth2.Config
	OIDCProvider    *oidc.Provider
	IDTokenVerifier *oidc.IDTokenVerifier
}

// NewProvider creates a new OAuth2/OIDC provider from configuration
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	// Discover OIDC provider
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %s: %w", cfg.IssuerURL, err)
	}

	// Set default scopes if none provided
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile", "groups", "offline_access"}
	}

	// Set default redirect URL if none provided
	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = "http://localhost:8000/callback"
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &Provider{
		OAuth2Config:    oauth2Config,
		OIDCProvider:    provider,
		IDTokenVerifier: verifier,
	}, nil
}

// GenerateState generates a cryptographically secure random state parameter
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// VerifyIDToken verifies and parses an ID token
func (p *Provider) VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	idToken, err := p.IDTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}
	return idToken, nil
}
