package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// AuthCodeFlowResult holds the result of an authorization code flow
type AuthCodeFlowResult struct {
	Token *oauth2.Token
	Error error
	mu    sync.RWMutex
}

// StartAuthCodeFlow initiates an OAuth2 authorization code flow with PKCE
func (p *Provider) StartAuthCodeFlow(ctx context.Context, port int) (string, *AuthCodeFlowResult, error) {
	// Generate state for CSRF protection
	state, err := GenerateState()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Generate PKCE verifier
	verifier := oauth2.GenerateVerifier()

	// Create authorization URL
	authURL := p.OAuth2Config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline, // Request refresh token
		oauth2.S256ChallengeOption(verifier),
	)

	// Start callback server
	result := &AuthCodeFlowResult{}
	if err := p.startCallbackServer(ctx, port, state, verifier, result); err != nil {
		return "", nil, fmt.Errorf("failed to start callback server: %w", err)
	}

	return authURL, result, nil
}

// startCallbackServer starts an HTTP server to handle OAuth callbacks
func (p *Provider) startCallbackServer(ctx context.Context, port int, expectedState, verifier string, result *AuthCodeFlowResult) error {
	var once sync.Once
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		errorParam := r.URL.Query().Get("error")
		errorDesc := r.URL.Query().Get("error_description")

		// Validate state for CSRF protection
		if state != expectedState {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			once.Do(func() {
				errChan <- errors.New("invalid state parameter - possible CSRF attack")
			})
			return
		}

		// Check for errors from provider
		if errorParam != "" {
			http.Error(w, "Authorization failed", http.StatusBadRequest)
			once.Do(func() {
				errChan <- fmt.Errorf("authorization failed: %s - %s", errorParam, errorDesc)
			})
			return
		}

		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			once.Do(func() {
				errChan <- errors.New("missing authorization code")
			})
			return
		}

		// Success response to browser
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto; }
        h1 { color: #4CAF50; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Authentication Successful!</h1>
        <p>You can close this window and return to your terminal.</p>
    </div>
</body>
</html>`)

		once.Do(func() {
			codeChan <- code
		})
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			once.Do(func() {
				result.setError(fmt.Errorf("callback server error: %w", err))
			})
		}
	}()

	// Wait for callback or timeout in another goroutine
	go func() {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutdownCtx)
		}()

		select {
		case code := <-codeChan:
			// Exchange authorization code for token
			token, err := p.OAuth2Config.Exchange(
				ctx,
				code,
				oauth2.VerifierOption(verifier),
			)
			if err != nil {
				result.setError(fmt.Errorf("failed to exchange code for token: %w", err))
				return
			}
			result.setToken(token)

		case err := <-errChan:
			result.setError(err)

		case <-ctx.Done():
			result.setError(fmt.Errorf("authentication cancelled: %w", ctx.Err()))

		case <-time.After(5 * time.Minute):
			result.setError(errors.New("authentication timeout - no callback received after 5 minutes"))
		}
	}()

	return nil
}

func (r *AuthCodeFlowResult) setToken(token *oauth2.Token) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Token = token
}

func (r *AuthCodeFlowResult) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Error = err
}

// Wait waits for the authentication flow to complete
func (r *AuthCodeFlowResult) Wait() (*oauth2.Token, error) {
	// Poll until we have either a token or an error
	for {
		r.mu.RLock()
		if r.Token != nil {
			token := r.Token
			r.mu.RUnlock()
			return token, nil
		}
		if r.Error != nil {
			err := r.Error
			r.mu.RUnlock()
			return nil, err
		}
		r.mu.RUnlock()
		time.Sleep(100 * time.Millisecond)
	}
}
