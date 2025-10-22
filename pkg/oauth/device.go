package oauth

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

// StartDeviceFlow initiates an OAuth2 device authorization flow
func (p *Provider) StartDeviceFlow(ctx context.Context) (*oauth2.Token, error) {
	// Start device authorization
	deviceAuth, err := p.OAuth2Config.DeviceAuth(ctx, oauth2.AccessTypeOffline)
	if err != nil {
		return nil, fmt.Errorf("device authorization failed: %w", err)
	}

	// Display instructions to user
	fmt.Printf("\n=== Device Authentication Required ===\n\n")
	fmt.Printf("Please visit: %s\n", deviceAuth.VerificationURI)
	fmt.Printf("And enter code: %s\n\n", deviceAuth.UserCode)

	if deviceAuth.VerificationURIComplete != "" {
		fmt.Printf("Or visit this URL directly:\n%s\n\n", deviceAuth.VerificationURIComplete)
	}

	fmt.Printf("Waiting for authentication...\n")

	// Poll for token
	return p.pollForDeviceToken(ctx, deviceAuth)
}

// pollForDeviceToken polls the authorization server for token issuance
func (p *Provider) pollForDeviceToken(ctx context.Context, deviceAuth *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	interval := time.Duration(deviceAuth.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timeout := time.NewTimer(10 * time.Minute)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("device flow cancelled: %w", ctx.Err())

		case <-timeout.C:
			return nil, fmt.Errorf("device flow timeout - no authentication after 10 minutes")

		case <-ticker.C:
			token, err := p.OAuth2Config.DeviceAccessToken(ctx, deviceAuth)
			if err == nil {
				fmt.Printf("\n✓ Authentication successful!\n\n")
				return token, nil
			}

			// Handle specific OAuth2 error codes
			if rerr, ok := err.(*oauth2.RetrieveError); ok {
				switch rerr.ErrorCode {
				case "authorization_pending":
					// Still waiting for user to authorize
					continue
				case "slow_down":
					// Server requested slower polling
					interval += 5 * time.Second
					ticker.Reset(interval)
					continue
				case "expired_token":
					return nil, fmt.Errorf("device code expired - please try again")
				case "access_denied":
					return nil, fmt.Errorf("authentication was denied")
				default:
					return nil, fmt.Errorf("device flow error: %s - %s", rerr.ErrorCode, rerr.ErrorDescription)
				}
			}

			// Unknown error
			return nil, fmt.Errorf("device flow error: %w", err)
		}
	}
}
