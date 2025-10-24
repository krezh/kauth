package credential

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

func TestOutputCredential(t *testing.T) {
	tests := []struct {
		name    string
		token   *oauth2.Token
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid token with id_token",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken:  "access-token-123",
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(1 * time.Hour),
					RefreshToken: "refresh-token-456",
				}
				return tok.WithExtra(map[string]any{
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
				})
			}(),
			wantErr: false,
		},
		{
			name: "valid token without expiry",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token-123",
					TokenType:   "Bearer",
				}
				return tok.WithExtra(map[string]any{
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
				})
			}(),
			wantErr: false,
		},
		{
			name:    "nil token",
			token:   nil,
			wantErr: true,
			errMsg:  "token is nil",
		},
		{
			name: "missing id_token",
			token: &oauth2.Token{
				AccessToken: "access-token-123",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(1 * time.Hour),
			},
			wantErr: true,
			errMsg:  "no id_token found in token",
		},
		{
			name: "empty id_token",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token-123",
				}
				return tok.WithExtra(map[string]any{
					"id_token": "",
				})
			}(),
			wantErr: true,
			errMsg:  "no id_token found in token",
		},
		{
			name: "id_token wrong type",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token-123",
				}
				return tok.WithExtra(map[string]any{
					"id_token": 12345, // Not a string
				})
			}(),
			wantErr: true,
			errMsg:  "no id_token found in token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := OutputCredential(tt.token)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			if tt.wantErr {
				if err == nil {
					t.Errorf("OutputCredential() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg && !contains(err.Error(), tt.errMsg) {
					t.Errorf("OutputCredential() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("OutputCredential() unexpected error = %v", err)
				return
			}

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)

			// Parse the JSON output
			var cred clientauthv1.ExecCredential
			if err := json.Unmarshal(buf.Bytes(), &cred); err != nil {
				t.Errorf("OutputCredential() produced invalid JSON: %v", err)
				return
			}

			// Verify structure
			if cred.APIVersion != "client.authentication.k8s.io/v1" {
				t.Errorf("OutputCredential() APIVersion = %v, want %v", cred.APIVersion, "client.authentication.k8s.io/v1")
			}
			if cred.Kind != "ExecCredential" {
				t.Errorf("OutputCredential() Kind = %v, want %v", cred.Kind, "ExecCredential")
			}
			if cred.Status == nil {
				t.Errorf("OutputCredential() Status is nil")
				return
			}

			// Verify token matches id_token from input
			expectedIDToken := tt.token.Extra("id_token").(string)
			if cred.Status.Token != expectedIDToken {
				t.Errorf("OutputCredential() Token = %v, want %v", cred.Status.Token, expectedIDToken)
			}

			// Verify expiry timestamp
			if !tt.token.Expiry.IsZero() {
				if cred.Status.ExpirationTimestamp == nil {
					t.Errorf("OutputCredential() ExpirationTimestamp is nil, want timestamp")
				} else {
					// Allow small time difference due to processing
					diff := cred.Status.ExpirationTimestamp.Sub(tt.token.Expiry)
					if diff < -1*time.Second || diff > 1*time.Second {
						t.Errorf("OutputCredential() ExpirationTimestamp = %v, want %v", cred.Status.ExpirationTimestamp.Time, tt.token.Expiry)
					}
				}
			} else {
				if cred.Status.ExpirationTimestamp != nil {
					t.Errorf("OutputCredential() ExpirationTimestamp = %v, want nil", cred.Status.ExpirationTimestamp)
				}
			}
		})
	}
}

func TestIsTokenValid(t *testing.T) {
	tests := []struct {
		name  string
		token *oauth2.Token
		want  bool
	}{
		{
			name: "valid token with sufficient time",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(10 * time.Minute),
				}
				return tok.WithExtra(map[string]any{
					"id_token": "valid-id-token",
				})
			}(),
			want: true,
		},
		{
			name: "valid token at exactly 1 minute buffer",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(61 * time.Second),
				}
				return tok.WithExtra(map[string]any{
					"id_token": "valid-id-token",
				})
			}(),
			want: true,
		},
		{
			name: "token within 1 minute expiry buffer",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(59 * time.Second),
				}
				return tok.WithExtra(map[string]any{
					"id_token": "valid-id-token",
				})
			}(),
			want: false,
		},
		{
			name: "expired token",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(-1 * time.Hour),
				}
				return tok.WithExtra(map[string]any{
					"id_token": "valid-id-token",
				})
			}(),
			want: false,
		},
		{
			name:  "nil token",
			token: nil,
			want:  false,
		},
		{
			name: "missing id_token",
			token: &oauth2.Token{
				AccessToken: "access-token",
				Expiry:      time.Now().Add(10 * time.Minute),
			},
			want: false,
		},
		{
			name: "empty id_token",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(10 * time.Minute),
				}
				return tok.WithExtra(map[string]any{
					"id_token": "",
				})
			}(),
			want: true, // Empty string is still a valid string type, passes type assertion
		},
		{
			name: "id_token wrong type",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(10 * time.Minute),
				}
				return tok.WithExtra(map[string]any{
					"id_token": 12345,
				})
			}(),
			want: false,
		},
		{
			name: "token with no expiry and valid id_token",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
				}
				return tok.WithExtra(map[string]any{
					"id_token": "valid-id-token",
				})
			}(),
			want: false, // Zero expiry means token.Valid() returns false
		},
		{
			name: "token already expired by 1 second",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(-1 * time.Second),
				}
				return tok.WithExtra(map[string]any{
					"id_token": "valid-id-token",
				})
			}(),
			want: false,
		},
		{
			name: "token expiring in exactly 60 seconds",
			token: func() *oauth2.Token {
				tok := &oauth2.Token{
					AccessToken: "access-token",
					Expiry:      time.Now().Add(60 * time.Second),
				}
				return tok.WithExtra(map[string]any{
					"id_token": "valid-id-token",
				})
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTokenValid(tt.token)
			if got != tt.want {
				t.Errorf("IsTokenValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTokenValidEdgeCases(t *testing.T) {
	// Test the exact boundary condition more precisely
	t.Run("boundary at 1 minute", func(t *testing.T) {
		// Token expiring in slightly more than 1 minute should be valid
		tok1 := &oauth2.Token{
			AccessToken: "access-token",
			Expiry:      time.Now().Add(61 * time.Second),
		}
		token1 := tok1.WithExtra(map[string]any{
			"id_token": "valid-id-token",
		})

		if !IsTokenValid(token1) {
			t.Errorf("IsTokenValid() with 61s remaining should be true")
		}

		// Token expiring in slightly less than 1 minute should be invalid
		tok2 := &oauth2.Token{
			AccessToken: "access-token",
			Expiry:      time.Now().Add(59 * time.Second),
		}
		token2 := tok2.WithExtra(map[string]any{
			"id_token": "valid-id-token",
		})

		if IsTokenValid(token2) {
			t.Errorf("IsTokenValid() with 59s remaining should be false")
		}
	})
}

func TestOutputCredentialFormat(t *testing.T) {
	tok := &oauth2.Token{
		AccessToken: "access-token-123",
		TokenType:   "Bearer",
		Expiry:      time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	token := tok.WithExtra(map[string]any{
		"id_token": "test-id-token-xyz",
	})

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := OutputCredential(token)
	if err != nil {
		t.Fatalf("OutputCredential() error = %v", err)
	}

	w.Close()
	if err != nil {
		t.Error(err)
	}
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	// Verify it's properly formatted JSON with indentation
	output := buf.String()
	if !contains(output, "  ") { // Should have indentation
		t.Errorf("OutputCredential() output is not indented")
	}

	// Verify required fields are present
	requiredFields := []string{
		`"apiVersion"`,
		`"kind"`,
		`"status"`,
		`"token"`,
		`"expirationTimestamp"`,
	}
	for _, field := range requiredFields {
		if !contains(output, field) {
			t.Errorf("OutputCredential() output missing field %s", field)
		}
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
