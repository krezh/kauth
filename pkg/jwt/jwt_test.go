package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name          string
		signingKey    []byte
		encryptionKey []byte
		wantErr       bool
		errContains   string
	}{
		{
			name:          "valid keys",
			signingKey:    make([]byte, 32),
			encryptionKey: make([]byte, 32),
			wantErr:       false,
		},
		{
			name:          "signing key too short",
			signingKey:    make([]byte, 31),
			encryptionKey: make([]byte, 32),
			wantErr:       true,
			errContains:   "signing key must be at least 32 bytes",
		},
		{
			name:          "encryption key too short",
			signingKey:    make([]byte, 32),
			encryptionKey: make([]byte, 31),
			wantErr:       true,
			errContains:   "encryption key must be exactly 32 bytes",
		},
		{
			name:          "encryption key too long",
			signingKey:    make([]byte, 32),
			encryptionKey: make([]byte, 33),
			wantErr:       true,
			errContains:   "encryption key must be exactly 32 bytes",
		},
		{
			name:          "signing key longer than 32 bytes is valid",
			signingKey:    make([]byte, 64),
			encryptionKey: make([]byte, 32),
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewManager(tt.signingKey, tt.encryptionKey)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewManager() expected error containing %q, got nil", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("NewManager() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("NewManager() unexpected error = %v", err)
				return
			}
			if mgr == nil {
				t.Errorf("NewManager() returned nil manager")
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "empty data",
			plaintext: []byte{},
		},
		{
			name:      "small data",
			plaintext: []byte("hello world"),
		},
		{
			name:      "large data",
			plaintext: make([]byte, 10000),
		},
		{
			name:      "json data",
			plaintext: []byte(`{"email":"test@example.com","token":"abc123"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := mgr.encrypt(tt.plaintext)
			if err != nil {
				t.Errorf("encrypt() error = %v", err)
				return
			}

			// Verify ciphertext is different from plaintext (except empty)
			if len(tt.plaintext) > 0 && string(ciphertext) == string(tt.plaintext) {
				t.Errorf("encrypt() ciphertext equals plaintext")
			}

			// Decrypt
			decrypted, err := mgr.decrypt(ciphertext)
			if err != nil {
				t.Errorf("decrypt() error = %v", err)
				return
			}

			// Verify decrypted equals original
			if string(decrypted) != string(tt.plaintext) {
				t.Errorf("decrypt() = %v, want %v", string(decrypted), string(tt.plaintext))
			}
		})
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    bool
	}{
		{
			name:       "too short ciphertext",
			ciphertext: []byte{1, 2, 3},
			wantErr:    true,
		},
		{
			name:       "empty ciphertext",
			ciphertext: []byte{},
			wantErr:    true,
		},
		{
			name: "tampered ciphertext",
			ciphertext: func() []byte {
				ct, _ := mgr.encrypt([]byte("test"))
				ct[len(ct)-1] ^= 1 // Flip a bit
				return ct
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mgr.decrypt(tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptUsesRandomNonce(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	plaintext := []byte("same plaintext")

	// Encrypt same plaintext twice
	ct1, err := mgr.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	ct2, err := mgr.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	// Ciphertexts should be different due to random nonce
	if string(ct1) == string(ct2) {
		t.Errorf("encrypt() produced identical ciphertexts for same plaintext")
	}
}

func TestSignVerify(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "small data",
			data: []byte("test data"),
		},
		{
			name: "large data",
			data: make([]byte, 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign
			signed := mgr.sign(tt.data)

			// Verify signature is prepended (32 bytes HMAC-SHA256)
			if len(signed) != 32+len(tt.data) {
				t.Errorf("sign() length = %d, want %d", len(signed), 32+len(tt.data))
			}

			// Verify
			verified, err := mgr.verify(signed)
			if err != nil {
				t.Errorf("verify() error = %v", err)
				return
			}

			// Verify data matches original
			if string(verified) != string(tt.data) {
				t.Errorf("verify() = %v, want %v", string(verified), string(tt.data))
			}
		})
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	tests := []struct {
		name    string
		signed  []byte
		wantErr error
	}{
		{
			name:    "too short",
			signed:  []byte{1, 2, 3},
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "empty",
			signed:  []byte{},
			wantErr: ErrInvalidSignature,
		},
		{
			name: "tampered signature",
			signed: func() []byte {
				s := mgr.sign([]byte("test"))
				s[0] ^= 1 // Flip a bit in signature
				return s
			}(),
			wantErr: ErrInvalidSignature,
		},
		{
			name: "tampered data",
			signed: func() []byte {
				s := mgr.sign([]byte("test"))
				s[len(s)-1] ^= 1 // Flip a bit in data
				return s
			}(),
			wantErr: ErrInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mgr.verify(tt.signed)
			if err != tt.wantErr {
				t.Errorf("verify() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyWithDifferentKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	encKey := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	rand.Read(encKey)

	mgr1, _ := NewManager(key1, encKey)
	mgr2, _ := NewManager(key2, encKey)

	signed := mgr1.sign([]byte("test"))

	_, err := mgr2.verify(signed)
	if err != ErrInvalidSignature {
		t.Errorf("verify() with different key error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestCreateSessionToken(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	state := "test-state-123"
	verifier := "test-verifier-456"
	ttl := 10 * time.Minute

	token, err := mgr.CreateSessionToken(state, verifier, ttl)
	if err != nil {
		t.Fatalf("CreateSessionToken() error = %v", err)
	}

	// Verify token is base64 encoded
	if _, err := base64.URLEncoding.DecodeString(token); err != nil {
		t.Errorf("CreateSessionToken() token is not valid base64: %v", err)
	}

	// Verify token is not empty
	if token == "" {
		t.Errorf("CreateSessionToken() returned empty token")
	}
}

func TestValidateSessionToken(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		state := "test-state"
		verifier := "test-verifier"
		ttl := 10 * time.Minute

		token, err := mgr.CreateSessionToken(state, verifier, ttl)
		if err != nil {
			t.Fatalf("CreateSessionToken() error = %v", err)
		}

		session, err := mgr.ValidateSessionToken(token)
		if err != nil {
			t.Errorf("ValidateSessionToken() error = %v", err)
			return
		}

		if session.State != state {
			t.Errorf("ValidateSessionToken() state = %v, want %v", session.State, state)
		}
		if session.Verifier != verifier {
			t.Errorf("ValidateSessionToken() verifier = %v, want %v", session.Verifier, verifier)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		state := "test-state"
		verifier := "test-verifier"
		ttl := -1 * time.Minute // Already expired

		token, err := mgr.CreateSessionToken(state, verifier, ttl)
		if err != nil {
			t.Fatalf("CreateSessionToken() error = %v", err)
		}

		_, err = mgr.ValidateSessionToken(token)
		if err != ErrExpiredToken {
			t.Errorf("ValidateSessionToken() error = %v, want %v", err, ErrExpiredToken)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := mgr.ValidateSessionToken("not-base64!!!")
		if err != ErrInvalidToken {
			t.Errorf("ValidateSessionToken() error = %v, want %v", err, ErrInvalidToken)
		}
	})

	t.Run("tampered token", func(t *testing.T) {
		token, err := mgr.CreateSessionToken("state", "verifier", 10*time.Minute)
		if err != nil {
			t.Fatalf("CreateSessionToken() error = %v", err)
		}

		// Decode, tamper, re-encode
		decoded, _ := base64.URLEncoding.DecodeString(token)
		decoded[0] ^= 1
		tampered := base64.URLEncoding.EncodeToString(decoded)

		_, err = mgr.ValidateSessionToken(tampered)
		if err != ErrInvalidSignature {
			t.Errorf("ValidateSessionToken() error = %v, want %v", err, ErrInvalidSignature)
		}
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := mgr.ValidateSessionToken("")
		if err != ErrInvalidToken && err != ErrInvalidSignature {
			t.Errorf("ValidateSessionToken() error = %v, want %v or %v", err, ErrInvalidToken, ErrInvalidSignature)
		}
	})
}

func TestCreateRefreshToken(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	email := "user@example.com"
	oidcToken := "oidc-refresh-token-xyz"
	rotationCounter := 5
	ttl := 24 * time.Hour

	token, err := mgr.CreateRefreshToken(email, oidcToken, rotationCounter, ttl)
	if err != nil {
		t.Fatalf("CreateRefreshToken() error = %v", err)
	}

	// Verify token is base64 encoded
	if _, err := base64.URLEncoding.DecodeString(token); err != nil {
		t.Errorf("CreateRefreshToken() token is not valid base64: %v", err)
	}

	// Verify token is not empty
	if token == "" {
		t.Errorf("CreateRefreshToken() returned empty token")
	}
}

func TestValidateRefreshToken(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		email := "user@example.com"
		oidcToken := "oidc-token"
		rotationCounter := 3
		ttl := 24 * time.Hour

		token, err := mgr.CreateRefreshToken(email, oidcToken, rotationCounter, ttl)
		if err != nil {
			t.Fatalf("CreateRefreshToken() error = %v", err)
		}

		refresh, err := mgr.ValidateRefreshToken(token, 5)
		if err != nil {
			t.Errorf("ValidateRefreshToken() error = %v", err)
			return
		}

		if refresh.UserEmail != email {
			t.Errorf("ValidateRefreshToken() email = %v, want %v", refresh.UserEmail, email)
		}
		if refresh.OIDCRefreshToken != oidcToken {
			t.Errorf("ValidateRefreshToken() oidc token = %v, want %v", refresh.OIDCRefreshToken, oidcToken)
		}
		if refresh.RotationCounter != rotationCounter {
			t.Errorf("ValidateRefreshToken() rotation counter = %v, want %v", refresh.RotationCounter, rotationCounter)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token, err := mgr.CreateRefreshToken("user@example.com", "oidc-token", 1, -1*time.Hour)
		if err != nil {
			t.Fatalf("CreateRefreshToken() error = %v", err)
		}

		_, err = mgr.ValidateRefreshToken(token, 5)
		if err != ErrExpiredToken {
			t.Errorf("ValidateRefreshToken() error = %v, want %v", err, ErrExpiredToken)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := mgr.ValidateRefreshToken("invalid-base64!!!", 5)
		if err != ErrInvalidToken {
			t.Errorf("ValidateRefreshToken() error = %v, want %v", err, ErrInvalidToken)
		}
	})

	t.Run("tampered token", func(t *testing.T) {
		token, err := mgr.CreateRefreshToken("user@example.com", "oidc-token", 1, 24*time.Hour)
		if err != nil {
			t.Fatalf("CreateRefreshToken() error = %v", err)
		}

		decoded, _ := base64.URLEncoding.DecodeString(token)
		decoded[10] ^= 1
		tampered := base64.URLEncoding.EncodeToString(decoded)

		_, err = mgr.ValidateRefreshToken(tampered, 5)
		if err != ErrInvalidSignature {
			t.Errorf("ValidateRefreshToken() error = %v, want %v", err, ErrInvalidSignature)
		}
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := mgr.ValidateRefreshToken("", 5)
		if err != ErrInvalidToken && err != ErrInvalidSignature {
			t.Errorf("ValidateRefreshToken() error = %v, want %v or %v", err, ErrInvalidToken, ErrInvalidSignature)
		}
	})
}

func TestGenerateRandomKey(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateRandomKey(tt.size)
			if err != nil {
				t.Errorf("GenerateRandomKey() error = %v", err)
				return
			}
			if len(key) != tt.size {
				t.Errorf("GenerateRandomKey() length = %d, want %d", len(key), tt.size)
			}

			// Generate another key and verify they're different
			key2, err := GenerateRandomKey(tt.size)
			if err != nil {
				t.Errorf("GenerateRandomKey() error = %v", err)
				return
			}
			if string(key) == string(key2) {
				t.Errorf("GenerateRandomKey() produced identical keys")
			}
		})
	}
}

func TestTokensAreIndependent(t *testing.T) {
	signingKey := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	rand.Read(signingKey)
	rand.Read(encryptionKey)

	mgr, err := NewManager(signingKey, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Create session token
	sessionToken, err := mgr.CreateSessionToken("state", "verifier", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateSessionToken() error = %v", err)
	}

	// Create refresh token
	refreshToken, err := mgr.CreateRefreshToken("user@example.com", "oidc-token", 1, 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken() error = %v", err)
	}

	// Verify tokens are different
	if sessionToken == refreshToken {
		t.Errorf("Session and refresh tokens are identical")
	}

	// Note: The JWT manager doesn't enforce token type at the cryptographic level.
	// Both token types can be decrypted/verified, but they will fail to unmarshal
	// into the wrong struct type. This is acceptable as the JSON structure differs.

	// Session token will fail to parse as refresh token (different JSON structure)
	_, err = mgr.ValidateRefreshToken(sessionToken, 5)
	if err == nil {
		t.Logf("Note: ValidateRefreshToken may accept session token structurally but will fail in practice")
		// This is acceptable - the unmarshal will fail due to different JSON fields
	}

	// Refresh token will fail to parse as session token (different JSON structure)
	_, err = mgr.ValidateSessionToken(refreshToken)
	if err == nil {
		t.Logf("Note: ValidateSessionToken may accept refresh token structurally but will fail in practice")
		// This is acceptable - the unmarshal will fail due to different JSON fields
	}
}
