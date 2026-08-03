package jwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token expired")
	ErrInvalidSignature = errors.New("invalid signature")
)

// SessionToken contains OAuth flow state (encrypted, signed)
type SessionToken struct {
	SessionID string    `json:"sessionID"`
	Verifier  string    `json:"verifier"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// APICredential is the opaque credential kubectl presents to the kauth API proxy.
type APICredential struct {
	Type      string    `json:"type"`
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

const apiCredentialType = "api"

const (
	dashboardLoginType   = "dashboard_login"
	dashboardSessionType = "dashboard_session"
)

type DashboardLoginToken struct {
	Type      string    `json:"type"`
	State     string    `json:"state"`
	Verifier  string    `json:"verifier"`
	ExpiresAt time.Time `json:"expires_at"`
}

type DashboardSessionToken struct {
	Type      string    `json:"type"`
	Email     string    `json:"email"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Groups    []string  `json:"groups"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RefreshToken contains refresh token data (encrypted, signed)
type RefreshToken struct {
	UserEmail        string    `json:"user_email"`
	OIDCRefreshToken string    `json:"oidc_refresh_token"`
	RotationCounter  int       `json:"rotation_counter"`
	SessionID        string    `json:"session_id"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// Manager handles JWT creation and validation
type Manager struct {
	signingKey    []byte
	encryptionKey []byte
}

// NewManager creates a new JWT manager
// signingKey: 32+ bytes for HMAC-SHA256
// encryptionKey: 32 bytes for AES-256
func NewManager(signingKey, encryptionKey []byte) (*Manager, error) {
	if len(signingKey) < 32 {
		return nil, errors.New("signing key must be at least 32 bytes")
	}
	if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must be exactly 32 bytes for AES-256")
	}

	return &Manager{
		signingKey:    signingKey,
		encryptionKey: encryptionKey,
	}, nil
}

// CreateSessionToken creates an encrypted and signed session token
func (m *Manager) CreateSessionToken(sessionID, verifier string, ttl time.Duration) (string, error) {
	now := time.Now()
	session := SessionToken{
		SessionID: sessionID,
		Verifier:  verifier,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	// Marshal to JSON
	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session: %w", err)
	}

	// Encrypt
	encrypted, err := m.encrypt(data)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt session: %w", err)
	}

	// Sign
	signed := m.sign(encrypted)

	return base64.URLEncoding.EncodeToString(signed), nil
}

// ValidateSessionToken validates and decrypts a session token
func (m *Manager) ValidateSessionToken(token string) (*SessionToken, error) {
	// Decode base64
	signed, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Verify signature
	encrypted, err := m.verify(signed)
	if err != nil {
		return nil, err
	}

	// Decrypt
	data, err := m.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session: %w", err)
	}

	// Unmarshal
	var session SessionToken
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, ErrInvalidToken
	}

	// Check expiry
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	return &session, nil
}

// CreateRefreshToken creates an encrypted and signed refresh token
func (m *Manager) CreateRefreshToken(userEmail, oidcRefreshToken, sessionID string, rotationCounter int, ttl time.Duration) (string, error) {
	now := time.Now()
	refresh := RefreshToken{
		UserEmail:        userEmail,
		OIDCRefreshToken: oidcRefreshToken,
		RotationCounter:  rotationCounter,
		SessionID:        sessionID,
		IssuedAt:         now,
		ExpiresAt:        now.Add(ttl),
	}

	// Marshal to JSON
	data, err := json.Marshal(refresh)
	if err != nil {
		return "", fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	// Encrypt
	encrypted, err := m.encrypt(data)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// Sign
	signed := m.sign(encrypted)

	return base64.URLEncoding.EncodeToString(signed), nil
}

// DecodeRefreshToken decodes and decrypts a refresh token without checking expiry.
// Use ValidateRefreshToken for normal validation; this is for comparing rotation
// counters against a stored (possibly expired) token.
func (m *Manager) DecodeRefreshToken(token string) (*RefreshToken, error) {
	signed, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	encrypted, err := m.verify(signed)
	if err != nil {
		return nil, err
	}
	data, err := m.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}
	var refresh RefreshToken
	if err := json.Unmarshal(data, &refresh); err != nil {
		return nil, ErrInvalidToken
	}
	return &refresh, nil
}

// ValidateRefreshToken validates and decrypts a refresh token
func (m *Manager) ValidateRefreshToken(token string) (*RefreshToken, error) {
	refresh, err := m.DecodeRefreshToken(token)
	if err != nil {
		return nil, err
	}
	if time.Now().After(refresh.ExpiresAt) {
		return nil, ErrExpiredToken
	}
	return refresh, nil
}

// CreateAPIToken creates an encrypted credential for the Kubernetes API proxy.
func (m *Manager) CreateAPIToken(sessionID string, ttl time.Duration) (string, error) {
	cred := APICredential{
		Type:      apiCredentialType,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(ttl),
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return "", fmt.Errorf("failed to marshal API credential: %w", err)
	}

	encrypted, err := m.encrypt(data)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt API credential: %w", err)
	}

	return base64.URLEncoding.EncodeToString(m.sign(encrypted)), nil
}

// DecodeAPIToken decrypts and decodes an API credential without checking
// expiry. Use ValidateAPIToken for request authentication; this is for
// extracting the ExpiresAt to propagate to clients.
func (m *Manager) DecodeAPIToken(token string) (*APICredential, error) {
	signed, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	encrypted, err := m.verify(signed)
	if err != nil {
		return nil, err
	}
	data, err := m.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt API credential: %w", err)
	}
	var cred APICredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, ErrInvalidToken
	}
	if cred.Type != apiCredentialType || cred.SessionID == "" || cred.ExpiresAt.IsZero() {
		return nil, ErrInvalidToken
	}
	return &cred, nil
}

// ValidateAPIToken decrypts and validates an API credential, returning
// the session ID on success.
func (m *Manager) ValidateAPIToken(token string) (*APICredential, error) {
	cred, err := m.DecodeAPIToken(token)
	if err != nil {
		return nil, err
	}
	if time.Now().After(cred.ExpiresAt) {
		return nil, ErrExpiredToken
	}
	return cred, nil
}

func (m *Manager) CreateDashboardLoginToken(state, verifier string, ttl time.Duration) (string, error) {
	return m.createTypedToken(DashboardLoginToken{
		Type: dashboardLoginType, State: state, Verifier: verifier, ExpiresAt: time.Now().Add(ttl),
	})
}

func (m *Manager) ValidateDashboardLoginToken(token string) (*DashboardLoginToken, error) {
	var claims DashboardLoginToken
	if err := m.decodeTypedToken(token, dashboardLoginType, &claims); err != nil {
		return nil, err
	}
	if claims.State == "" || claims.Verifier == "" || time.Now().After(claims.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

func (m *Manager) CreateDashboardSessionToken(email, subject, issuer string, groups []string, ttl time.Duration) (string, error) {
	csrf, err := GenerateRandomKey(32)
	if err != nil {
		return "", err
	}
	return m.createTypedToken(DashboardSessionToken{
		Type: dashboardSessionType, Email: email, Subject: subject, Issuer: issuer, Groups: groups,
		CSRFToken: base64.RawURLEncoding.EncodeToString(csrf), ExpiresAt: time.Now().Add(ttl),
	})
}

func (m *Manager) ValidateDashboardSessionToken(token string) (*DashboardSessionToken, error) {
	var claims DashboardSessionToken
	if err := m.decodeTypedToken(token, dashboardSessionType, &claims); err != nil {
		return nil, err
	}
	if claims.Email == "" || claims.CSRFToken == "" || time.Now().After(claims.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

func (m *Manager) createTypedToken(claims any) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encrypted, err := m.encrypt(data)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(m.sign(encrypted)), nil
}

func (m *Manager) decodeTypedToken(token, expectedType string, claims any) error {
	signed, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return ErrInvalidToken
	}
	encrypted, err := m.verify(signed)
	if err != nil {
		return err
	}
	data, err := m.decrypt(encrypted)
	if err != nil {
		return ErrInvalidToken
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Type != expectedType {
		return ErrInvalidToken
	}
	if err := json.Unmarshal(data, claims); err != nil {
		return ErrInvalidToken
	}
	return nil
}

// encrypt encrypts data using AES-GCM
func (m *Manager) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (m *Manager) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// sign creates HMAC-SHA256 signature
func (m *Manager) sign(data []byte) []byte {
	h := hmac.New(sha256.New, m.signingKey)
	h.Write(data)
	signature := h.Sum(nil)

	// Prepend signature to data
	signed := make([]byte, len(signature)+len(data))
	copy(signed, signature)
	copy(signed[len(signature):], data)

	return signed
}

// verify verifies HMAC-SHA256 signature
func (m *Manager) verify(signed []byte) ([]byte, error) {
	if len(signed) < sha256.Size {
		return nil, ErrInvalidSignature
	}

	// Extract signature and data
	signature := signed[:sha256.Size]
	data := signed[sha256.Size:]

	// Compute expected signature
	h := hmac.New(sha256.New, m.signingKey)
	h.Write(data)
	expectedSignature := h.Sum(nil)

	// Constant-time comparison
	if !hmac.Equal(signature, expectedSignature) {
		return nil, ErrInvalidSignature
	}

	return data, nil
}

// GenerateRandomKey generates a cryptographically secure random key
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
