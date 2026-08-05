package session

import "time"

// Phase represents the lifecycle phase of a session.
type Phase string

const (
	PhasePending        Phase = "Pending"
	PhaseAuthenticating Phase = "Authenticating"
	PhaseFailed         Phase = "Failed"
	PhaseActive         Phase = "Active"
	PhaseRevoked        Phase = "Revoked"
	PhaseExpired        Phase = "Expired"
)

// Session is a stored OAuth session row.
type Session struct {
	SessionID    string
	Verifier     string
	UserID       string
	CreatedAt    time.Time
	LastUsed     time.Time
	Phase        Phase
	Email        string
	Username     string
	Subject      string
	Issuer       string
	RefreshToken string
	RevokedAt    *time.Time
	ExpiredAt    *time.Time
	CompletedAt  *time.Time
	Error        string
	Groups       []string
	APIToken     string
	// TokenRotation increments on every refresh-token rotation and is the
	// non-secret value RotateRefreshToken uses to detect a replay.
	TokenRotation int64
}

// Status is the partial-update shape accepted by UpdateStatus and RotateRefreshToken.
type Status struct {
	Phase        Phase
	Email        string
	Username     string
	Subject      string
	Issuer       string
	RefreshToken string
	RevokedAt    *time.Time
	ExpiredAt    *time.Time
	CompletedAt  *time.Time
	Error        string
	Groups       []string
	APIToken     string
}
