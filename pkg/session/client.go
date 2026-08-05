package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrRefreshTokenReplayed = errors.New("refresh token is no longer current")
var ErrLoginAlreadyClaimed = errors.New("login session is no longer pending")
var ErrSessionNotFound = errors.New("session not found")

// maxPoolConns caps pgxpool's NumCPU-scaling default so replicas don't exhaust Postgres' max_connections.
const maxPoolConns = 10

// Client wraps a Postgres pool for OAuthSession operations, scoped to one cluster.
type Client struct {
	pool      *pgxpool.Pool
	cluster   string
	hub       *Hub
	lifecycle context.Context
	cancel    context.CancelFunc
}

// NewClient opens a pool, migrates the schema, and starts the LISTEN/NOTIFY hub.
func NewClient(ctx context.Context, databaseURL, cluster string) (*Client, error) {
	if databaseURL == "" {
		return nil, errors.New("database URL is required")
	}
	if cluster == "" {
		return nil, errors.New("cluster is required")
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	if poolConfig.MaxConns > maxPoolConns {
		poolConfig.MaxConns = maxPoolConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open session database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to session database: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate session database: %w", err)
	}

	hub, err := NewHub(databaseURL)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("create session hub: %w", err)
	}

	lifecycle, cancel := context.WithCancel(context.Background())
	go hub.Run(lifecycle)

	return &Client{
		pool:      pool,
		cluster:   cluster,
		hub:       hub,
		lifecycle: lifecycle,
		cancel:    cancel,
	}, nil
}

// Close stops the hub and closes the pool.
func (c *Client) Close(ctx context.Context) error {
	c.cancel()
	c.pool.Close()
	return nil
}

// Subscribe registers for session events; callers must drain and unsubscribe.
func (c *Client) Subscribe() (<-chan SessionEvent, func()) {
	return c.hub.Subscribe()
}

// Create creates a new pending session.
func (c *Client) Create(ctx context.Context, sessionID, verifier, userID string) (*Session, error) {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO oauth_sessions (session_id, cluster, verifier, user_id, created_at, phase)
		VALUES ($1, $2, $3, $4, now(), $5)
	`, sessionID, c.cluster, verifier, userID, string(PhasePending))
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	return c.Get(ctx, sessionID)
}

// Get retrieves a session by ID.
func (c *Client) Get(ctx context.Context, sessionID string) (*Session, error) {
	row := c.pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM oauth_sessions WHERE cluster=$1 AND session_id=$2`,
		c.cluster, sessionID)
	return scanSession(row)
}

const sessionColumns = `session_id, verifier, user_id, created_at, last_used, phase, email,
	       username, subject, issuer, refresh_token, revoked_at, expired_at,
	       completed_at, error, groups, api_token`

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(row rowScanner) (*Session, error) {
	var s Session
	var phase string
	var lastUsed *time.Time
	err := row.Scan(&s.SessionID, &s.Verifier, &s.UserID, &s.CreatedAt, &lastUsed,
		&phase, &s.Email, &s.Username, &s.Subject, &s.Issuer, &s.RefreshToken,
		&s.RevokedAt, &s.ExpiredAt, &s.CompletedAt, &s.Error, &s.Groups, &s.APIToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}
	s.Phase = Phase(phase)
	if lastUsed != nil {
		s.LastUsed = *lastUsed
	}
	return &s, nil
}

func (c *Client) queryList(ctx context.Context, whereExtra string, args ...any) ([]Session, error) {
	rows, err := c.pool.Query(ctx, `SELECT `+sessionColumns+` FROM oauth_sessions WHERE cluster=$1`+whereExtra, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// ListActive returns every session not in a terminal phase.
func (c *Client) ListActive(ctx context.Context) ([]Session, error) {
	return c.queryList(ctx, ` AND phase NOT IN ($2,$3)`, c.cluster, string(PhaseRevoked), string(PhaseExpired))
}

// ListAll returns every session, including terminal ones.
func (c *Client) ListAll(ctx context.Context) ([]Session, error) {
	return c.queryList(ctx, ``, c.cluster)
}

// GetByUser matches userID against either the authenticated email or the pre-login user ID.
func (c *Client) GetByUser(ctx context.Context, userID string) ([]Session, error) {
	return c.queryList(ctx, ` AND (email=$2 OR user_id=$2)`, c.cluster, userID)
}

// ValidateSession checks a session exists and has the expected phase.
func (c *Client) ValidateSession(ctx context.Context, sessionID string, expectedPhase Phase) error {
	s, err := c.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}
	if s.Phase != expectedPhase {
		return fmt.Errorf("session is %s, expected %s", s.Phase, expectedPhase)
	}
	return nil
}

// UpdateLastUsed unconditionally bumps last_used.
func (c *Client) UpdateLastUsed(ctx context.Context, sessionID string) error {
	tag, err := c.pool.Exec(ctx, `UPDATE oauth_sessions SET last_used=now() WHERE cluster=$1 AND session_id=$2`,
		c.cluster, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("failed to update last used: %w", ErrSessionNotFound)
	}
	return nil
}

// TouchLastUsed bumps last_used at most once per window; a zero-row result is a silent no-op.
func (c *Client) TouchLastUsed(ctx context.Context, sessionID string, window time.Duration) error {
	_, err := c.pool.Exec(ctx, `
		UPDATE oauth_sessions SET last_used=now()
		WHERE cluster=$1 AND session_id=$2
		  AND (last_used IS NULL OR last_used < now() - ($3::float8 * interval '1 second'))
	`, c.cluster, sessionID, window.Seconds())
	if err != nil {
		return fmt.Errorf("failed to touch last used: %w", err)
	}
	return nil
}

// UpdateUserID sets the pre-login user ID and bumps last_used.
func (c *Client) UpdateUserID(ctx context.Context, sessionID, userID string) error {
	tag, err := c.pool.Exec(ctx, `
		UPDATE oauth_sessions SET user_id=$3, last_used=now()
		WHERE cluster=$1 AND session_id=$2
	`, c.cluster, sessionID, userID)
	if err != nil {
		return fmt.Errorf("failed to update user ID: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("failed to update user ID: %w", ErrSessionNotFound)
	}
	return nil
}

// Delete removes a session row.
func (c *Client) Delete(ctx context.Context, sessionID string) error {
	tag, err := c.pool.Exec(ctx, `DELETE FROM oauth_sessions WHERE cluster=$1 AND session_id=$2`, c.cluster, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("failed to delete session: %w", ErrSessionNotFound)
	}
	return nil
}
