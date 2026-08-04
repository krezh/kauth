package session

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CleanupOldSessions deletes terminal history and stale pending sessions past their retention window.
func (c *Client) CleanupOldSessions(ctx context.Context, terminalTTL, pendingTTL time.Duration) error {
	_, err := c.pool.Exec(ctx, `
		DELETE FROM oauth_sessions
		WHERE cluster=$1
		  AND (
		    (phase=$2 AND COALESCE(revoked_at, created_at) < now() - ($3::float8 * interval '1 second'))
		    OR (phase=$4 AND COALESCE(expired_at, created_at) < now() - ($3::float8 * interval '1 second'))
		    OR (phase IN ($5,$6,$7) AND created_at < now() - ($8::float8 * interval '1 second'))
		  )
	`, c.cluster, string(PhaseRevoked), terminalTTL.Seconds(), string(PhaseExpired),
		string(PhasePending), string(PhaseAuthenticating), string(PhaseFailed), pendingTTL.Seconds())
	if err != nil {
		return fmt.Errorf("failed to clean up old sessions: %w", err)
	}
	return nil
}

// ExpireInactiveSessions expires and scrubs Active sessions idle past ttl, publishing per session.
func (c *Client) ExpireInactiveSessions(ctx context.Context, ttl time.Duration) error {
	return c.withNotify(ctx, func(tx pgx.Tx) ([]SessionEvent, error) {
		rows, err := tx.Query(ctx, `
			UPDATE oauth_sessions
			SET phase=$2, expired_at=now(), refresh_token='', api_token=''
			WHERE cluster=$1 AND phase=$3
			  AND COALESCE(last_used, created_at) < now() - ($4::float8 * interval '1 second')
			RETURNING session_id, subject, issuer
		`, c.cluster, string(PhaseExpired), string(PhaseActive), ttl.Seconds())
		if err != nil {
			return nil, fmt.Errorf("failed to expire inactive sessions: %w", err)
		}
		defer rows.Close()
		var events []SessionEvent
		for rows.Next() {
			var sessionID, subject, issuer string
			if err := rows.Scan(&sessionID, &subject, &issuer); err != nil {
				return nil, fmt.Errorf("failed to scan expired session: %w", err)
			}
			events = append(events, SessionEvent{SessionID: sessionID, Phase: PhaseExpired, Subject: subject, Issuer: issuer})
		}
		return events, rows.Err()
	})
}
