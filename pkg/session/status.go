package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// withNotify runs fn in a transaction and pg_notifies every returned event before committing.
func (c *Client) withNotify(ctx context.Context, fn func(tx pgx.Tx) ([]SessionEvent, error)) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	events, err := fn(tx)
	if err != nil {
		return err
	}
	for _, ev := range events {
		payload, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("failed to marshal session event: %w", err)
		}
		if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", sessionEventsChannel, string(payload)); err != nil {
			return fmt.Errorf("failed to publish session event: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// UpdateStatus guards against reactivating a terminal session and publishes on Active or Error.
func (c *Client) UpdateStatus(ctx context.Context, sessionID string, status Status) error {
	groups := status.Groups
	if groups == nil {
		groups = []string{}
	}

	var conflict bool
	err := c.withNotify(ctx, func(tx pgx.Tx) ([]SessionEvent, error) {
		tag, err := tx.Exec(ctx, `
			UPDATE oauth_sessions
			SET phase=$3, email=$4, username=$5, subject=$6, issuer=$7, refresh_token=$8,
			    groups=$9, error=$10, revoked_at=$11, expired_at=$12,
			    api_token = COALESCE(NULLIF($13,''), api_token),
			    completed_at = CASE WHEN $3=$14 THEN COALESCE($15, completed_at, now()) ELSE $15 END
			WHERE cluster=$1 AND session_id=$2
			  AND NOT ($3=$14 AND phase IN ($16,$17,$18))
		`, c.cluster, sessionID, string(status.Phase), status.Email, status.Username,
			status.Subject, status.Issuer, status.RefreshToken, groups, status.Error,
			status.RevokedAt, status.ExpiredAt, status.APIToken, string(PhaseActive), status.CompletedAt,
			string(PhaseRevoked), string(PhaseExpired), string(PhaseFailed))
		if err != nil {
			return nil, fmt.Errorf("failed to update status: %w", err)
		}
		if tag.RowsAffected() == 0 {
			conflict = true
			return nil, nil
		}
		if status.Phase != PhaseActive && status.Error == "" {
			return nil, nil
		}
		return []SessionEvent{{SessionID: sessionID, Cluster: c.cluster, Phase: status.Phase, Subject: status.Subject, Issuer: status.Issuer}}, nil
	})
	if err != nil {
		return err
	}
	if conflict {
		return c.updateStatusConflictError(ctx, sessionID)
	}
	return nil
}

// updateStatusConflictError distinguishes not-found from terminal-state-blocked after a zero-row UPDATE.
func (c *Client) updateStatusConflictError(ctx context.Context, sessionID string) error {
	existing, err := c.Get(ctx, sessionID)
	if errors.Is(err, ErrSessionNotFound) {
		return fmt.Errorf("failed to get session: %w", err)
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("session is in terminal state %s, cannot reactivate", existing.Phase)
}

// ClaimLogin exactly-once flips Pending to Authenticating via a row lock; not published, no consumer needs it.
func (c *Client) ClaimLogin(ctx context.Context, sessionID string) error {
	tag, err := c.pool.Exec(ctx, `
		UPDATE oauth_sessions SET phase=$3
		WHERE cluster=$1 AND session_id=$2 AND phase=$4
	`, c.cluster, sessionID, string(PhaseAuthenticating), string(PhasePending))
	if err != nil {
		return fmt.Errorf("failed to claim login session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		if _, err := c.Get(ctx, sessionID); errors.Is(err, ErrSessionNotFound) {
			return fmt.Errorf("failed to get session: %w", err)
		}
		return ErrLoginAlreadyClaimed
	}
	return nil
}

// RotateRefreshToken swaps the token in one conditional UPDATE guarding against replay; not published.
//
// The guard is the non-secret token_rotation counter the caller read alongside the
// token it verified, so the stored secret is never compared by the database: only a
// rotation that started from the current counter wins, and concurrent replays of the
// same token lose the compare-and-set.
func (c *Client) RotateRefreshToken(ctx context.Context, sessionID string, rotation int64, status Status) error {
	groups := status.Groups
	if groups == nil {
		groups = []string{}
	}
	tag, err := c.pool.Exec(ctx, `
		UPDATE oauth_sessions
		SET phase=$3, email=$4, username=$5, subject=$6, issuer=$7, refresh_token=$8, groups=$9,
		    api_token = COALESCE(NULLIF($10,''), api_token),
		    completed_at = COALESCE($11, completed_at),
		    token_rotation = token_rotation + 1
		WHERE cluster=$1 AND session_id=$2 AND phase=$12 AND token_rotation=$13
		  AND refresh_token <> ''
	`, c.cluster, sessionID, string(status.Phase), status.Email, status.Username,
		status.Subject, status.Issuer, status.RefreshToken, groups,
		status.APIToken, status.CompletedAt, string(PhaseActive), rotation)
	if err != nil {
		return fmt.Errorf("failed to rotate refresh token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		existing, err := c.Get(ctx, sessionID)
		if errors.Is(err, ErrSessionNotFound) {
			return fmt.Errorf("failed to get session: %w", err)
		}
		if err != nil {
			return err
		}
		if existing.Phase != PhaseActive {
			return fmt.Errorf("session is not active")
		}
		return ErrRefreshTokenReplayed
	}
	return nil
}

// Revoke scrubs credentials and marks a session revoked; idempotent.
func (c *Client) Revoke(ctx context.Context, sessionID string) error {
	var alreadyRevoked bool
	err := c.withNotify(ctx, func(tx pgx.Tx) ([]SessionEvent, error) {
		var subject, issuer string
		row := tx.QueryRow(ctx, `
			UPDATE oauth_sessions
			SET phase=$3, revoked_at=now(), refresh_token='', api_token=''
			WHERE cluster=$1 AND session_id=$2 AND phase != $3
			RETURNING subject, issuer
		`, c.cluster, sessionID, string(PhaseRevoked))
		if err := row.Scan(&subject, &issuer); errors.Is(err, pgx.ErrNoRows) {
			alreadyRevoked = true
			return nil, nil
		} else if err != nil {
			return nil, fmt.Errorf("failed to revoke session: %w", err)
		}
		return []SessionEvent{{SessionID: sessionID, Cluster: c.cluster, Phase: PhaseRevoked, Subject: subject, Issuer: issuer}}, nil
	})
	if err != nil {
		return err
	}
	if alreadyRevoked {
		if _, err := c.Get(ctx, sessionID); err != nil {
			return err
		}
	}
	return nil
}

// RevokeByUser revokes every non-terminal session matching userID in one UPDATE, unbounded by maxListResults.
func (c *Client) RevokeByUser(ctx context.Context, userID string) (int, error) {
	var revoked int
	err := c.withNotify(ctx, func(tx pgx.Tx) ([]SessionEvent, error) {
		rows, err := tx.Query(ctx, `
			UPDATE oauth_sessions
			SET phase=$3, revoked_at=now(), refresh_token='', api_token=''
			WHERE cluster=$1 AND (email=$2 OR user_id=$2) AND phase != $3
			RETURNING session_id, subject, issuer
		`, c.cluster, userID, string(PhaseRevoked))
		if err != nil {
			return nil, fmt.Errorf("failed to revoke user sessions: %w", err)
		}
		defer rows.Close()
		var events []SessionEvent
		for rows.Next() {
			var sessionID, subject, issuer string
			if err := rows.Scan(&sessionID, &subject, &issuer); err != nil {
				return nil, fmt.Errorf("failed to scan revoked session: %w", err)
			}
			events = append(events, SessionEvent{SessionID: sessionID, Cluster: c.cluster, Phase: PhaseRevoked, Subject: subject, Issuer: issuer})
		}
		revoked = len(events)
		return events, rows.Err()
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}
