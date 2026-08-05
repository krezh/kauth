package session

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS oauth_sessions (
    session_id     TEXT NOT NULL,
    cluster        TEXT NOT NULL,
    verifier       TEXT NOT NULL,
    user_id        TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL,
    last_used      TIMESTAMPTZ,
    phase          TEXT NOT NULL,
    email          TEXT NOT NULL DEFAULT '',
    username       TEXT NOT NULL DEFAULT '',
    subject        TEXT NOT NULL DEFAULT '',
    issuer         TEXT NOT NULL DEFAULT '',
    refresh_token  TEXT NOT NULL DEFAULT '',
    revoked_at     TIMESTAMPTZ,
    expired_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    error          TEXT NOT NULL DEFAULT '',
    groups         TEXT[] NOT NULL DEFAULT '{}',
    api_token      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (cluster, session_id)
);
CREATE INDEX IF NOT EXISTS oauth_sessions_email_idx
    ON oauth_sessions (cluster, email) WHERE email <> '';
CREATE INDEX IF NOT EXISTS oauth_sessions_user_id_idx
    ON oauth_sessions (cluster, user_id) WHERE user_id <> '';
CREATE INDEX IF NOT EXISTS oauth_sessions_phase_idx
    ON oauth_sessions (cluster, phase);
`

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('kauth_session_schema'))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, schema); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
