package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxPoolConns caps pgxpool's NumCPU-scaling default so replicas don't exhaust Postgres' max_connections.
const maxPoolConns = 10

const schema = `
CREATE TABLE IF NOT EXISTS api_requests (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    occurred_at TIMESTAMPTZ NOT NULL,
    cluster TEXT NOT NULL,
    request_id TEXT NOT NULL,
    session_id TEXT,
    username TEXT,
    groups TEXT[] NOT NULL DEFAULT '{}',
    authenticated BOOLEAN NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code SMALLINT NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    response_bytes BIGINT NOT NULL CHECK (response_bytes >= 0),
    duration_ms BIGINT NOT NULL CHECK (duration_ms >= 0),
    remote_addr TEXT,
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS api_requests_cluster_time_idx
    ON api_requests (cluster, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS api_requests_session_time_idx
    ON api_requests (cluster, session_id, occurred_at DESC, id DESC)
    WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS api_requests_username_time_idx
    ON api_requests (cluster, username, occurred_at DESC, id DESC)
    WHERE username IS NOT NULL;
CREATE INDEX IF NOT EXISTS api_requests_retention_idx
    ON api_requests (occurred_at, id);
`

type RequestEvent struct {
	ID            int64
	EventID       string
	OccurredAt    time.Time
	Cluster       string
	RequestID     string
	SessionID     string
	Username      string
	Groups        []string
	Authenticated bool
	Method        string
	Path          string
	StatusCode    int
	ResponseBytes int64
	Duration      time.Duration
	RemoteAddr    string
	UserAgent     string
}

type RequestMetrics struct {
	Requests      int64
	ClientErrors  int64
	ServerErrors  int64
	ResponseBytes int64
	Average       time.Duration
	P95           time.Duration
	LastRequestAt time.Time
}

type RequestStore interface {
	Record(RequestEvent) bool
	ListSession(context.Context, string, string, int, int) ([]RequestEvent, error)
	SessionMetrics(context.Context, string, string, time.Time) (RequestMetrics, error)
	SessionsMetrics(context.Context, string, []string, time.Time) (RequestMetrics, error)
	GlobalMetrics(context.Context, string, time.Time) (RequestMetrics, error)
	Subscribe() (<-chan AuditEvent, func())
	Close(context.Context) error
}

type PostgresStore struct {
	pool      *pgxpool.Pool
	hub       *Hub
	queue     chan RequestEvent
	stop      chan struct{}
	done      chan struct{}
	retention time.Duration
	dropped   atomic.Uint64
	closed    atomic.Bool
	admission sync.RWMutex
	closeCtx  context.Context
	lifecycle context.Context
	cancel    context.CancelFunc
}

func NewPostgresStore(ctx context.Context, databaseURL string, queueSize int, retention time.Duration) (*PostgresStore, error) {
	if databaseURL == "" {
		return nil, errors.New("database URL is required")
	}
	if queueSize <= 0 {
		queueSize = 8192
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
		return nil, fmt.Errorf("open audit database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to audit database: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate audit database: %w", err)
	}

	hub, err := NewHub(databaseURL)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("create audit hub: %w", err)
	}

	lifecycle, cancel := context.WithCancel(context.Background())
	go hub.Run(lifecycle)
	store := &PostgresStore{
		pool:      pool,
		hub:       hub,
		queue:     make(chan RequestEvent, queueSize),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		retention: retention,
		lifecycle: lifecycle,
		cancel:    cancel,
	}
	go store.run()
	return store, nil
}

// Subscribe registers for post-flush audit events; callers must drain and unsubscribe.
func (s *PostgresStore) Subscribe() (<-chan AuditEvent, func()) {
	return s.hub.Subscribe()
}

func (s *PostgresStore) Record(event RequestEvent) bool {
	s.admission.RLock()
	defer s.admission.RUnlock()
	if s.closed.Load() {
		return false
	}
	if event.EventID == "" {
		event.EventID = randomEventID()
	}
	event.Groups = append([]string(nil), event.Groups...)
	if event.Groups == nil {
		event.Groups = []string{}
	}
	select {
	case s.queue <- event:
		return true
	default:
		dropped := s.dropped.Add(1)
		if dropped == 1 || dropped%1000 == 0 {
			slog.Error("audit queue full; dropping Kubernetes request events", "dropped", dropped)
		}
		return false
	}
}

func (s *PostgresStore) run() {
	defer close(s.done)
	defer s.pool.Close()
	flushTicker := time.NewTicker(250 * time.Millisecond)
	retentionTicker := time.NewTicker(time.Hour)
	defer flushTicker.Stop()
	defer retentionTicker.Stop()

	batch := make([]RequestEvent, 0, 250)
	for {
		select {
		case event := <-s.queue:
			batch = append(batch, event)
			if len(batch) >= cap(batch) {
				batch = s.flushWithRetry(batch)
			}
		case <-flushTicker.C:
			batch = s.flushWithRetry(batch)
		case <-retentionTicker.C:
			s.deleteExpired()
		case <-s.stop:
			for {
				select {
				case event := <-s.queue:
					batch = append(batch, event)
				default:
					ctx := s.closeCtx
					if ctx == nil {
						ctx = context.Background()
					}
					s.flushDuringShutdown(ctx, batch)
					return
				}
			}
		}
	}
}

func (s *PostgresStore) flushWithRetry(batch []RequestEvent) []RequestEvent {
	if len(batch) == 0 {
		return batch
	}
	delay := 250 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.insertBatch(ctx, batch)
		cancel()
		if err == nil {
			return batch[:0]
		}
		slog.Error("failed to persist audit events", "count", len(batch), "error", err, "retry_in", delay)
		select {
		case <-time.After(delay):
			if delay < 10*time.Second {
				delay *= 2
			}
		case <-s.stop:
			return batch
		}
	}
}

func (s *PostgresStore) insertBatch(ctx context.Context, events []RequestEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	batch := &pgx.Batch{}
	clusters := make(map[string]struct{}, 1)
	for _, event := range events {
		var sessionID, username, remoteAddr any
		if event.SessionID != "" {
			sessionID = event.SessionID
		}
		if event.Username != "" {
			username = event.Username
		}
		if event.RemoteAddr != "" {
			remoteAddr = event.RemoteAddr
		}
		clusters[event.Cluster] = struct{}{}
		batch.Queue(`INSERT INTO api_requests (
            event_id, occurred_at, cluster, request_id, session_id, username,
            groups, authenticated, method, path, status_code, response_bytes,
            duration_ms, remote_addr, user_agent
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        ON CONFLICT (event_id) DO NOTHING`,
			event.EventID, event.OccurredAt, event.Cluster, event.RequestID,
			sessionID, username, event.Groups, event.Authenticated, event.Method,
			event.Path, event.StatusCode, event.ResponseBytes, event.Duration.Milliseconds(),
			remoteAddr, event.UserAgent,
		)
	}
	results := tx.SendBatch(ctx, batch)
	for range events {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return err
		}
	}
	if err := results.Close(); err != nil {
		return err
	}
	for cluster := range clusters {
		payload, _ := json.Marshal(AuditEvent{Cluster: cluster})
		if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", auditEventsChannel, string(payload)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ListSession(ctx context.Context, cluster, sessionID string, limit, offset int) ([]RequestEvent, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx, `SELECT id, event_id, occurred_at, cluster, request_id,
        COALESCE(session_id, ''), COALESCE(username, ''), groups, authenticated,
        method, path, status_code, response_bytes, duration_ms,
		COALESCE(remote_addr, ''), user_agent
        FROM api_requests WHERE cluster=$1 AND session_id=$2
        ORDER BY occurred_at DESC, id DESC LIMIT $3 OFFSET $4`, cluster, sessionID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]RequestEvent, 0, limit)
	for rows.Next() {
		var event RequestEvent
		var durationMS int64
		if err := rows.Scan(
			&event.ID, &event.EventID, &event.OccurredAt, &event.Cluster, &event.RequestID,
			&event.SessionID, &event.Username, &event.Groups, &event.Authenticated,
			&event.Method, &event.Path, &event.StatusCode, &event.ResponseBytes,
			&durationMS, &event.RemoteAddr, &event.UserAgent,
		); err != nil {
			return nil, err
		}
		event.Duration = time.Duration(durationMS) * time.Millisecond
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *PostgresStore) SessionMetrics(ctx context.Context, cluster, sessionID string, since time.Time) (RequestMetrics, error) {
	return s.metrics(ctx, cluster, "session_id=$3", sessionID, since)
}

func (s *PostgresStore) SessionsMetrics(ctx context.Context, cluster string, sessionIDs []string, since time.Time) (RequestMetrics, error) {
	return s.metrics(ctx, cluster, "session_id = ANY($3)", sessionIDs, since)
}

func (s *PostgresStore) GlobalMetrics(ctx context.Context, cluster string, since time.Time) (RequestMetrics, error) {
	return s.metrics(ctx, cluster, "", "", since)
}

func (s *PostgresStore) metrics(ctx context.Context, cluster, filter string, filterValue any, since time.Time) (RequestMetrics, error) {
	query := `SELECT count(*)::bigint,
        count(*) FILTER (WHERE status_code BETWEEN 400 AND 499)::bigint,
        count(*) FILTER (WHERE status_code >= 500)::bigint,
        COALESCE(sum(response_bytes), 0)::bigint,
        COALESCE(avg(duration_ms), 0)::double precision,
        COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), 0)::double precision,
        COALESCE(max(occurred_at), 'epoch'::timestamptz)
        FROM api_requests WHERE cluster=$1 AND occurred_at >= $2`
	args := []any{cluster, since}
	if filter != "" {
		query += " AND " + filter
		args = append(args, filterValue)
	}
	var metrics RequestMetrics
	var averageMS, p95MS float64
	err := s.pool.QueryRow(ctx, query, args...).Scan(
		&metrics.Requests, &metrics.ClientErrors, &metrics.ServerErrors,
		&metrics.ResponseBytes, &averageMS, &p95MS, &metrics.LastRequestAt,
	)
	metrics.Average = time.Duration(averageMS * float64(time.Millisecond))
	metrics.P95 = time.Duration(p95MS * float64(time.Millisecond))
	return metrics, err
}

func (s *PostgresStore) deleteExpired() {
	if s.retention <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(s.lifecycle, time.Minute)
	defer cancel()
	if err := s.RunRetention(ctx, time.Now()); err != nil {
		slog.Error("failed to apply audit retention", "error", err)
	}
}

// RunRetention deletes expired audit rows in bounded batches. It is exported so
// operators and integration tests can trigger the same cleanup used hourly.
func (s *PostgresStore) RunRetention(ctx context.Context, now time.Time) error {
	if s.retention <= 0 {
		return nil
	}
	cutoff := now.Add(-s.retention)
	for {
		result, err := s.pool.Exec(ctx, `WITH victims AS (
            SELECT id FROM api_requests WHERE occurred_at < $1 ORDER BY occurred_at LIMIT 10000
        ) DELETE FROM api_requests a USING victims v WHERE a.id=v.id`, cutoff)
		if err != nil {
			return err
		}
		if result.RowsAffected() < 10000 {
			return nil
		}
	}
}

func (s *PostgresStore) Close(ctx context.Context) error {
	s.admission.Lock()
	if !s.closed.Swap(true) {
		s.closeCtx = ctx
		s.cancel()
		close(s.stop)
	}
	s.admission.Unlock()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *PostgresStore) flushDuringShutdown(ctx context.Context, batch []RequestEvent) {
	delay := 100 * time.Millisecond
	for len(batch) > 0 {
		if err := s.insertBatch(ctx, batch); err == nil {
			return
		} else {
			slog.Error("failed to flush audit events during shutdown", "count", len(batch), "error", err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
			if delay < time.Second {
				delay *= 2
			}
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('kauth_audit_schema'))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, schema); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func randomEventID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value)
}
