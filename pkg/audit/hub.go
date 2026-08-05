package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const auditEventsChannel = "kauth_audit_events"

// AuditEvent is delivered to subscribers after a batch flush; no request details, just a refresh signal.
type AuditEvent struct {
	Cluster string `json:"cluster"`
}

// Hub fans out kauth_audit_events NOTIFY payloads to local subscribers.
type Hub struct {
	// connConfig is parsed once so the raw DSN, password included, is not retained.
	connConfig *pgx.ConnConfig
	mu         sync.Mutex
	subs       map[chan AuditEvent]struct{}
}

func NewHub(databaseURL string) (*Hub, error) {
	connConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	return &Hub{connConfig: connConfig, subs: make(map[chan AuditEvent]struct{})}, nil
}

// Subscribe returns a channel to drain and an unsubscribe func; valid across reconnects.
func (h *Hub) Subscribe() (<-chan AuditEvent, func()) {
	ch := make(chan AuditEvent, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

func (h *Hub) publish(ev AuditEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
	// healthyConnection is how long a LISTEN connection must stay up for the next
	// reconnect to start over at minBackoff.
	healthyConnection = 30 * time.Second
)

// Run holds a dedicated (non-pooled) LISTEN connection open, reconnecting with backoff on error.
func (h *Hub) Run(ctx context.Context) {
	backoff := minBackoff
	for ctx.Err() == nil {
		var connectedAt time.Time
		err := h.listenOnce(ctx, func() { connectedAt = time.Now() })
		if !connectedAt.IsZero() && time.Since(connectedAt) >= healthyConnection {
			backoff = minBackoff
		}
		if err != nil {
			slog.ErrorContext(ctx, "audit hub: listen connection failed, reconnecting", "error", err, "backoff", backoff)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (h *Hub) listenOnce(ctx context.Context, onConnected func()) error {
	conn, err := pgx.ConnectConfig(ctx, h.connConfig.Copy())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()

	if _, err := conn.Exec(ctx, "LISTEN "+auditEventsChannel); err != nil {
		return err
	}
	onConnected()
	slog.InfoContext(ctx, "audit hub: listening", "channel", auditEventsChannel)

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var ev AuditEvent
		if err := json.Unmarshal([]byte(notification.Payload), &ev); err != nil {
			slog.WarnContext(ctx, "audit hub: dropping malformed notification", "error", err)
			continue
		}
		h.publish(ev)
	}
}
