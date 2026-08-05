package audit

import (
	"context"
	"encoding/json"
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
	databaseURL string
	mu          sync.Mutex
	subs        map[chan AuditEvent]struct{}
}

func NewHub(databaseURL string) *Hub {
	return &Hub{databaseURL: databaseURL, subs: make(map[chan AuditEvent]struct{})}
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

// Run holds a dedicated (non-pooled) LISTEN connection open, reconnecting with backoff on error.
func (h *Hub) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for ctx.Err() == nil {
		if err := h.listenOnce(ctx); err != nil {
			slog.ErrorContext(ctx, "audit hub: listen connection failed, reconnecting", "error", err, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second
	}
}

func (h *Hub) listenOnce(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, h.databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()

	if _, err := conn.Exec(ctx, "LISTEN "+auditEventsChannel); err != nil {
		return err
	}
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
