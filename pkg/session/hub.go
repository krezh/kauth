package session

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const sessionEventsChannel = "kauth_session_events"

// SessionEvent is delivered to subscribers on session mutation; no tokens.
type SessionEvent struct {
	SessionID string `json:"session_id"`
	Phase     Phase  `json:"phase"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
}

// Hub fans out kauth_session_events NOTIFY payloads to local subscribers.
type Hub struct {
	databaseURL string
	mu          sync.Mutex
	subs        map[chan SessionEvent]struct{}
}

func NewHub(databaseURL string) (*Hub, error) {
	return &Hub{databaseURL: databaseURL, subs: make(map[chan SessionEvent]struct{})}, nil
}

// Subscribe returns a channel to drain and an unsubscribe func; valid across reconnects.
func (h *Hub) Subscribe() (<-chan SessionEvent, func()) {
	ch := make(chan SessionEvent, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

func (h *Hub) publish(ev SessionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
			// slow subscriber, drop
		}
	}
}

// Run holds a dedicated (non-pooled) LISTEN connection open, reconnecting with backoff on error.
func (h *Hub) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for ctx.Err() == nil {
		if err := h.listenOnce(ctx); err != nil {
			slog.ErrorContext(ctx, "session hub: listen connection failed, reconnecting", "error", err, "backoff", backoff)
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

	if _, err := conn.Exec(ctx, "LISTEN "+sessionEventsChannel); err != nil {
		return err
	}
	slog.InfoContext(ctx, "session hub: listening", "channel", sessionEventsChannel)

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var ev SessionEvent
		if err := json.Unmarshal([]byte(notification.Payload), &ev); err != nil {
			slog.WarnContext(ctx, "session hub: dropping malformed notification", "error", err)
			continue
		}
		h.publish(ev)
	}
}
