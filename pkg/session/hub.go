package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const sessionEventsChannel = "kauth_session_events"

// SessionEvent is delivered to subscribers on session mutation; no tokens.
type SessionEvent struct {
	SessionID string `json:"session_id"`
	Cluster   string `json:"cluster"`
	Phase     Phase  `json:"phase"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
}

// subscriberBuffer is deliberately generous: an expiry sweep publishes one event per
// expired session, and a dropped Active event stalls a waiting CLI login.
const subscriberBuffer = 256

// Hub fans out kauth_session_events NOTIFY payloads to local subscribers.
type Hub struct {
	// connConfig is parsed once so the raw DSN, password included, is not retained.
	connConfig *pgx.ConnConfig
	cluster    string
	mu         sync.Mutex
	subs       map[chan SessionEvent]struct{}
}

func NewHub(databaseURL, cluster string) (*Hub, error) {
	if cluster == "" {
		return nil, errors.New("cluster is required")
	}
	connConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	return &Hub{connConfig: connConfig, cluster: cluster, subs: make(map[chan SessionEvent]struct{})}, nil
}

// Subscribe returns a channel to drain and an unsubscribe func; valid across reconnects.
func (h *Hub) Subscribe() (<-chan SessionEvent, func()) {
	ch := make(chan SessionEvent, subscriberBuffer)
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
			slog.ErrorContext(ctx, "session hub: listen connection failed, reconnecting", "error", err, "backoff", backoff)
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

	if _, err := conn.Exec(ctx, "LISTEN "+sessionEventsChannel); err != nil {
		return err
	}
	onConnected()
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
		if ev.Cluster != h.cluster {
			continue
		}
		h.publish(ev)
	}
}
