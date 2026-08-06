package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"kauth/pkg/audit"
)

// fakeAuditStore implements audit.RequestStore, backed by a fixed slice of
// events, so fetchGroupedSessionEvents can be tested without Postgres. Every
// method except ListSession is unused by these tests and panics if called.
type fakeAuditStore struct {
	events    []audit.RequestEvent
	chunkErr  error
	callCount int
}

func (s *fakeAuditStore) ListSession(_ context.Context, _, _ string, limit, offset int) ([]audit.RequestEvent, error) {
	s.callCount++
	if s.chunkErr != nil {
		return nil, s.chunkErr
	}
	if offset >= len(s.events) {
		return nil, nil
	}
	end := min(offset+limit, len(s.events))
	return s.events[offset:end], nil
}

func (*fakeAuditStore) Record(audit.RequestEvent) bool { panic("unused") }
func (*fakeAuditStore) SessionMetrics(context.Context, string, string, time.Time) (audit.RequestMetrics, error) {
	panic("unused")
}
func (*fakeAuditStore) SessionsMetrics(context.Context, string, []string, time.Time) (audit.RequestMetrics, error) {
	panic("unused")
}
func (*fakeAuditStore) GlobalMetrics(context.Context, string, time.Time) (audit.RequestMetrics, error) {
	panic("unused")
}
func (*fakeAuditStore) Subscribe() (<-chan audit.AuditEvent, func()) { panic("unused") }
func (*fakeAuditStore) Close(context.Context) error                 { panic("unused") }

func kubectlBurst(sessionID string, base time.Time) []audit.RequestEvent {
	// Newest first, matching ListSession's ORDER BY occurred_at DESC, id DESC.
	return []audit.RequestEvent{
		{SessionID: sessionID, Path: "/api/v1/namespaces/default/pods", OccurredAt: base},
		{SessionID: sessionID, Path: "/apis", OccurredAt: base.Add(-3 * time.Millisecond)},
		{SessionID: sessionID, Path: "/api", OccurredAt: base.Add(-4 * time.Millisecond)},
	}
}

func TestFetchGroupedSessionEvents_GroupsDiscoveryUnderPrimary(t *testing.T) {
	base := time.Date(2026, 8, 5, 20, 57, 0, 0, time.UTC)
	store := &fakeAuditStore{events: kubectlBurst("sess-1", base)}

	groups, hasNext, err := fetchGroupedSessionEvents(context.Background(), store, "cluster", "sess-1", 100, 0)
	if err != nil {
		t.Fatalf("fetchGroupedSessionEvents() error = %v", err)
	}
	if hasNext {
		t.Fatal("hasNext = true, want false (only one group of 3 raw rows)")
	}
	if len(groups) != 1 {
		t.Fatalf("len(groups) = %d, want 1", len(groups))
	}
	if groups[0].Path != "/api/v1/namespaces/default/pods" {
		t.Fatalf("primary path = %q, want the real request", groups[0].Path)
	}
	if len(groups[0].Discovery) != 2 {
		t.Fatalf("len(Discovery) = %d, want 2", len(groups[0].Discovery))
	}
	if groups[0].Discovery[0].Path != "/apis" || groups[0].Discovery[1].Path != "/api" {
		t.Fatalf("Discovery = %+v, want [/apis /api] in stream order", groups[0].Discovery)
	}
}

func TestFetchGroupedSessionEvents_OrphanDiscoveryStandsAlone(t *testing.T) {
	base := time.Date(2026, 8, 5, 20, 57, 0, 0, time.UTC)
	store := &fakeAuditStore{events: []audit.RequestEvent{
		{SessionID: "sess-1", Path: "/apis", OccurredAt: base},
	}}

	groups, _, err := fetchGroupedSessionEvents(context.Background(), store, "cluster", "sess-1", 100, 0)
	if err != nil {
		t.Fatalf("fetchGroupedSessionEvents() error = %v", err)
	}
	if len(groups) != 1 || groups[0].Path != "/apis" || len(groups[0].Discovery) != 0 {
		t.Fatalf("groups = %+v, want a single standalone /apis row with no children", groups)
	}
}

func TestFetchGroupedSessionEvents_DifferentSessionDoesNotGroup(t *testing.T) {
	base := time.Date(2026, 8, 5, 20, 57, 0, 0, time.UTC)
	store := &fakeAuditStore{events: []audit.RequestEvent{
		{SessionID: "sess-1", Path: "/api/v1/namespaces/default/pods", OccurredAt: base},
		{SessionID: "sess-2", Path: "/apis", OccurredAt: base.Add(-1 * time.Millisecond)},
	}}

	groups, _, err := fetchGroupedSessionEvents(context.Background(), store, "cluster", "sess-1", 100, 0)
	if err != nil {
		t.Fatalf("fetchGroupedSessionEvents() error = %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2 (different sessions must not group)", len(groups))
	}
}

func TestFetchGroupedSessionEvents_OutsideWindowDoesNotGroup(t *testing.T) {
	base := time.Date(2026, 8, 5, 20, 57, 0, 0, time.UTC)
	store := &fakeAuditStore{events: []audit.RequestEvent{
		{SessionID: "sess-1", Path: "/api/v1/namespaces/default/pods", OccurredAt: base},
		{SessionID: "sess-1", Path: "/apis", OccurredAt: base.Add(-3 * time.Second)},
	}}

	groups, _, err := fetchGroupedSessionEvents(context.Background(), store, "cluster", "sess-1", 100, 0)
	if err != nil {
		t.Fatalf("fetchGroupedSessionEvents() error = %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2 (3s gap exceeds the 2s grouping window)", len(groups))
	}
}

func TestFetchGroupedSessionEvents_GroupNeverSplitsAcrossChunkBoundary(t *testing.T) {
	base := time.Date(2026, 8, 5, 20, 57, 0, 0, time.UTC)
	// sessionEventsChunkSize primary/discovery bursts, forcing multiple
	// ListSession round-trips; one burst straddles a chunk edge.
	var events []audit.RequestEvent
	for i := range 90 {
		t := base.Add(-time.Duration(i) * time.Second)
		events = append(events, audit.RequestEvent{SessionID: "sess-1", Path: "/api/v1/namespaces/default/pods", OccurredAt: t})
		events = append(events, audit.RequestEvent{SessionID: "sess-1", Path: "/apis", OccurredAt: t.Add(-1 * time.Millisecond)})
		events = append(events, audit.RequestEvent{SessionID: "sess-1", Path: "/api", OccurredAt: t.Add(-2 * time.Millisecond)})
	}
	store := &fakeAuditStore{events: events}

	// pageSize=70 is deliberately chosen so the page can't resolve out of a
	// single 200-row chunk: chunk 1 (events[0:200]) contains 66 complete
	// bursts plus burst 67's primary and first discovery call only (its
	// second discovery call is event index 200, one past the chunk edge),
	// so after chunk 1 alone there are 67 group entries — not > 70, forcing
	// a second ListSession call to resolve burst 67 and reach the page size.
	groups, hasNext, err := fetchGroupedSessionEvents(context.Background(), store, "cluster", "sess-1", 70, 0)
	if err != nil {
		t.Fatalf("fetchGroupedSessionEvents() error = %v", err)
	}
	if len(groups) != 70 {
		t.Fatalf("len(groups) = %d, want a full page of 70 primary rows", len(groups))
	}
	for i, g := range groups {
		if len(g.Discovery) != 2 {
			t.Fatalf("groups[%d].Discovery = %+v, want 2 children each, including group 66 which straddles the %d-row chunk boundary", i, g.Discovery, sessionEventsChunkSize)
		}
	}
	if !hasNext {
		t.Fatal("hasNext = false, want true (90 primaries exist, page size 70)")
	}
	if store.callCount < 2 {
		t.Fatalf("callCount = %d, want at least 2 (burst 67 straddles the %d-row chunk boundary, forcing a second ListSession call)", store.callCount, sessionEventsChunkSize)
	}
}

func TestFetchGroupedSessionEvents_OffsetPastEndReturnsEmpty(t *testing.T) {
	base := time.Date(2026, 8, 5, 20, 57, 0, 0, time.UTC)
	store := &fakeAuditStore{events: kubectlBurst("sess-1", base)}

	groups, hasNext, err := fetchGroupedSessionEvents(context.Background(), store, "cluster", "sess-1", 100, 5)
	if err != nil {
		t.Fatalf("fetchGroupedSessionEvents() error = %v", err)
	}
	if len(groups) != 0 || hasNext {
		t.Fatalf("groups = %+v, hasNext = %v, want empty page with no next", groups, hasNext)
	}
}

func TestFetchGroupedSessionEvents_PropagatesStoreError(t *testing.T) {
	store := &fakeAuditStore{chunkErr: errors.New("boom")}
	_, _, err := fetchGroupedSessionEvents(context.Background(), store, "cluster", "sess-1", 100, 0)
	if err == nil {
		t.Fatal("fetchGroupedSessionEvents() error = nil, want the store error propagated")
	}
}
