package audit

import "testing"

func TestPostgresStoreRecordNormalizesGroups(t *testing.T) {
	store := &PostgresStore{queue: make(chan RequestEvent, 1)}
	if !store.Record(RequestEvent{SessionID: "session-1"}) {
		t.Fatal("Record returned false")
	}
	event := <-store.queue
	if event.Groups == nil {
		t.Fatal("Groups must be a non-nil empty array for PostgreSQL NOT NULL")
	}
}

func TestPostgresStoreRecordDropsWhenQueueIsFull(t *testing.T) {
	store := &PostgresStore{queue: make(chan RequestEvent, 1)}
	if !store.Record(RequestEvent{}) {
		t.Fatal("first event should fit")
	}
	if store.Record(RequestEvent{}) {
		t.Fatal("second event should be dropped")
	}
	if got := store.dropped.Load(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}
