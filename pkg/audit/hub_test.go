package audit

import (
	"context"
	"os"
	"testing"
	"time"
)

func testStore(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, dsn, 16, time.Hour)
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM api_requests WHERE cluster LIKE 'hub-test-%'"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close(context.Background())
	})
	return s
}

func TestHub_NotifiesSubscribersAfterFlush(t *testing.T) {
	store := testStore(t)

	ch, unsubscribe := store.Subscribe()
	defer unsubscribe()

	time.Sleep(200 * time.Millisecond) // let listenOnce establish LISTEN before recording

	if !store.Record(RequestEvent{Cluster: "hub-test-cluster", Method: "GET", Path: "/x", StatusCode: 200}) {
		t.Fatal("Record returned false")
	}

	select {
	case ev := <-ch:
		if ev.Cluster != "hub-test-cluster" {
			t.Errorf("Cluster = %q, want %q", ev.Cluster, "hub-test-cluster")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive audit event within 5s")
	}
}

func TestHub_TwoSubscribersReceiveOneNotify(t *testing.T) {
	store := testStore(t)

	ch1, unsub1 := store.Subscribe()
	defer unsub1()
	ch2, unsub2 := store.Subscribe()
	defer unsub2()

	time.Sleep(200 * time.Millisecond)

	if !store.Record(RequestEvent{Cluster: "hub-test-cluster-2", Method: "GET", Path: "/y", StatusCode: 200}) {
		t.Fatal("Record returned false")
	}

	for i, ch := range []<-chan AuditEvent{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.Cluster != "hub-test-cluster-2" {
				t.Errorf("subscriber %d Cluster = %q, want %q", i, ev.Cluster, "hub-test-cluster-2")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("subscriber %d did not receive the event within 5s", i)
		}
	}
}
