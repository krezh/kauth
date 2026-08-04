package session

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestHub_TwoSubscribersReceiveOneNotify(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub, err := NewHub(dsn)
	if err != nil {
		t.Fatal(err)
	}
	go hub.Run(ctx)

	ch1, unsub1 := hub.Subscribe()
	defer unsub1()
	ch2, unsub2 := hub.Subscribe()
	defer unsub2()

	// let listenOnce establish LISTEN before publishing
	time.Sleep(200 * time.Millisecond)

	client := testClient(t)
	if _, err := client.Create(ctx, "hub-test-session", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "hub-test-session", Status{
		Phase: PhaseActive, Subject: "sub-123", Issuer: "https://issuer.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	for i, ch := range []<-chan SessionEvent{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.SessionID != "hub-test-session" {
				t.Errorf("subscriber %d got SessionID = %q, want %q", i, ev.SessionID, "hub-test-session")
			}
			if ev.Phase != PhaseActive {
				t.Errorf("subscriber %d got Phase = %q, want %q", i, ev.Phase, PhaseActive)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("subscriber %d did not receive the event within 5s", i)
		}
	}
}
