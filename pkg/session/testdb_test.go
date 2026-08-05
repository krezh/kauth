package session

import (
	"context"
	"os"
	"testing"
)

func testClient(t *testing.T) *Client {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	c, err := NewClient(ctx, dsn, "test-cluster")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := c.pool.Exec(ctx, "DELETE FROM oauth_sessions WHERE cluster=$1", c.cluster); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
	})
	return c
}
