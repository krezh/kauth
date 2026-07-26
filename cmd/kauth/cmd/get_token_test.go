package cmd

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kauth/pkg/token"
)

func TestRunGetTokenRejectsExpiredCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	profile := "0123456789abcdef"
	path, err := token.ProfileCachePath(profile)
	if err != nil {
		t.Fatal(err)
	}
	storage := token.NewStorage(path)
	if err := storage.Save(&token.Cache{
		ServerURL:    "https://kauth.example.com",
		WebhookToken: "expired-token",
		Expiry:       time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	tokenProfile = profile
	t.Cleanup(func() { tokenProfile = "" })
	if err := runGetToken(nil, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("runGetToken() error = %v, want expired-session error (cache %s)", err, filepath.Base(path))
	}
}
