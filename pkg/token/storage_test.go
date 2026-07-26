package token

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProfileID(t *testing.T) {
	first := ProfileID("https://kauth.example.com")
	if len(first) != 16 || first != ProfileID("https://kauth.example.com") {
		t.Fatalf("ProfileID() = %q", first)
	}
	if first == ProfileID("https://other.example.com") {
		t.Error("different servers produced the same profile")
	}
}

func TestStorageWithLock(t *testing.T) {
	storage := NewStorage(filepath.Join(t.TempDir(), "token.json"))
	called := false
	if err := storage.WithLock(time.Second, func() error {
		called = true
		if _, err := os.Stat(storage.cachePath + ".lock"); err != nil {
			t.Fatalf("lock file missing during callback: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("lock callback was not called")
	}
	if _, err := os.Stat(storage.cachePath + ".lock"); err != nil {
		t.Fatalf("lock file should remain reusable after callback: %v", err)
	}
}

func TestProfileCachePathRejectsTraversal(t *testing.T) {
	if _, err := ProfileCachePath("../../escape"); err == nil {
		t.Fatal("ProfileCachePath() accepted path traversal")
	}
	path, err := ProfileCachePath("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(path), "/.kube/cache/kauth-0123456789abcdef.json") {
		t.Errorf("ProfileCachePath() = %q", path)
	}
}
