package token

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
)

var profilePattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

// Cache represents the token cache structure
type Cache struct {
	ServerURL        string    `json:"server_url,omitempty"`
	IDToken          string    `json:"id_token,omitempty"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	RefreshRequestID string    `json:"refresh_request_id,omitempty"`
	SessionID        string    `json:"session_id,omitempty"`
	WebhookToken     string    `json:"webhook_token,omitempty"`
	Expiry           time.Time `json:"expiry,omitempty"`
}

// WithLock serializes cache read-modify-write operations across processes.
func (s *Storage) WithLock(timeout time.Duration, fn func() error) error {
	dir := filepath.Dir(s.cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	return WithFileLock(s.cachePath+".lock", timeout, fn)
}

// WithFileLock serializes a file transaction and is released by the OS on exit.
func WithFileLock(lockPath string, timeout time.Duration, fn func() error) error {
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	defer func() { _ = lock.Close() }()
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
			return fn()
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("failed to acquire token cache lock: %w", err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("timed out waiting for token cache lock")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Storage handles token persistence
type Storage struct {
	cachePath string
}

// NewStorage creates a new token storage instance
func NewStorage(cachePath string) *Storage {
	return &Storage{
		cachePath: cachePath,
	}
}

// DefaultCachePath returns the default cache path for the current user
func DefaultCachePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	return filepath.Join(homeDir, ".kube", "cache", "kauth-token.json")
}

// ProfileID returns a stable, non-secret cache profile for a kauth server URL.
func ProfileID(serverURL string) string {
	sum := sha256.Sum256([]byte(serverURL))
	return fmt.Sprintf("%x", sum[:8])
}

// ProfileCachePath returns the cache path for a validated profile ID.
func ProfileCachePath(profile string) (string, error) {
	if !profilePattern.MatchString(profile) {
		return "", fmt.Errorf("invalid token cache profile")
	}
	return filepath.Join(filepath.Dir(DefaultCachePath()), "kauth-"+profile+".json"), nil
}

// HasProfileCaches reports whether profile-aware logins exist on this machine.
func HasProfileCaches() bool {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(DefaultCachePath()), "kauth-????????????????.json"))
	return err == nil && len(matches) > 0
}

// Load loads a token from the cache
func (s *Storage) Load() (*Cache, error) {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read token cache: %w", err)
	}

	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token cache: %w", err)
	}

	return &cache, nil
}

// Save saves a token to the cache with secure permissions.
// Uses a temp-file + rename to avoid partial writes under concurrent kubectl calls.
func (s *Storage) Save(cache *Cache) error {
	if cache == nil {
		return fmt.Errorf("cannot save nil cache")
	}

	dir := filepath.Dir(s.cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".kauth-token-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set temp file permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, s.cachePath); err != nil {
		return fmt.Errorf("failed to rename token cache: %w", err)
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("failed to open token cache directory: %w", err)
	}
	defer func() { _ = dirHandle.Close() }()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("failed to sync token cache directory: %w", err)
	}

	return nil
}

// Delete removes the token cache file
func (s *Storage) Delete() error {
	if err := os.Remove(s.cachePath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to delete token cache: %w", err)
	}
	return nil
}

// Exists checks if a token cache file exists
func (s *Storage) Exists() bool {
	_, err := os.Stat(s.cachePath)
	return err == nil
}
