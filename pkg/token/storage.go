package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Cache represents the token cache structure
type Cache struct {
	ServerURL    string    `json:"server_url,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
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
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, s.cachePath); err != nil {
		return fmt.Errorf("failed to rename token cache: %w", err)
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
