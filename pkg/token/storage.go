package token

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cache represents the token cache structure
type Cache struct {
	IDToken      string    `json:"id_token"`
	RefreshToken string    `json:"refresh_token"`
	SessionID    string    `json:"session_id"`
	Expiry       time.Time `json:"expiry"`
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
		if os.IsNotExist(err) {
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

// Save saves a token to the cache with secure permissions
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

	if err := os.WriteFile(s.cachePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token cache: %w", err)
	}

	return nil
}

// Delete removes the token cache file
func (s *Storage) Delete() error {
	if err := os.Remove(s.cachePath); err != nil {
		if os.IsNotExist(err) {
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
