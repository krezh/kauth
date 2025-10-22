package token

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

// Cache represents the token cache structure
type Cache struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	TokenType    string    `json:"token_type"`
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

// Save saves a token to the cache with secure permissions
func (s *Storage) Save(token *oauth2.Token) error {
	if token == nil {
		return fmt.Errorf("cannot save nil token")
	}

	// Create cache directory with 0700 permissions (rwx for owner only)
	dir := filepath.Dir(s.cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Build cache structure
	cache := Cache{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	}

	// Extract ID token from extras
	if idToken, ok := token.Extra("id_token").(string); ok {
		cache.IDToken = idToken
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Write with 0600 permissions (rw- for owner only)
	if err := os.WriteFile(s.cachePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token cache: %w", err)
	}

	return nil
}

// Load loads a token from the cache
func (s *Storage) Load() (*oauth2.Token, error) {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cache exists
		}
		return nil, fmt.Errorf("failed to read token cache: %w", err)
	}

	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token cache: %w", err)
	}

	// Build oauth2.Token
	token := &oauth2.Token{
		AccessToken:  cache.AccessToken,
		RefreshToken: cache.RefreshToken,
		TokenType:    cache.TokenType,
		Expiry:       cache.Expiry,
	}

	// Add ID token to extras if present
	if cache.IDToken != "" {
		token = token.WithExtra(map[string]interface{}{
			"id_token": cache.IDToken,
		})
	}

	return token, nil
}

// Delete removes the token cache file
func (s *Storage) Delete() error {
	if err := os.Remove(s.cachePath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
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

// GetIDToken extracts the ID token from an oauth2.Token
func GetIDToken(token *oauth2.Token) (string, error) {
	if token == nil {
		return "", fmt.Errorf("token is nil")
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return "", fmt.Errorf("no id_token found in token")
	}

	return idToken, nil
}
