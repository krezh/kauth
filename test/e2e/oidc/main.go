//go:build e2e

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

const keyID = "kauth-e2e"

func main() {
	issuer := os.Getenv("ISSUER_URL")
	if issuer == "" {
		log.Fatal("ISSUER_URL is required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": keyID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "the E2E harness submits the callback directly", http.StatusNotImplemented)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		if r.Form.Get("grant_type") == "authorization_code" {
			_, expectedChallenge, ok := strings.Cut(code, ".")
			actualChallenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || expectedChallenge != base64.RawURLEncoding.EncodeToString(actualChallenge[:]) {
				http.Error(w, "invalid PKCE verifier", http.StatusUnauthorized)
				return
			}
		}
		groups := []string{"kauth-e2e-allowed", "system:masters"}
		if strings.HasPrefix(code, "dashboard-user-code.") {
			groups = []string{"users"}
		}
		idToken, err := signIDToken(key, issuer, "e2e", groups)
		if err != nil {
			http.Error(w, "sign token", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"access_token":  "e2e-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "e2e-refresh-token",
			"id_token":      idToken,
		})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
}

func signIDToken(key *rsa.PrivateKey, issuer, audience string, groups []string) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"iss":                issuer,
		"aud":                audience,
		"sub":                "e2e-user",
		"email":              "e2e-user@example.com",
		"preferred_username": "e2e-user",
		"name":               "E2E User",
		"groups":             groups,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}
