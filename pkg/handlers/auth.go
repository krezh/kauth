package handlers

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"kauth/pkg/oauth"
)

type contextKey string

const callerContextKey = contextKey("caller")

// CallerClaims represents the authenticated caller's claims
type CallerClaims struct {
	Email  string
	Groups []string
}

// RequireAuth is middleware that verifies the Bearer token and extracts caller claims
func RequireAuth(getProvider func() *oauth.Provider, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := getProvider()
		if provider == nil {
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		rawToken, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		idToken, err := provider.VerifyIDToken(r.Context(), rawToken)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		var claims struct {
			Email  string   `json:"email"`
			Groups []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
			return
		}

		if claims.Email == "" {
			http.Error(w, "Token must contain email claim", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), callerContextKey, &CallerClaims{
			Email:  claims.Email,
			Groups: claims.Groups,
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// getCaller extracts caller claims from context
func getCaller(ctx context.Context) *CallerClaims {
	claims, _ := ctx.Value(callerContextKey).(*CallerClaims)
	return claims
}

// isAdmin checks if the caller is in any of the admin groups
func (c *CallerClaims) isAdmin(adminGroups []string) bool {
	for _, ag := range adminGroups {
		if slices.Contains(c.Groups, ag) {
			return true
		}
	}
	return false
}
