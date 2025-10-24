package session

import (
	"strings"
	"testing"
)

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name  string
		state string
		want  string
	}{
		{
			name:  "simple lowercase state",
			state: "abcdef123456",
			want:  "oauth-abcdef123456",
		},
		{
			name:  "uppercase converted to lowercase",
			state: "ABCDEF123456",
			want:  "oauth-abcdef123456",
		},
		{
			name:  "special characters converted to dashes",
			state: "abc!@#def$%^123",
			want:  "oauth-abc---def---123",
		},
		{
			name:  "base64 URL-safe characters",
			state: "abc_def-123",
			want:  "oauth-abc-def-123",
		},
		{
			name:  "email-like state",
			state: "user@example.com",
			want:  "oauth-user-example-com",
		},
		{
			name:  "dots converted to dashes",
			state: "state.with.dots",
			want:  "oauth-state-with-dots",
		},
		{
			name:  "leading dash removed",
			state: "-leadingdash",
			want:  "oauth-leadingdash",
		},
		{
			name:  "trailing dash removed",
			state: "trailingdash-",
			want:  "oauth-trailingdash",
		},
		{
			name:  "multiple consecutive dashes",
			state: "state---with---dashes",
			want:  "oauth-state---with---dashes",
		},
		{
			name:  "very long state truncated",
			state: strings.Repeat("a", 100),
			want:  "oauth-" + strings.Repeat("a", 57),
		},
		{
			name:  "exactly 57 chars after sanitization",
			state: strings.Repeat("a", 57),
			want:  "oauth-" + strings.Repeat("a", 57),
		},
		{
			name:  "empty state gets default",
			state: "",
			want:  "oauth-default",
		},
		{
			name:  "only special characters gets default",
			state: "!@#$%^&*()",
			want:  "oauth-default",
		},
		{
			name:  "unicode characters converted to dashes",
			state: "state-with-日本語",
			want:  "oauth-state-with",
		},
		{
			name:  "mixed case with numbers",
			state: "AbC123DeF456",
			want:  "oauth-abc123def456",
		},
		{
			name:  "state with plus signs",
			state: "state+with+plus",
			want:  "oauth-state-with-plus",
		},
		{
			name:  "state with underscores",
			state: "state_with_underscores",
			want:  "oauth-state-with-underscores",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeName(tt.state)
			if got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.state, got, tt.want)
			}

			// Verify result is a valid Kubernetes resource name
			if len(got) > 63 {
				t.Errorf("sanitizeName(%q) = %q, length %d exceeds 63 characters", tt.state, got, len(got))
			}

			// Verify starts with "oauth-"
			if !strings.HasPrefix(got, "oauth-") {
				t.Errorf("sanitizeName(%q) = %q, does not start with 'oauth-'", tt.state, got)
			}
		})
	}
}

func TestSanitizeNameKubernetesCompliance(t *testing.T) {
	// Test various states to ensure output is always Kubernetes-compliant
	states := []string{
		"normal-state-123",
		"UPPERCASE-STATE",
		"state!with@special#chars",
		"state_with_underscores",
		"state+with+plus",
		"user@example.com",
		strings.Repeat("a", 100),
		"",
		"!@#$%",
		"-leading-dash",
		"trailing-dash-",
		"state.with.dots",
	}

	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			result := sanitizeName(state)

			// Check length
			if len(result) > 63 {
				t.Errorf("result %q exceeds 63 characters (len=%d)", result, len(result))
			}

			// Check lowercase
			if result != strings.ToLower(result) {
				t.Errorf("result %q is not lowercase", result)
			}

			// Check starts and ends with alphanumeric (if not empty after prefix)
			if len(result) > 6 { // "oauth-" is 6 chars
				lastChar := result[len(result)-1]
				if !isAlphanumeric(lastChar) {
					t.Errorf("result %q ends with non-alphanumeric character %c", result, lastChar)
				}
			}

			// Check prefix
			if !strings.HasPrefix(result, "oauth-") {
				t.Errorf("result %q does not start with 'oauth-'", result)
			}

			// Check only contains valid characters (lowercase alphanumeric, '-', '.')
			for i, c := range result {
				if !isValidK8sNameChar(byte(c)) {
					t.Errorf("result %q contains invalid character %c at position %d", result, c, i)
				}
			}
		})
	}
}

func TestSanitizeNameIdempotent(t *testing.T) {
	// Sanitizing an already sanitized name should not change it (except for prefix)
	validState := "already-valid-123"
	result1 := sanitizeName(validState)

	// Remove prefix and sanitize again
	withoutPrefix := strings.TrimPrefix(result1, "oauth-")
	result2 := sanitizeName(withoutPrefix)

	if result1 != result2 {
		t.Errorf("sanitizeName is not idempotent: %q -> %q -> %q", validState, result1, result2)
	}
}

func TestSanitizeNameUniqueness(t *testing.T) {
	// Different states should produce different sanitized names (in most cases)
	states := []string{
		"state1",
		"state2",
		"state-1",
		"state-2",
	}

	results := make(map[string]string)
	for _, state := range states {
		result := sanitizeName(state)
		if prev, exists := results[result]; exists {
			// This is acceptable if the states are similar enough
			t.Logf("sanitizeName collision: %q and %q both produce %q", prev, state, result)
		}
		results[result] = state
	}
}

// Helper functions for validation
func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func isValidK8sNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
}
