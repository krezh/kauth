package handlers

import (
	"fmt"
	"testing"
)

func TestLoginHandler_isUserAuthorized(t *testing.T) {
	tests := []struct {
		name          string
		allowedGroups []string
		userGroups    []string
		want          bool
	}{
		{
			name:          "no group restrictions - allow all",
			allowedGroups: []string{},
			userGroups:    []string{"any-group"},
			want:          true,
		},
		{
			name:          "no group restrictions - empty user groups",
			allowedGroups: []string{},
			userGroups:    []string{},
			want:          true,
		},
		{
			name:          "user has matching group",
			allowedGroups: []string{"admin", "developers"},
			userGroups:    []string{"developers"},
			want:          true,
		},
		{
			name:          "user has one of multiple allowed groups",
			allowedGroups: []string{"admin", "developers", "ops"},
			userGroups:    []string{"developers"},
			want:          true,
		},
		{
			name:          "user has multiple groups, one matches",
			allowedGroups: []string{"admin"},
			userGroups:    []string{"users", "admin", "guests"},
			want:          true,
		},
		{
			name:          "user has multiple groups, multiple match",
			allowedGroups: []string{"admin", "developers"},
			userGroups:    []string{"admin", "developers", "users"},
			want:          true,
		},
		{
			name:          "user has no matching groups",
			allowedGroups: []string{"admin", "developers"},
			userGroups:    []string{"users", "guests"},
			want:          false,
		},
		{
			name:          "user has no groups but groups required",
			allowedGroups: []string{"admin"},
			userGroups:    []string{},
			want:          false,
		},
		{
			name:          "empty user groups with restrictions",
			allowedGroups: []string{"admin", "developers"},
			userGroups:    []string{},
			want:          false,
		},
		{
			name:          "case sensitive - no match",
			allowedGroups: []string{"Admin"},
			userGroups:    []string{"admin"},
			want:          false,
		},
		{
			name:          "exact string match required",
			allowedGroups: []string{"admin"},
			userGroups:    []string{"administrator"},
			want:          false,
		},
		{
			name:          "whitespace matters",
			allowedGroups: []string{"admin"},
			userGroups:    []string{"admin "},
			want:          false,
		},
		{
			name:          "single allowed group, single user group match",
			allowedGroups: []string{"admin"},
			userGroups:    []string{"admin"},
			want:          true,
		},
		{
			name:          "nil user groups treated as empty",
			allowedGroups: []string{"admin"},
			userGroups:    nil,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &LoginHandler{
				allowedGroups: tt.allowedGroups,
			}

			got := h.isUserAuthorized(tt.userGroups)
			if got != tt.want {
				t.Errorf("LoginHandler.isUserAuthorized() = %v, want %v (allowedGroups=%v, userGroups=%v)",
					got, tt.want, tt.allowedGroups, tt.userGroups)
			}
		})
	}
}

func TestLoginHandler_isUserAuthorizedEdgeCases(t *testing.T) {
	t.Run("nil allowed groups - allows all", func(t *testing.T) {
		h := &LoginHandler{
			allowedGroups: nil,
		}
		if !h.isUserAuthorized([]string{"any-group"}) {
			t.Errorf("nil allowedGroups should allow all users")
		}
	})

	t.Run("empty strings in groups", func(t *testing.T) {
		h := &LoginHandler{
			allowedGroups: []string{""},
		}
		if !h.isUserAuthorized([]string{""}) {
			t.Errorf("empty string should match empty string")
		}
	})

	t.Run("special characters in group names", func(t *testing.T) {
		h := &LoginHandler{
			allowedGroups: []string{"group/admin", "group:developers"},
		}
		if !h.isUserAuthorized([]string{"group/admin"}) {
			t.Errorf("special characters should be matched exactly")
		}
		if !h.isUserAuthorized([]string{"group:developers"}) {
			t.Errorf("special characters should be matched exactly")
		}
	})

	t.Run("unicode characters in group names", func(t *testing.T) {
		h := &LoginHandler{
			allowedGroups: []string{"管理者", "разработчики"},
		}
		if !h.isUserAuthorized([]string{"管理者"}) {
			t.Errorf("unicode characters should be matched exactly")
		}
	})

	t.Run("very long group names", func(t *testing.T) {
		longGroup := string(make([]byte, 10000))
		h := &LoginHandler{
			allowedGroups: []string{longGroup},
		}
		if !h.isUserAuthorized([]string{longGroup}) {
			t.Errorf("long group names should be matched")
		}
	})
}

func TestLoginHandler_isUserAuthorizedPerformance(t *testing.T) {
	// Test with many groups to ensure performance is acceptable
	allowedGroups := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		allowedGroups[i] = fmt.Sprintf("group-%d", i)
	}

	userGroups := []string{"group-999"} // Last group

	h := &LoginHandler{
		allowedGroups: allowedGroups,
	}

	// Should still complete quickly
	if !h.isUserAuthorized(userGroups) {
		t.Errorf("should find group-999 in allowed groups")
	}
}
