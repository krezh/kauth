package handlers

import (
	"context"
	"testing"
)

func TestCallerClaims_isAdmin(t *testing.T) {
	tests := []struct {
		name        string
		claims      *CallerClaims
		adminGroups []string
		want        bool
	}{
		{
			name: "user in admin group",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{"developers", "admins"},
			},
			adminGroups: []string{"admins"},
			want:        true,
		},
		{
			name: "user not in admin group",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{"developers"},
			},
			adminGroups: []string{"admins"},
			want:        false,
		},
		{
			name: "user in multiple admin groups",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{"super-admins", "developers"},
			},
			adminGroups: []string{"admins", "super-admins"},
			want:        true,
		},
		{
			name: "empty admin groups - no one is admin",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{"admins"},
			},
			adminGroups: []string{},
			want:        false,
		},
		{
			name: "nil admin groups - no one is admin",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{"admins"},
			},
			adminGroups: nil,
			want:        false,
		},
		{
			name: "user has no groups",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{},
			},
			adminGroups: []string{"admins"},
			want:        false,
		},
		{
			name: "user has nil groups",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: nil,
			},
			adminGroups: []string{"admins"},
			want:        false,
		},
		{
			name: "case sensitive - no match",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{"Admins"},
			},
			adminGroups: []string{"admins"},
			want:        false,
		},
		{
			name: "exact match required",
			claims: &CallerClaims{
				Email:  "user@example.com",
				Groups: []string{"administrator"},
			},
			adminGroups: []string{"admin"},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.isAdmin(tt.adminGroups)
			if got != tt.want {
				t.Errorf("isAdmin() = %v, want %v (groups=%v, adminGroups=%v)",
					got, tt.want, tt.claims.Groups, tt.adminGroups)
			}
		})
	}
}

func TestGetCaller(t *testing.T) {
	t.Run("nil context value returns nil", func(t *testing.T) {
		ctx := context.Background()
		claims := getCaller(ctx)
		if claims != nil {
			t.Errorf("getCaller() = %v, want nil", claims)
		}
	})

	t.Run("extracts caller from context", func(t *testing.T) {
		expected := &CallerClaims{
			Email:  "test@example.com",
			Groups: []string{"group1"},
		}
		ctx := context.WithValue(context.Background(), callerContextKey, expected)
		got := getCaller(ctx)
		if got == nil {
			t.Fatal("getCaller() = nil, want non-nil")
		}
		if got.Email != expected.Email {
			t.Errorf("Email = %q, want %q", got.Email, expected.Email)
		}
		if len(got.Groups) != len(expected.Groups) {
			t.Errorf("Groups length = %d, want %d", len(got.Groups), len(expected.Groups))
		}
	})
}
