package validation

import (
	"strings"
	"testing"
)

func TestValidateResourceName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "valid lowercase name",
			input:     "valid-name",
			wantError: false,
		},
		{
			name:      "valid with numbers",
			input:     "valid-name-123",
			wantError: false,
		},
		{
			name:      "valid with dots",
			input:     "valid.name.example",
			wantError: false,
		},
		{
			name:      "valid single character",
			input:     "a",
			wantError: false,
		},
		{
			name:      "invalid uppercase",
			input:     "Invalid-Name",
			wantError: true,
		},
		{
			name:      "invalid underscore",
			input:     "invalid_name",
			wantError: true,
		},
		{
			name:      "invalid starts with dash",
			input:     "-invalid",
			wantError: true,
		},
		{
			name:      "invalid ends with dash",
			input:     "invalid-",
			wantError: true,
		},
		{
			name:      "invalid empty",
			input:     "",
			wantError: true,
		},
		{
			name:      "invalid too long",
			input:     strings.Repeat("a", 64),
			wantError: true,
		},
		{
			name:      "valid exactly 63 chars",
			input:     strings.Repeat("a", 63),
			wantError: false,
		},
		{
			name:      "invalid special characters",
			input:     "name@example.com",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResourceName(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateResourceName(%q) error = %v, wantError %v", tt.input, err, tt.wantError)
			}
		})
	}
}

func TestSanitizeToResourceName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already valid",
			input:    "valid-name",
			expected: "valid-name",
		},
		{
			name:     "uppercase to lowercase",
			input:    "ValidName",
			expected: "validname",
		},
		{
			name:     "underscore to dash",
			input:    "valid_name",
			expected: "valid-name",
		},
		{
			name:     "email address",
			input:    "user@example.com",
			expected: "user-example-com",
		},
		{
			name:     "email with plus",
			input:    "user+test@example.com",
			expected: "user-test-example-com",
		},
		{
			name:     "mixed case email",
			input:    "User.Name@Example.COM",
			expected: "user-name-example-com",
		},
		{
			name:     "leading dash removed",
			input:    "-invalid",
			expected: "invalid",
		},
		{
			name:     "trailing dash removed",
			input:    "invalid-",
			expected: "invalid",
		},
		{
			name:     "multiple consecutive dashes",
			input:    "name---with---dashes",
			expected: "name---with---dashes",
		},
		{
			name:     "special characters",
			input:    "name!@#$%test",
			expected: "name-----test",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "default",
		},
		{
			name:     "only special characters",
			input:    "!@#$%",
			expected: "default",
		},
		{
			name:     "too long",
			input:    strings.Repeat("a", 100),
			expected: strings.Repeat("a", 63),
		},
		{
			name:     "too long with trailing dash",
			input:    strings.Repeat("a", 62) + "-" + strings.Repeat("b", 50),
			expected: strings.Repeat("a", 62),
		},
		{
			name:     "oauth state with underscores",
			input:    "x96Pc3ynjOX2eMnby1oZI1jSmfCwUn7ai_O9TYPJaBc",
			expected: "x96pc3ynjox2emnby1ozi1jsmfcwun7ai-o9typjabc",
		},
		{
			name:     "spaces to dashes",
			input:    "my cluster name",
			expected: "my-cluster-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeToResourceName(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeToResourceName(%q) = %q, want %q", tt.input, result, tt.expected)
			}

			// Verify result is valid
			if err := ValidateResourceName(result); err != nil {
				t.Errorf("SanitizeToResourceName(%q) produced invalid result %q: %v", tt.input, result, err)
			}
		})
	}
}

// Benchmark tests
func BenchmarkSanitizeToResourceName(b *testing.B) {
	input := "User.Name+Test@Example.COM"
	for i := 0; i < b.N; i++ {
		SanitizeToResourceName(input)
	}
}

func BenchmarkValidateResourceName(b *testing.B) {
	input := "valid-resource-name"
	for i := 0; i < b.N; i++ {
		ValidateResourceName(input)
	}
}
