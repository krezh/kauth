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

// Benchmark tests
func BenchmarkValidateResourceName(b *testing.B) {
	input := "valid-resource-name"
	for b.Loop() {
		if err := ValidateResourceName(input); err != nil {
			b.Fatal(err)
		}
	}
}
