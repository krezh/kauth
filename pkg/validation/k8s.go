package validation

import (
	"fmt"
	"regexp"
	"strings"
)

var resourceNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// ValidateResourceName validates a Kubernetes resource name (RFC 1123 subdomain)
func ValidateResourceName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("name cannot be empty")
	}
	if len(name) > 63 {
		return fmt.Errorf("name exceeds 63 characters: %d", len(name))
	}
	if !resourceNameRE.MatchString(name) {
		return fmt.Errorf("name must be lowercase alphanumeric with hyphens or dots: %q", name)
	}
	return nil
}

// SanitizeToResourceName converts any string to a valid Kubernetes resource name
// following RFC 1123 subdomain rules: lowercase alphanumeric characters, '-' or '.',
// and must start and end with an alphanumeric character
func SanitizeToResourceName(input string) string {
	if input == "" {
		return "default"
	}

	var b strings.Builder
	b.Grow(len(input))
	for _, ch := range input {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			b.WriteRune(ch - 'A' + 'a')
		default:
			b.WriteByte('-')
		}
	}

	name := strings.TrimRight(strings.TrimLeft(b.String(), "-."), "-.")

	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-.")
	}

	if name == "" {
		return "default"
	}
	return name
}
