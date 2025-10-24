package validation

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateResourceName validates a Kubernetes resource name (RFC 1123 subdomain)
func ValidateResourceName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("name cannot be empty")
	}
	if len(name) > 63 {
		return fmt.Errorf("name exceeds 63 characters: %d", len(name))
	}

	pattern := `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	matched, _ := regexp.MatchString(pattern, name)
	if !matched {
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

	// Convert to lowercase and replace invalid characters with dashes
	name := ""
	for _, ch := range input {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			name += string(ch)
		} else if ch >= 'A' && ch <= 'Z' {
			name += string(ch - 'A' + 'a') // Convert uppercase to lowercase
		} else {
			name += "-"
		}
	}

	// Remove leading dashes/dots
	name = strings.TrimLeft(name, "-.")

	// Remove trailing dashes/dots
	name = strings.TrimRight(name, "-.")

	// Truncate if too long (max 63 chars for k8s names)
	if len(name) > 63 {
		name = name[:63]
		// Ensure we didn't truncate to end with a dash/dot
		name = strings.TrimRight(name, "-.")
	}

	// Ensure name isn't empty after sanitization
	if name == "" {
		name = "default"
	}

	return name
}
