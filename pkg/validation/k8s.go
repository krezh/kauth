package validation

import (
	"fmt"
	"regexp"
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
