package browser

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Open opens a URL in the default browser for the current platform
func Open(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		// Try multiple commands as different distros have different defaults
		for _, c := range []string{"xdg-open", "x-www-browser", "www-browser"} {
			if err := exec.Command(c, url).Start(); err == nil {
				return nil
			}
		}
		return fmt.Errorf("could not find a browser to open - please visit the URL manually")
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err := exec.Command(cmd, args...).Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}

	return nil
}
