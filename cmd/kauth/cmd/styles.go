package cmd

import (
	"fmt"
	"net/url"

	"charm.land/lipgloss/v2"
)

var (
	bold   = lipgloss.NewStyle().Bold(true)
	muted  = lipgloss.NewStyle().Foreground(lipgloss.Color("#7f849c")) // Overlay1
	accent = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa")).Bold(true) // Blue
	green  = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1")).Bold(true) // Green
	link   = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa")).Underline(true) // Blue

	red    = lipgloss.NewStyle().Foreground(lipgloss.Color("#f38ba8")).Bold(true) // Red
	yellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#f9e2af")).Bold(true) // Yellow
	orange = lipgloss.NewStyle().Foreground(lipgloss.Color("#fab387"))            // Peach

	pill = lipgloss.NewStyle().
		Background(lipgloss.Color("#cba6f7")). // Mauve
		Foreground(lipgloss.Color("#1e1e2e")). // Base
		Padding(0, 1).
		Bold(true)

	successIcon = green.Render("✓")
	warningIcon = yellow.Render("!")
	errorIcon   = red.Render("✗")
	infoIcon    = orange.Render("i")
)

func hyperlink(styledText, rawURL string) string {
	return fmt.Sprintf("\x1b]8;;%s\x1b\\%s\x1b]8;;\x1b\\", rawURL, styledText)
}

func urlHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}
