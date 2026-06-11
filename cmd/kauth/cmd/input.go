package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

type promptOption struct {
	key   string
	label string
}

func promptMenu(options []promptOption, indent string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return promptMenuFallback(options, indent)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return promptMenuFallback(options, indent)
	}
	defer term.Restore(fd, oldState) //nolint:errcheck

	fmt.Print("\x1b[?25l")
	defer fmt.Print("\x1b[?25h")

	var parts []string
	for _, opt := range options {
		parts = append(parts, fmt.Sprintf("%s %s", pill.Render(opt.key), muted.Render(opt.label)))
	}
	fmt.Printf("\n%s%s\r\n\r\n", indent, strings.Join(parts, muted.Render(" / ")))

	buf := make([]byte, 32)
	for {
		n, err := os.Stdin.Read(buf)
		if n == 0 || err != nil {
			return "", fmt.Errorf("input closed")
		}
		b := buf[:n]

		switch b[0] {
		case 3:
			fmt.Print("\r\n")
			return "", fmt.Errorf("interrupted")
		default:
			key := strings.ToLower(string(b[0]))
			for _, opt := range options {
				if key == opt.key {
					if key == "c" {
						fmt.Printf("%s%s %s\r\n", indent, warningIcon, muted.Render("Cancelled"))
					} else {
						fmt.Printf("%s%s %s\r\n", indent, successIcon, muted.Render(opt.label))
					}
					return key, nil
				}
			}
		}
	}
}

func promptMenuFallback(options []promptOption, indent string) (string, error) {
	var parts []string
	for _, opt := range options {
		parts = append(parts, fmt.Sprintf("%s %s", pill.Render(opt.key), muted.Render(opt.label)))
	}
	fmt.Printf("\n%s%s\r\n", indent, strings.Join(parts, muted.Render(" / ")))

	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	in := strings.TrimSpace(strings.ToLower(line))
	if in == "" {
		fmt.Printf("%s%s %s\r\n", indent, successIcon, muted.Render(options[0].label))
		return options[0].key, nil
	}
	for _, opt := range options {
		if in == opt.key {
			if in == "c" {
				fmt.Printf("%s%s %s\r\n", indent, warningIcon, muted.Render("Cancelled"))
			} else {
				fmt.Printf("%s%s %s\r\n", indent, successIcon, muted.Render(opt.label))
			}
			return in, nil
		}
	}
	return "", fmt.Errorf("invalid choice %q", in)
}
