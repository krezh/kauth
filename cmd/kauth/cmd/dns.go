package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

type discoveredServer struct {
	URL  string
	Name string
}

// discoverDNS looks up _kauth.<domain> TXT records and returns any valid kauth servers.
// Returns nil (no error) when no records exist — callers fall back to cached URL.
func discoverDNS(domain string) []discoveredServer {
	records, err := net.LookupTXT("_kauth." + domain)
	if err != nil {
		return nil
	}
	var servers []discoveredServer
	for _, record := range records {
		url, name := parseTXTRecord(record)
		if url != "" {
			servers = append(servers, discoveredServer{URL: url, Name: name})
		}
	}
	return servers
}

// parseTXTRecord parses a TXT record of the form:
//
//	v=kauth1 url=https://kauth.example.com name=production
//
// The name field is optional. Records without v=kauth1 are ignored.
func parseTXTRecord(record string) (url, name string) {
	var hasVersion bool
	for _, field := range strings.Fields(record) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch k {
		case "v":
			hasVersion = v == "kauth1"
		case "url":
			url = v
		case "name":
			name = v
		}
	}
	if !hasVersion {
		return "", ""
	}
	return url, name
}

// detectDomain returns the DNS search domain to query for kauth servers.
// Resolution order: KAUTH_DOMAIN env var → USERDNSDOMAIN env var →
// FQDN hostname suffix → /etc/resolv.conf search/domain line.
func detectDomain() (string, error) {
	if d := os.Getenv("KAUTH_DOMAIN"); d != "" {
		return d, nil
	}
	if d := os.Getenv("USERDNSDOMAIN"); d != "" {
		return strings.ToLower(d), nil
	}
	if hostname, err := os.Hostname(); err == nil {
		if _, domain, found := strings.Cut(hostname, "."); found && domain != "" {
			return domain, nil
		}
	}
	return domainFromResolvConf()
}

func domainFromResolvConf() (string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("could not determine DNS search domain: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "domain ") || strings.HasPrefix(line, "search ") {
			if parts := strings.Fields(line); len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading /etc/resolv.conf: %w", err)
	}
	return "", fmt.Errorf("no DNS search domain found in /etc/resolv.conf")
}
