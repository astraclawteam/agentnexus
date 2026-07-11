package deploypreflight

import (
	"errors"
	"net/url"
	"strings"
)

var allowedTLSModes = map[string]struct{}{
	"require":     {},
	"verify-ca":   {},
	"verify-full": {},
}

func ValidateProductionPostgresDSN(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.IndexFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("production PostgreSQL DSN is empty or contains unsafe whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgres" || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.Fragment != "" || parsed.Path == "" || parsed.Path == "/" {
		return errors.New("production PostgreSQL DSN must be a postgres URL with host and database")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return errors.New("production PostgreSQL DSN query is malformed")
	}
	for _, field := range strings.Split(parsed.RawQuery, "&") {
		rawKey, rawValue, _ := strings.Cut(field, "=")
		decodedKey, err := url.QueryUnescape(rawKey)
		if err != nil {
			return errors.New("production PostgreSQL DSN query is malformed")
		}
		if strings.EqualFold(decodedKey, "sslmode") && (rawKey != "sslmode" || strings.Contains(rawValue, "%")) {
			return errors.New("production PostgreSQL DSN sslmode must not use percent encoding")
		}
	}
	var modes []string
	for key, values := range query {
		if strings.EqualFold(key, "sslmode") {
			if key != "sslmode" {
				return errors.New("production PostgreSQL DSN sslmode key is non-canonical")
			}
			modes = append(modes, values...)
		}
	}
	if len(modes) != 1 {
		return errors.New("production PostgreSQL DSN requires exactly one explicit sslmode")
	}
	if _, ok := allowedTLSModes[modes[0]]; !ok {
		return errors.New("production PostgreSQL DSN sslmode must be require, verify-ca, or verify-full")
	}
	return nil
}
