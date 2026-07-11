package browserauth

import (
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConsoleClientCredentialsAuthenticateCurrentAndPreviousWithoutRawSecret(t *testing.T) {
	dir := t.TempDir()
	currentPath := filepath.Join(dir, "current.secret")
	previousPath := filepath.Join(dir, "previous.secret")
	current := "C0nsole-current-7qVw8xK2mP4rT6yB9dF3hJ5s"
	previous := "C0nsole-previous-4mN8vQ2xL6pR9tY3bD7fH5kS"
	writeSecretFile(t, currentPath, current)
	writeSecretFile(t, previousPath, previous)

	credentials, err := LoadConsoleClientSecretFiles(
		`{"agentatlas":[`+quoteJSON(currentPath)+`,`+quoteJSON(previousPath)+`]}`,
		map[string][]string{"agentatlas": {"https://atlas.example/auth/callback"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{current, previous} {
		if !credentials.Authenticate("agentatlas", secret) {
			t.Fatalf("configured credential rejected")
		}
	}
	if credentials.Authenticate("agentatlas", "wrong-secret-with-sufficient-length-123456789") || credentials.Authenticate("other", current) {
		t.Fatal("wrong client credential accepted")
	}
	formatted := fmt.Sprintf("%#v", credentials)
	if contains(formatted, current) || contains(formatted, previous) {
		t.Fatal("raw downstream console secret retained in memory config")
	}
	// The production comparison must remain constant-time over equal-length hashes.
	left := consoleClientSecretHash("agentatlas", current)
	right := consoleClientSecretHash("agentatlas", current)
	if subtle.ConstantTimeCompare(left[:], right[:]) != 1 {
		t.Fatal("credential hash contract invalid")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestConsoleClientSecretFilesFailClosed(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.secret")
	writeSecretFile(t, good, "C0nsole-current-7qVw8xK2mP4rT6yB9dF3hJ5s")
	clients := map[string][]string{"agentatlas": {"https://atlas.example/auth/callback"}}
	cases := map[string]string{
		"missing client": `{}`,
		"unknown client": `{"agentatlas":[` + quoteJSON(good) + `],"unknown":[` + quoteJSON(good) + `]}`,
		"duplicate path": `{"agentatlas":[` + quoteJSON(good) + `,` + quoteJSON(good) + `]}`,
		"relative path":  `{"agentatlas":["relative.secret"]}`,
		"duplicate key":  `{"agentatlas":[` + quoteJSON(good) + `],"agentatlas":[` + quoteJSON(good) + `]}`,
		"wrong value":    `{"agentatlas":` + quoteJSON(good) + `}`,
		"trailing JSON":  `{"agentatlas":[` + quoteJSON(good) + `]}[]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConsoleClientSecretFiles(raw, clients); err == nil {
				t.Fatal("unsafe console credential config accepted")
			}
		})
	}
	weak := filepath.Join(dir, "weak.secret")
	writeSecretFile(t, weak, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := LoadConsoleClientSecretFiles(`{"agentatlas":[`+quoteJSON(weak)+`]}`, clients); err == nil {
		t.Fatal("low-entropy console secret accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(good, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConsoleClientSecretFiles(`{"agentatlas":[`+quoteJSON(good)+`]}`, clients); err == nil {
			t.Fatal("broad secret permissions accepted")
		}
	}
}

func TestConsoleClientIDUsesOneCanonicalASCIIContract(t *testing.T) {
	valid := []string{"agentatlas", "AgentAtlas.BFF_1", "client~prod-2"}
	for _, clientID := range valid {
		if !ValidConsoleClientID(clientID) {
			t.Fatalf("valid client id rejected: %q", clientID)
		}
	}
	invalid := []string{"", " bad", "bad ", "bad:client", "bad%client", "bad+client", "bad/client", "客户端", string(make([]byte, 257))}
	for _, clientID := range invalid {
		if ValidConsoleClientID(clientID) {
			t.Fatalf("unsafe client id accepted: %q", clientID)
		}
		if _, err := NewConsoleClientCredentials(map[string][]string{clientID: {"Console-BFF-secret-Q7mV2xK9pR4tY8dF3"}}); err == nil {
			t.Fatalf("credential map accepted unsafe client id: %q", clientID)
		}
	}
}

func TestSecureJSONMapDecodersRejectDuplicateWrongShapeAndTrailingData(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate slice key": `{"atlas":["a"],"atlas":["b"]}`,
		"wrong slice value":   `{"atlas":"a"}`,
		"nested slice value":  `{"atlas":[["a"]]}`,
		"slice trailing":      `{"atlas":["a"]}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUniqueStringSliceMapJSON(raw); err == nil {
				t.Fatal("unsafe JSON accepted")
			}
		})
	}
	for name, raw := range map[string]string{
		"duplicate string key": `{"old":"a","old":"b"}`,
		"wrong string value":   `{"old":["a"]}`,
		"nested string value":  `{"old":{"path":"a"}}`,
		"string trailing":      `{"old":"a"}[]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUniqueStringMapJSON(raw); err == nil {
				t.Fatal("unsafe JSON accepted")
			}
		})
	}
}

func writeSecretFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func quoteJSON(value string) string {
	quoted := []byte{'"'}
	for _, b := range []byte(value) {
		if b == '\\' || b == '"' {
			quoted = append(quoted, '\\')
		}
		quoted = append(quoted, b)
	}
	return string(append(quoted, '"'))
}
