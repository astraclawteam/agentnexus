package browserauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const consoleClientSecretHashDomain = "agentnexus:console-client-secret:v1:"

type consoleClientCredentialHashes struct {
	current     [32]byte
	previous    [32]byte
	hasPrevious bool
}

// ConsoleClientCredentials deliberately has no field capable of retaining a raw secret.
type ConsoleClientCredentials struct {
	clients map[string]consoleClientCredentialHashes
}

func NewConsoleClientCredentials(raw map[string][]string) (ConsoleClientCredentials, error) {
	credentials := ConsoleClientCredentials{clients: make(map[string]consoleClientCredentialHashes, len(raw))}
	for clientID, secrets := range raw {
		if !ValidConsoleClientID(clientID) || len(secrets) < 1 || len(secrets) > 2 {
			return ConsoleClientCredentials{}, errors.New("console client requires current and optional previous secret")
		}
		for _, secret := range secrets {
			if err := validateConsoleClientSecret(secret); err != nil {
				return ConsoleClientCredentials{}, fmt.Errorf("console client %q: %w", clientID, err)
			}
		}
		entry := consoleClientCredentialHashes{current: consoleClientSecretHash(clientID, secrets[0])}
		if len(secrets) == 2 {
			entry.previous = consoleClientSecretHash(clientID, secrets[1])
			entry.hasPrevious = true
			if subtle.ConstantTimeCompare(entry.current[:], entry.previous[:]) == 1 {
				return ConsoleClientCredentials{}, fmt.Errorf("console client %q current and previous secrets must differ", clientID)
			}
		}
		credentials.clients[clientID] = entry
	}
	return credentials, nil
}

func (c ConsoleClientCredentials) ValidateClosedSet(consoleClients map[string][]string) error {
	if len(consoleClients) == 0 || len(c.clients) != len(consoleClients) {
		return errors.New("console credential client set must exactly match redirect client set")
	}
	for clientID := range consoleClients {
		if _, ok := c.clients[clientID]; !ok {
			return fmt.Errorf("console client %q has no confidential credential", clientID)
		}
	}
	return nil
}

func (c ConsoleClientCredentials) Authenticate(clientID, secret string) bool {
	entry, ok := c.clients[clientID]
	candidate := consoleClientSecretHash(clientID, secret)
	currentMatch := subtle.ConstantTimeCompare(candidate[:], entry.current[:])
	previousMatch := subtle.ConstantTimeCompare(candidate[:], entry.previous[:])
	valid := subtle.ConstantTimeEq(int32(currentMatch|previousMatch), 1)
	return ok && valid == 1 && (currentMatch == 1 || entry.hasPrevious)
}

func consoleClientSecretHash(clientID, secret string) [32]byte {
	return sha256.Sum256([]byte(consoleClientSecretHashDomain + clientID + ":" + secret))
}

func LoadConsoleClientSecretFiles(rawJSON string, consoleClients map[string][]string) (ConsoleClientCredentials, error) {
	paths, err := DecodeUniqueStringSliceMapJSON(rawJSON)
	if err != nil {
		return ConsoleClientCredentials{}, errors.New("parse console client secret files JSON")
	}
	if len(paths) != len(consoleClients) {
		return ConsoleClientCredentials{}, errors.New("console secret file client set must be closed")
	}
	raw := make(map[string][]string, len(paths))
	for clientID, clientPaths := range paths {
		if _, ok := consoleClients[clientID]; !ok || len(clientPaths) < 1 || len(clientPaths) > 2 {
			return ConsoleClientCredentials{}, fmt.Errorf("invalid console secret file entry for %q", clientID)
		}
		if len(clientPaths) == 2 && clientPaths[0] == clientPaths[1] {
			return ConsoleClientCredentials{}, fmt.Errorf("duplicate console secret path for %q", clientID)
		}
		for _, path := range clientPaths {
			secret, err := loadStrictSecretFile(path)
			if err != nil {
				return ConsoleClientCredentials{}, fmt.Errorf("load console client %q secret: %w", clientID, err)
			}
			raw[clientID] = append(raw[clientID], secret)
		}
	}
	credentials, err := NewConsoleClientCredentials(raw)
	if err != nil {
		return ConsoleClientCredentials{}, err
	}
	if err := credentials.ValidateClosedSet(consoleClients); err != nil {
		return ConsoleClientCredentials{}, err
	}
	return credentials, nil
}

func DecodeUniqueStringSliceMapJSON(rawJSON string) (map[string][]string, error) {
	return decodeUniqueMapJSON[[]string](rawJSON)
}

func DecodeUniqueStringMapJSON(rawJSON string) (map[string]string, error) {
	return decodeUniqueMapJSON[string](rawJSON)
}

func decodeUniqueMapJSON[T any](rawJSON string) (map[string]T, error) {
	if rawJSON == "" {
		return nil, errors.New("empty JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(rawJSON)))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("secret file map must be an object")
	}
	values := map[string]T{}
	for decoder.More() {
		token, err := decoder.Token()
		clientID, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid console client key")
		}
		if _, exists := values[clientID]; exists {
			return nil, errors.New("duplicate console client key")
		}
		var value T
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		values[clientID] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("invalid console client map ending")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing console client JSON")
	}
	return values, nil
}

func ValidConsoleClientID(clientID string) bool {
	if len(clientID) < 1 || len(clientID) > 256 {
		return false
	}
	for i := 0; i < len(clientID); i++ {
		value := clientID[i]
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '.' || value == '_' || value == '~' || value == '-' {
			continue
		}
		return false
	}
	return true
}

// LoadOIDCUpstreamClientSecret loads the separate upstream IdP credential.
func LoadOIDCUpstreamClientSecret(path string) (string, error) {
	return loadStrictSecretFile(path)
}

func loadStrictSecretFile(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("secret path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("secret must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("secret file permissions are too broad")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := string(data)
	if err := validateConsoleClientSecret(secret); err != nil {
		return "", err
	}
	return secret, nil
}

func validateConsoleClientSecret(secret string) error {
	if len(secret) < 32 || len(secret) > 256 {
		return errors.New("secret must contain 32 to 256 bytes")
	}
	seen := map[byte]struct{}{}
	for i := 0; i < len(secret); i++ {
		if secret[i] < 0x21 || secret[i] > 0x7e {
			return errors.New("secret must be printable ASCII without whitespace")
		}
		seen[secret[i]] = struct{}{}
	}
	if len(seen) < 12 {
		return errors.New("secret does not meet minimum entropy diversity")
	}
	return nil
}
