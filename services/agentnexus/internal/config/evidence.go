package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
)

// EvidenceConfig locates the node-local staging root and the stable content
// encryption key of the semantic evidence runtime.
//
// It is OPTIONAL: without it /v1/runtime/locate and /v1/runtime/read stay
// UNREGISTERED, which is the historical behaviour. It is ALL-OR-NOTHING when
// present, because there is no safe default for either half — an invented
// staging root would scatter encrypted customer content somewhere nobody
// chose, and a generated key would be per-process, which silently makes every
// handle staged before a restart unreadable.
type EvidenceConfig struct {
	// ObjectRoot is the directory encrypted staged content lives under. It is
	// NODE-LOCAL: with more than one gateway-api replica, a handle staged by one
	// replica is unreadable on another (the read fails closed with 503, it does
	// not leak and it does not serve a substitute). A multi-replica deployment
	// needs a shared ObjectStore implementation, which this build does not have.
	ObjectRoot string
	// ContentKeyRef is the STABLE reference persisted into every handle. It must
	// not change across restarts or redeploys: reads resolve a handle's key by
	// this reference, so rotating it orphans previously staged content.
	ContentKeyRef string
	// ContentKey is exactly evidence.ContentKeyBytes of AES-256 key material.
	ContentKey []byte
	// SourceCatalog is the private semantic registry this deployment declares:
	// the data classes that exist, the connector binding supplying each, and
	// the organization-placed capability that authorizes reading it.
	//
	// It is part of the all-or-nothing set rather than an optional extra. A
	// staging root and a key with no catalog compose a registry that is EMPTY,
	// so every locate denies at not_resolvable — a runtime surface that
	// registers, reports healthy, and refuses everything. That failure has no
	// symptom worth noticing, which is precisely why it must be refused at
	// startup instead.
	SourceCatalog evidence.SourceCatalog
}

// Enabled reports whether the evidence runtime should be composed at all.
func (c EvidenceConfig) Enabled() bool {
	return c.ObjectRoot != "" && c.ContentKeyRef != "" && len(c.ContentKey) > 0 && c.SourceCatalog.Declared()
}

// Evidence environment variables.
const (
	envEvidenceObjectRoot    = "AGENTNEXUS_EVIDENCE_OBJECT_ROOT"
	envEvidenceContentKeyRef = "AGENTNEXUS_EVIDENCE_CONTENT_KEY_REF"
	envEvidenceContentKey    = "AGENTNEXUS_EVIDENCE_CONTENT_KEY_FILE"
	envEvidenceSourceCatalog = "AGENTNEXUS_EVIDENCE_SOURCE_CATALOG_FILE"
)

// LoadEvidence reads the evidence runtime settings. A partial set is an error
// rather than a silent fallback, on the AGENTNEXUS_APPROVAL_CHANNEL precedent:
// an operator who configured a staging root but no key must be told at startup,
// not left with a runtime surface that accepts every locate and fails it.
func LoadEvidence() (EvidenceConfig, error) {
	root := strings.TrimSpace(os.Getenv(envEvidenceObjectRoot))
	keyRef := strings.TrimSpace(os.Getenv(envEvidenceContentKeyRef))
	keyPath := strings.TrimSpace(os.Getenv(envEvidenceContentKey))
	catalogPath := strings.TrimSpace(os.Getenv(envEvidenceSourceCatalog))
	if root == "" && keyRef == "" && keyPath == "" && catalogPath == "" {
		return EvidenceConfig{}, nil
	}
	var missing []string
	for _, entry := range []struct{ name, value string }{
		{envEvidenceObjectRoot, root},
		{envEvidenceContentKeyRef, keyRef},
		{envEvidenceContentKey, keyPath},
		{envEvidenceSourceCatalog, catalogPath},
	} {
		if entry.value == "" {
			missing = append(missing, entry.name)
		}
	}
	if len(missing) > 0 {
		return EvidenceConfig{}, fmt.Errorf(
			"the evidence runtime needs %s, %s, %s and %s together; missing: %s",
			envEvidenceObjectRoot, envEvidenceContentKeyRef, envEvidenceContentKey, envEvidenceSourceCatalog,
			strings.Join(missing, ", "))
	}
	key, err := loadEvidenceContentKey(keyPath)
	if err != nil {
		return EvidenceConfig{}, err
	}
	catalog, err := loadEvidenceSourceCatalog(catalogPath)
	if err != nil {
		return EvidenceConfig{}, err
	}
	return EvidenceConfig{ObjectRoot: root, ContentKeyRef: keyRef, ContentKey: key, SourceCatalog: catalog}, nil
}

// loadEvidenceSourceCatalog reads and fully validates the private semantic
// registry document. Validation happens HERE, at config load, so a malformed
// catalog is reported against the environment variable that named it rather
// than surfacing later as an opaque router-composition failure. The connector
// references it names are resolved later, against the database.
func loadEvidenceSourceCatalog(path string) (evidence.SourceCatalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return evidence.SourceCatalog{}, fmt.Errorf("read %s: %w", envEvidenceSourceCatalog, err)
	}
	catalog, err := evidence.ParseSourceCatalog(raw)
	if err != nil {
		return evidence.SourceCatalog{}, fmt.Errorf("%s: %w", envEvidenceSourceCatalog, err)
	}
	return catalog, nil
}

// loadEvidenceContentKey reads the base64 (standard encoding) content key from
// a file. The length is checked here so a wrong key fails at startup rather
// than at the first locate, where it would surface as an opaque 503.
func loadEvidenceContentKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", envEvidenceContentKey, err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s must contain standard base64 key material: %w", envEvidenceContentKey, err)
	}
	if len(key) != evidence.ContentKeyBytes {
		return nil, fmt.Errorf("%s must decode to exactly %d bytes (AES-256), got %d",
			envEvidenceContentKey, evidence.ContentKeyBytes, len(key))
	}
	if isAllZero(key) {
		return nil, errors.New(envEvidenceContentKey + " must not be an all-zero key")
	}
	return key, nil
}

func isAllZero(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}
