package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
)

func writeEvidenceKeyFile(t *testing.T, encoded string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "content.key")
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

func validEvidenceKey() string {
	key := make([]byte, evidence.ContentKeyBytes)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// validEvidenceCatalog is a minimal well-formed private semantic registry: one
// data class, read through one named customer connector binding, authorized by
// an organization-placed capability the neutral policy actually grants.
const validEvidenceCatalog = `{
  "schema_version": "evidence.source_catalog/v1",
  "sources": [
    {
      "tenant_ref": "ent-1",
      "data_class": "erp.purchase_orders",
      "connector": {"binding_key": "erp-prod", "capability": "erp.purchase_order.read"},
      "access_capability": "knowledge.suggest",
      "resource_type": "knowledge",
      "resource_id": "kb-space",
      "cached_read_allowed": true
    }
  ]
}`

func writeEvidenceCatalogFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write catalog file: %v", err)
	}
	return path
}

func TestLoadEvidenceIsDisabledWhenNothingIsSet(t *testing.T) {
	t.Setenv(envEvidenceObjectRoot, "")
	t.Setenv(envEvidenceContentKeyRef, "")
	t.Setenv(envEvidenceContentKey, "")
	t.Setenv(envEvidenceSourceCatalog, "")
	cfg, err := LoadEvidence()
	if err != nil {
		t.Fatalf("LoadEvidence: %v", err)
	}
	// Unset is the historical shape: /v1/runtime/locate and /v1/runtime/read
	// stay unregistered rather than being registered over an invented key.
	if cfg.Enabled() {
		t.Fatal("LoadEvidence enabled the runtime with nothing configured")
	}
}

func TestLoadEvidenceRejectsAPartialSet(t *testing.T) {
	for _, tc := range []struct{ name, root, ref, keyPath, catalogPath string }{
		{"root only", "/var/lib/evidence", "", "", ""},
		{"root and ref, no key", "/var/lib/evidence", "evd-key-1", "", ""},
		{"key without root", "", "evd-key-1", "somewhere", ""},
		{"root and key, no ref", "/var/lib/evidence", "", "somewhere", ""},
		// The case this task exists for. A staging root and a stable key with no
		// declared sources compose a plane whose registry is EMPTY: every locate
		// denies at not_resolvable while /healthz and /readyz say nothing is
		// wrong. That is the one failure shape nobody notices, so it must be a
		// startup error like every other incomplete half.
		{"everything but the catalog", "/var/lib/evidence", "evd-key-1", "somewhere", ""},
		{"catalog alone", "", "", "", "somewhere"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envEvidenceObjectRoot, tc.root)
			t.Setenv(envEvidenceContentKeyRef, tc.ref)
			t.Setenv(envEvidenceContentKey, tc.keyPath)
			t.Setenv(envEvidenceSourceCatalog, tc.catalogPath)
			// A partial set must be a startup error, not a silent skip: an
			// operator who configured a staging root but no key would otherwise
			// get a plane that accepts every locate and fails it.
			cfg, err := LoadEvidence()
			if err == nil {
				t.Fatalf("LoadEvidence accepted a partial set (enabled=%t)", cfg.Enabled())
			}
			if !strings.Contains(err.Error(), "missing") {
				t.Errorf("error must name what is missing, got %v", err)
			}
		})
	}
}

func TestLoadEvidenceRejectsUnusableKeyMaterial(t *testing.T) {
	for _, tc := range []struct{ name, contents string }{
		{"not base64", "this is not base64 !!"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 64))},
		// An all-zero key is well-formed AES-256 material and would seal and
		// open perfectly, which is exactly why it has to be refused here: it is
		// what a placeholder or a truncated secret mount looks like.
		{"all zero", base64.StdEncoding.EncodeToString(make([]byte, evidence.ContentKeyBytes))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envEvidenceObjectRoot, "/var/lib/evidence")
			t.Setenv(envEvidenceContentKeyRef, "evd-key-1")
			t.Setenv(envEvidenceContentKey, writeEvidenceKeyFile(t, tc.contents))
			// Set a VALID catalog so the failure below can only be the key.
			t.Setenv(envEvidenceSourceCatalog, writeEvidenceCatalogFile(t, validEvidenceCatalog))
			if _, err := LoadEvidence(); err == nil {
				t.Fatal("LoadEvidence accepted unusable key material")
			}
		})
	}
}

// A catalog that cannot be applied is refused at config load, named against the
// variable that supplied it. Booting past any of these would give a deployment
// that denies the data class it believes it declared.
func TestLoadEvidenceRejectsAnUnusableCatalog(t *testing.T) {
	for _, tc := range []struct{ name, contents string }{
		{"not json", "this is not json"},
		{"wrong schema version", `{"schema_version":"evidence.source_catalog/v2","sources":[]}`},
		{"no sources", `{"schema_version":"evidence.source_catalog/v1","sources":[]}`},
		{"unknown field", `{"schema_version":"evidence.source_catalog/v1","sources":[],"extra":1}`},
		{"no connector reference", `{"schema_version":"evidence.source_catalog/v1","sources":[
			{"tenant_ref":"ent-1","data_class":"erp.purchase_orders",
			 "access_capability":"knowledge.suggest","resource_type":"knowledge","resource_id":"kb-space"}]}`},
		{"capability the policy does not grant", `{"schema_version":"evidence.source_catalog/v1","sources":[
			{"tenant_ref":"ent-1","data_class":"erp.purchase_orders",
			 "connector":{"binding_key":"erp-prod","capability":"erp.purchase_order.read"},
			 "access_capability":"knowledge.invented","resource_type":"knowledge","resource_id":"kb-space"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envEvidenceObjectRoot, "/var/lib/evidence")
			t.Setenv(envEvidenceContentKeyRef, "evd-key-1")
			t.Setenv(envEvidenceContentKey, writeEvidenceKeyFile(t, validEvidenceKey()))
			t.Setenv(envEvidenceSourceCatalog, writeEvidenceCatalogFile(t, tc.contents))
			_, err := LoadEvidence()
			if err == nil {
				t.Fatal("LoadEvidence accepted an unusable source catalog")
			}
			if !strings.Contains(err.Error(), envEvidenceSourceCatalog) {
				t.Errorf("error must name %s, got %v", envEvidenceSourceCatalog, err)
			}
		})
	}
}

func TestLoadEvidenceRejectsAMissingCatalogFile(t *testing.T) {
	t.Setenv(envEvidenceObjectRoot, "/var/lib/evidence")
	t.Setenv(envEvidenceContentKeyRef, "evd-key-1")
	t.Setenv(envEvidenceContentKey, writeEvidenceKeyFile(t, validEvidenceKey()))
	t.Setenv(envEvidenceSourceCatalog, filepath.Join(t.TempDir(), "absent.json"))
	if _, err := LoadEvidence(); err == nil {
		t.Fatal("LoadEvidence accepted a catalog path that does not exist")
	}
}

func TestLoadEvidenceLoadsACompleteSet(t *testing.T) {
	// Surrounding whitespace is what a secret file written by an operator or a
	// mounted secret actually looks like.
	t.Setenv(envEvidenceObjectRoot, "/var/lib/evidence")
	t.Setenv(envEvidenceContentKeyRef, "evd-key-1")
	t.Setenv(envEvidenceContentKey, writeEvidenceKeyFile(t, "  "+validEvidenceKey()+"\n"))
	t.Setenv(envEvidenceSourceCatalog, writeEvidenceCatalogFile(t, validEvidenceCatalog))
	cfg, err := LoadEvidence()
	if err != nil {
		t.Fatalf("LoadEvidence: %v", err)
	}
	if !cfg.Enabled() {
		t.Fatal("a complete set must enable the evidence runtime")
	}
	if cfg.ObjectRoot != "/var/lib/evidence" || cfg.ContentKeyRef != "evd-key-1" {
		t.Fatalf("LoadEvidence = %+v", struct{ Root, Ref string }{cfg.ObjectRoot, cfg.ContentKeyRef})
	}
	if len(cfg.ContentKey) != evidence.ContentKeyBytes {
		t.Fatalf("content key = %d bytes, want %d", len(cfg.ContentKey), evidence.ContentKeyBytes)
	}
	// The loaded material must be usable by the provider the router builds.
	if _, err := evidence.NewConfiguredKeyProvider(cfg.ContentKeyRef, cfg.ContentKey); err != nil {
		t.Fatalf("the loaded key was rejected by NewConfiguredKeyProvider: %v", err)
	}
	// The catalog must arrive PARSED, not as a path the router has to re-read.
	if len(cfg.SourceCatalog.Sources) != 1 {
		t.Fatalf("source catalog = %+v, want exactly one declared source", cfg.SourceCatalog)
	}
	if got := cfg.SourceCatalog.Sources[0].Connector.Capability; got != "erp.purchase_order.read" {
		t.Fatalf("declared connector capability = %q", got)
	}
}
