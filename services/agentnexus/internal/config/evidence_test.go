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

func TestLoadEvidenceIsDisabledWhenNothingIsSet(t *testing.T) {
	t.Setenv(envEvidenceObjectRoot, "")
	t.Setenv(envEvidenceContentKeyRef, "")
	t.Setenv(envEvidenceContentKey, "")
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
	for _, tc := range []struct{ name, root, ref, keyPath string }{
		{"root only", "/var/lib/evidence", "", ""},
		{"root and ref, no key", "/var/lib/evidence", "evd-key-1", ""},
		{"key without root", "", "evd-key-1", "somewhere"},
		{"root and key, no ref", "/var/lib/evidence", "", "somewhere"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envEvidenceObjectRoot, tc.root)
			t.Setenv(envEvidenceContentKeyRef, tc.ref)
			t.Setenv(envEvidenceContentKey, tc.keyPath)
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
			if _, err := LoadEvidence(); err == nil {
				t.Fatal("LoadEvidence accepted unusable key material")
			}
		})
	}
}

func TestLoadEvidenceLoadsACompleteSet(t *testing.T) {
	// Surrounding whitespace is what a secret file written by an operator or a
	// mounted secret actually looks like.
	t.Setenv(envEvidenceObjectRoot, "/var/lib/evidence")
	t.Setenv(envEvidenceContentKeyRef, "evd-key-1")
	t.Setenv(envEvidenceContentKey, writeEvidenceKeyFile(t, "  "+validEvidenceKey()+"\n"))
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
}
