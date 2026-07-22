package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The connector worker's execution seams (its Action plane, its receipt signer
// and its private Postgres BindingResolver) had no configuration surface at all
// before task B1: every one of them was reported "constructed by nobody" with
// nothing an operator could set to satisfy any of them.
//
// These assertions drive the loader over the REAL environment. What matters is
// not that the variables are read somewhere, it is that setting them (and
// setting only half of them) produces what an operator would expect to see.

func writeSigningKey(t *testing.T) (path string, key ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "receipt-signing-key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

func setExecutionEnv(t *testing.T, keyFile, keyID, dsn string) {
	t.Helper()
	t.Setenv(envWorkerReceiptSigningKeyFile, keyFile)
	t.Setenv(envWorkerReceiptSigningKeyID, keyID)
	t.Setenv("AGENTNEXUS_POSTGRES_DSN", dsn)
	t.Setenv("AGENTNEXUS_DATABASE_URL", "")
}

func TestLoadWorkerExecutionReadsTheConfiguredSurface(t *testing.T) {
	keyFile, key := writeSigningKey(t)
	setExecutionEnv(t, keyFile, "connector-worker-receipt-1", "postgres://localhost:5432/agentnexus")

	executionConfig, err := LoadWorkerExecution()
	if err != nil {
		t.Fatalf("LoadWorkerExecution: %v", err)
	}
	if !executionConfig.Configured() {
		t.Fatal("a fully configured environment did not produce a configured execution surface")
	}
	if executionConfig.ReceiptSigningKeyID != "connector-worker-receipt-1" {
		t.Errorf("key id = %q, want the configured one", executionConfig.ReceiptSigningKeyID)
	}
	if executionConfig.DatabaseURL != "postgres://localhost:5432/agentnexus" {
		t.Errorf("dsn = %q, want the configured one", executionConfig.DatabaseURL)
	}
	// The key must be the material on disk, not merely the right length: a
	// loader that generated its own key would mint receipts nobody can verify
	// against the registered public half.
	if !executionConfig.ReceiptSigningKey.Equal(key) {
		t.Error("the loaded signing key is not the key in the file")
	}
}

// The unconfigured deployment: no error, nothing configured, so the worker stays
// unconstructed and /readyz says which seams are missing. This must NOT become a
// startup failure — a deployment part-way through its wiring has to keep its
// health surface observable.
func TestUnconfiguredWorkerExecutionIsNotAnError(t *testing.T) {
	setExecutionEnv(t, "", "", "postgres://localhost:5432/agentnexus")

	executionConfig, err := LoadWorkerExecution()
	if err != nil {
		t.Fatalf("an unconfigured execution surface must not be a startup error: %v", err)
	}
	if executionConfig.Configured() {
		t.Fatal("an empty environment produced a configured execution surface")
	}
}

// A PARTIAL group is a startup error naming exactly what was missed. The failure
// this prevents: the operator sets the key and the worker boots reporting that
// its seams were "constructed by nobody", which reads as though the variable
// they set does not exist.
func TestPartialWorkerExecutionEnvironmentNamesWhatIsMissing(t *testing.T) {
	keyFile, _ := writeSigningKey(t)
	for _, tc := range []struct {
		name              string
		keyFile, keyID    string
		dsn               string
		wantNamedInReason string
	}{
		{"key file without a key id", keyFile, "", "postgres://localhost:5432/x", envWorkerReceiptSigningKeyID},
		{"key id without a key file", "", "receipt-1", "postgres://localhost:5432/x", envWorkerReceiptSigningKeyFile},
		{"a key with no database", keyFile, "receipt-1", "", "AGENTNEXUS_POSTGRES_DSN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setExecutionEnv(t, tc.keyFile, tc.keyID, tc.dsn)
			_, err := LoadWorkerExecution()
			if err == nil {
				t.Fatal("a partial execution environment must fail startup")
			}
			if !strings.Contains(err.Error(), tc.wantNamedInReason) {
				t.Errorf("the error does not name %s: %v", tc.wantNamedInReason, err)
			}
		})
	}
}

// Broken key material is rejected at STARTUP, not at the first signature. A key
// that cannot sign is a configuration fact; discovering it when the first Action
// completes would strand that Action at result_unknown.
func TestUnusableSigningKeyMaterialIsAStartupError(t *testing.T) {
	dir := t.TempDir()
	shortKey := filepath.Join(dir, "short")
	if err := os.WriteFile(shortKey, []byte(base64.StdEncoding.EncodeToString([]byte("too short"))), 0o600); err != nil {
		t.Fatal(err)
	}
	notBase64 := filepath.Join(dir, "not-base64")
	if err := os.WriteFile(notBase64, []byte("this is not base64 at all !!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path string }{
		{"a key of the wrong length", shortKey},
		{"a file that is not base64", notBase64},
		{"a file that does not exist", filepath.Join(dir, "absent")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setExecutionEnv(t, tc.path, "receipt-1", "postgres://localhost:5432/x")
			if _, err := LoadWorkerExecution(); err == nil {
				t.Fatal("unusable signing key material must fail startup")
			}
		})
	}
}

// Configured() is what the composition root branches on, so a surface missing
// any one part must not report itself usable. Without this a zero DSN would
// reach pgxpool.New and a zero key would reach the signer constructor.
func TestConfiguredRequiresEveryPart(t *testing.T) {
	_, key := writeSigningKey(t)
	complete := WorkerExecutionConfig{DatabaseURL: "postgres://x", ReceiptSigningKeyID: "k", ReceiptSigningKey: key}
	if !complete.Configured() {
		t.Fatal("a complete surface reports itself unconfigured")
	}
	for name, partial := range map[string]WorkerExecutionConfig{
		"no dsn":    {ReceiptSigningKeyID: "k", ReceiptSigningKey: key},
		"no key id": {DatabaseURL: "postgres://x", ReceiptSigningKey: key},
		"no key":    {DatabaseURL: "postgres://x", ReceiptSigningKeyID: "k"},
		"short key": {DatabaseURL: "postgres://x", ReceiptSigningKeyID: "k", ReceiptSigningKey: key[:8]},
	} {
		if partial.Configured() {
			t.Errorf("a surface with %s reports itself configured", name)
		}
	}
}
