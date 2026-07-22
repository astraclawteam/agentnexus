package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// WorkerExecutionConfig is the connector worker's Postgres-backed EXECUTION
// surface: the database its private BindingResolver and its Action plane read,
// and the ed25519 key it signs authoritative ActionReceipts with.
//
// It is separate from WorkerIdentityConfig because the two answer different
// questions. The identity says WHO the worker acts as; this says WHAT it can
// reach. A deployment can have either without the other, and the wiring guard
// reports each gap on its own rather than folding them into one refusal.
//
// The signing key is the trigger for the whole group. It is deliberately not
// the DSN: AGENTNEXUS_POSTGRES_DSN is already set for every service in the
// shipped compose profiles, so keying off it would make this worker's execution
// wiring switch on by accident. Supplying a receipt signing key is an explicit
// operator act, and it is the one this group cannot do without — the
// action-transition audit sink refuses to append an UNSIGNED high-risk event,
// so an Action plane composed without a signer would fail every transition it
// attempted.
type WorkerExecutionConfig struct {
	DatabaseURL string
	// ReceiptSigningKeyID / ReceiptSigningKey sign the ActionReceipt the worker
	// produces for a technically-completed execution, and the action-transition
	// audit lineage of that completion. The key MUST be stable across restarts:
	// its public half is registered in the signing-key registry the actions
	// ReceiptVerifier resolves against, and a receipt is durable long after the
	// process that signed it. There is deliberately NO ephemeral escape hatch
	// here (the EvidenceContentKey precedent, not the AllowEphemeralAuditKey
	// one): an ephemeral key would mint receipts that stop verifying at the next
	// restart, which is worse than an unwired signer the guard can name.
	ReceiptSigningKeyID string
	ReceiptSigningKey   ed25519.PrivateKey
}

// Configured reports whether the deployment supplied a complete execution
// surface. An unconfigured one is not an error: the worker stays unconstructed
// and /readyz names the seams, which is the honest state for a deployment that
// has not finished wiring.
func (c WorkerExecutionConfig) Configured() bool {
	return c.DatabaseURL != "" && c.ReceiptSigningKeyID != "" &&
		len(c.ReceiptSigningKey) == ed25519.PrivateKeySize
}

// Worker execution environment variables. The DSN reuses the name every other
// service in this module already reads — the connector bindings, the durable
// Actions and the audit chain live in the one database.
const (
	envWorkerReceiptSigningKeyFile = "AGENTNEXUS_WORKER_RECEIPT_SIGNING_KEY_FILE"
	envWorkerReceiptSigningKeyID   = "AGENTNEXUS_WORKER_RECEIPT_SIGNING_KEY_ID"
)

// LoadWorkerExecution reads the connector worker's execution surface.
//
// Supplying neither key variable returns the zero config with no error: that is
// the deployment which has not wired the worker's execution seams yet, and it
// must keep booting so its health surface stays observable.
//
// Supplying either one commits to the whole group, on the LoadEvidence and
// LoadWorkerIdentity precedent: the other key variable and a database DSN are
// then required, and a missing one is a startup error naming it. The failure
// this rule prevents is specific — a half-supplied group would otherwise fall
// through to the wiring guard, which can only report that the seams were
// constructed by nobody and cannot tell an operator that the variable they DID
// set was ignored.
//
// The key file holds the base64 (std) ed25519 PRIVATE key, the same format
// cmd/audit-export reads, so one operator procedure produces both.
func LoadWorkerExecution() (WorkerExecutionConfig, error) {
	keyFile := strings.TrimSpace(os.Getenv(envWorkerReceiptSigningKeyFile))
	keyID := strings.TrimSpace(os.Getenv(envWorkerReceiptSigningKeyID))
	if keyFile == "" && keyID == "" {
		return WorkerExecutionConfig{}, nil
	}
	dsn := os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_DATABASE_URL")
	}
	var missing []string
	for _, entry := range []struct{ name, value string }{
		{envWorkerReceiptSigningKeyFile, keyFile},
		{envWorkerReceiptSigningKeyID, keyID},
		{"AGENTNEXUS_POSTGRES_DSN", dsn},
	} {
		if entry.value == "" {
			missing = append(missing, entry.name)
		}
	}
	if len(missing) > 0 {
		return WorkerExecutionConfig{}, fmt.Errorf(
			"the connector worker execution seams need %s, %s and a database DSN together; missing: %s",
			envWorkerReceiptSigningKeyFile, envWorkerReceiptSigningKeyID, strings.Join(missing, ", "))
	}
	key, err := loadReceiptSigningKey(keyFile)
	if err != nil {
		return WorkerExecutionConfig{}, fmt.Errorf("load connector worker receipt signing key: %w", err)
	}
	return WorkerExecutionConfig{DatabaseURL: dsn, ReceiptSigningKeyID: keyID, ReceiptSigningKey: key}, nil
}

// loadReceiptSigningKey reads the base64 ed25519 private key. Malformed material
// is rejected here rather than at the first signature: a key that cannot sign is
// a startup fact, and discovering it when the first Action completes would leave
// that Action stranded.
func loadReceiptSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, errors.New("the key file must hold a base64 (std) encoded ed25519 private key")
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the key file decodes to %d bytes, want exactly %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}
