// Command audit-export is the operator surface for the GA Task 0G signed audit
// chain: it PRODUCES the offline WORM/SIEM verification bundle for a tenant from
// the database, PERSISTS a signed batch-root checkpoint (the truncation anchor),
// and CHECKS for truncation of the live chain below the most recent checkpoint.
// Without a defined checkpoint+export surface, truncation of an exported chain
// would be undetectable; this command is where checkpoints are produced.
//
//	audit-export --dsn "$DSN" --tenant ent_1 \
//	  --key-file /etc/agentnexus/audit-key.b64 --key-id audit-1 \
//	  --checkpoint --out /var/lib/agentnexus/audit-ent_1.json
//
// The signing key file holds the base64 (std) ed25519 PRIVATE key (64 bytes) the
// runtime signs with; the same key's public half must be pinned as the offline
// verifier's trust anchor. A signing operation never uses an ephemeral key.
//
// Exit codes: 0 ok, 1 truncation detected or operation failure, 2 usage/I/O.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("audit-export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsn := flags.String("dsn", "", "PostgreSQL DSN")
	tenant := flags.String("tenant", "", "tenant (enterprise) id")
	keyFile := flags.String("key-file", "", "file holding the base64 ed25519 private signing key")
	keyID := flags.String("key-id", "", "signing key id (must match the registered public key)")
	out := flags.String("out", "", "write the verification bundle JSON to this path")
	checkpoint := flags.Bool("checkpoint", false, "persist a signed batch-root checkpoint")
	checkTruncation := flags.Bool("check-truncation", false, "fail if the chain is truncated below the latest checkpoint")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *dsn == "" || *tenant == "" || *keyFile == "" || *keyID == "" {
		fmt.Fprintln(stderr, "audit-export: --dsn, --tenant, --key-file and --key-id are required")
		return 2
	}
	signer, err := loadSigner(*keyFile, *keyID)
	if err != nil {
		fmt.Fprintf(stderr, "audit-export: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(stderr, "audit-export: connect: %v\n", err)
		return 2
	}
	defer pool.Close()
	// Register the signer's public half so verifiers resolve it, then wire it.
	if _, err := db.New(pool).UpsertAuditSigningKey(ctx, db.UpsertAuditSigningKeyParams{
		KeyID: signer.KeyID(), Algorithm: audit.SignatureAlgorithmEd25519, PublicKey: signer.PublicKey(),
	}); err != nil {
		fmt.Fprintf(stderr, "audit-export: register key: %v\n", err)
		return 1
	}
	sink := app.NewPostgresBrowserAuditSink(pool, app.WithAuditSigner(signer))

	if *checkTruncation {
		if err := sink.DetectActionAuditTruncation(ctx, *tenant); err != nil {
			fmt.Fprintf(stderr, "audit-export: %v\n", err)
			return 1
		}
	}
	if *checkpoint {
		lastSeq, err := sink.PersistActionAuditCheckpoint(ctx, *tenant)
		if err != nil {
			fmt.Fprintf(stderr, "audit-export: checkpoint: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "checkpoint persisted: tenant=%s last_seq=%d\n", *tenant, lastSeq)
	}
	if *out != "" {
		pkg, err := sink.ExportActionAuditPackage(ctx, *tenant)
		if err != nil {
			fmt.Fprintf(stderr, "audit-export: export: %v\n", err)
			return 1
		}
		raw, err := audit.MarshalPackage(pkg)
		if err != nil {
			fmt.Fprintf(stderr, "audit-export: marshal: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*out, raw, 0o600); err != nil {
			fmt.Fprintf(stderr, "audit-export: write: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "bundle written: tenant=%s events=%d out=%s\n", *tenant, len(pkg.Events), *out)
	}
	return 0
}

func loadSigner(keyFile, keyID string) (*audit.Ed25519AuditSigner, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(trimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("key file is not base64: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("key file must hold a base64 ed25519 private key (64 bytes)")
	}
	return audit.NewEd25519AuditSigner(keyID, ed25519.PrivateKey(decoded))
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}
