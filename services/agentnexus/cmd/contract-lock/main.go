// Command contract-lock generates and verifies the digest lock of the frozen
// vendor-neutral public contract artifacts (ELC-NEXUS-1 candidate).
//
//	go run ./cmd/contract-lock -update   # regenerate api/contract.lock
//	go run ./cmd/contract-lock -verify   # fail (exit 1) on any drift
//
// Digests are sha256 over LF-normalized bytes, so they are identical on LF
// and autocrlf (CRLF) checkouts and equal `git show :<path> | sha256sum` for
// LF-committed text. The tool is pure Go on purpose: the drift gate must run
// on machines without protoc/buf.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const lockPath = "api/contract.lock"

// frozenArtifacts is the closed set of public contract files pinned by the
// lock. Adding or removing a public contract artifact is a contract change
// and must update this list, the lock and the protocol changelog together.
var frozenArtifacts = []string{
	"api/CHANGELOG.yaml",
	"api/openapi/gateway-agent.yaml",
	"api/openapi/gateway-runtime.yaml",
	"api/proto/agentnexus/actions/v1/actions.proto",
	"api/proto/agentnexus/audit/v1/audit.proto",
	"api/proto/agentnexus/evidence/v1/evidence.proto",
	"api/proto/agentnexus/trust/v1/trust.proto",
}

type lockFile struct {
	Protocol      string     `yaml:"protocol"`
	Normalization string     `yaml:"normalization"`
	GeneratedBy   string     `yaml:"generated_by"`
	Files         []lockItem `yaml:"files"`
}

type lockItem struct {
	Path   string `yaml:"path"`
	SHA256 string `yaml:"sha256"`
}

func digestLFNormalized(path string) (string, error) {
	raw, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		return "", err
	}
	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	sum := sha256.Sum256(normalized)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func currentLock() (*lockFile, error) {
	lock := &lockFile{
		Protocol:      "agentnexus-public-contract",
		Normalization: "lf",
		GeneratedBy:   "go run ./cmd/contract-lock -update",
	}
	for _, path := range frozenArtifacts {
		digest, err := digestLFNormalized(path)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", path, err)
		}
		lock.Files = append(lock.Files, lockItem{Path: path, SHA256: digest})
	}
	return lock, nil
}

func update() error {
	lock, err := currentLock()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# Digest lock of the frozen vendor-neutral public contract artifacts.\n")
	buf.WriteString("# Regenerate with: go run ./cmd/contract-lock -update\n")
	buf.WriteString("# Verify with:     go run ./cmd/contract-lock -verify\n")
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(lock); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	return os.WriteFile(filepath.FromSlash(lockPath), buf.Bytes(), 0o644)
}

func verify() error {
	raw, err := os.ReadFile(filepath.FromSlash(lockPath))
	if err != nil {
		return fmt.Errorf("read %s (run `go run ./cmd/contract-lock -update` once after a deliberate contract change): %w", lockPath, err)
	}
	var recorded lockFile
	if err := yaml.Unmarshal(raw, &recorded); err != nil {
		return fmt.Errorf("parse %s: %w", lockPath, err)
	}
	current, err := currentLock()
	if err != nil {
		return err
	}
	recordedByPath := map[string]string{}
	for _, item := range recorded.Files {
		recordedByPath[item.Path] = item.SHA256
	}
	var drift []string
	for _, item := range current.Files {
		want, pinned := recordedByPath[item.Path]
		switch {
		case !pinned:
			drift = append(drift, fmt.Sprintf("%s is a frozen artifact but is not pinned in %s", item.Path, lockPath))
		case want != item.SHA256:
			drift = append(drift, fmt.Sprintf("%s drifted: lock pins %s but file hashes to %s", item.Path, want, item.SHA256))
		}
		delete(recordedByPath, item.Path)
	}
	for path := range recordedByPath {
		drift = append(drift, fmt.Sprintf("%s is pinned in %s but is not a frozen artifact", path, lockPath))
	}
	if len(drift) > 0 {
		return fmt.Errorf("public contract drift detected:\n  %s", strings.Join(drift, "\n  "))
	}
	fmt.Printf("contract lock verified: %d artifacts match %s\n", len(current.Files), lockPath)
	return nil
}

func main() {
	updateFlag := flag.Bool("update", false, "regenerate "+lockPath)
	verifyFlag := flag.Bool("verify", false, "verify the frozen artifacts against "+lockPath)
	flag.Parse()
	var err error
	switch {
	case *updateFlag:
		err = update()
	case *verifyFlag:
		err = verify()
	default:
		err = fmt.Errorf("one of -update or -verify is required")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "contract-lock:", err)
		os.Exit(1)
	}
}
