package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// Signed self-update errors (fail-closed; a refused update never applies).
var (
	// ErrUpdateUnsigned marks an update package with no signature.
	ErrUpdateUnsigned = errors.New("connector agent update is unsigned")
	// ErrUpdateUntrusted marks an update whose signature does not verify against
	// the EXTERNAL trust anchor. The package's own embedded key is never trusted.
	ErrUpdateUntrusted = errors.New("connector agent update signature does not verify against the external trust anchor")
	// ErrUpdateDigestMismatch marks an update whose declared digest does not match
	// its payload bytes.
	ErrUpdateDigestMismatch = errors.New("connector agent update package digest does not match the payload")
	// ErrUpdateApplyFailed marks an apply that failed and was rolled back to the
	// prior version.
	ErrUpdateApplyFailed = errors.New("connector agent update apply failed; rolled back to the prior version")
	// ErrUpdateInvalid marks a structurally invalid updater configuration.
	ErrUpdateInvalid = errors.New("connector agent updater configuration invalid")
)

// UpdatePackage is a signed self-update. The signature is verified against an
// EXTERNAL trust anchor supplied out of band; EmbeddedKey is the key the package
// claims for itself and is NEVER trusted (the Task 0G lesson: a verifier must not
// trust material carried by the object it is verifying).
type UpdatePackage struct {
	Version     string
	Digest      string // "sha256:" + hex over Payload
	Payload     []byte
	Signature   []byte             // ed25519 over UpdateCanonical(version, digest)
	EmbeddedKey ed25519.PublicKey  // the package's self-asserted key — ignored
}

// UpdateCanonical is the byte string the update signature covers: the version
// and the payload digest, newline-joined. Binding the digest (not the raw
// payload) keeps the signed pre-image bounded while still committing to the
// exact bytes (the digest is verified against the payload before the signature).
func UpdateCanonical(version, digest string) []byte {
	return []byte(version + "\n" + digest)
}

// PayloadDigest is the canonical content digest of an update payload.
func PayloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SignUpdatePackage builds a signed update package. It is the reference signer
// (also used by tests): a real deployment's release pipeline signs with the
// anchor's private half out of band and never ships the private key to the edge.
func SignUpdatePackage(anchorPriv ed25519.PrivateKey, version string, payload []byte) UpdatePackage {
	digest := PayloadDigest(payload)
	sig := ed25519.Sign(anchorPriv, UpdateCanonical(version, digest))
	return UpdatePackage{Version: version, Digest: digest, Payload: payload, Signature: sig}
}

// Updater applies signed self-updates with rollback. The trust anchor is the
// EXTERNAL public key provided at construction; the active version is what the
// agent's health reports.
type Updater struct {
	anchor  ed25519.PublicKey
	apply   func(UpdatePackage) error
	mu      sync.Mutex
	version string
}

// NewUpdater builds an updater bound to an external trust anchor and an initial
// active version. apply performs the actual swap of the running package (a real
// deployment swaps the binary + verifies it comes up); it is injectable so a
// failed apply can be exercised. A missing anchor or apply hook is refused.
func NewUpdater(anchor ed25519.PublicKey, initialVersion string, apply func(UpdatePackage) error) (*Updater, error) {
	if len(anchor) != ed25519.PublicKeySize {
		return nil, errors.Join(ErrUpdateInvalid, errors.New("updater requires an external ed25519 trust anchor"))
	}
	if apply == nil {
		return nil, errors.Join(ErrUpdateInvalid, errors.New("updater requires an apply hook"))
	}
	if initialVersion == "" {
		return nil, errors.Join(ErrUpdateInvalid, errors.New("updater requires an initial version"))
	}
	return &Updater{anchor: anchor, apply: apply, version: initialVersion}, nil
}

// ActiveVersion returns the currently active package version (what health
// reports).
func (u *Updater) ActiveVersion() string {
	if u == nil {
		return ""
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.version
}

// Apply verifies and applies a signed update, rolling back on a failed apply.
// The verification order is fail-closed: an unsigned package, a payload whose
// bytes do not match the declared digest, or a signature that does not verify
// against the EXTERNAL trust anchor are each refused BEFORE any apply. The
// package's own EmbeddedKey is never consulted. A failed apply rolls the active
// version back to the prior version, so health never reports a half-applied
// update.
func (u *Updater) Apply(pkg UpdatePackage) error {
	if len(pkg.Signature) == 0 {
		return ErrUpdateUnsigned
	}
	if pkg.Digest != PayloadDigest(pkg.Payload) {
		return ErrUpdateDigestMismatch
	}
	if !ed25519.Verify(u.anchor, UpdateCanonical(pkg.Version, pkg.Digest), pkg.Signature) {
		return ErrUpdateUntrusted
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	prev := u.version
	if err := u.apply(pkg); err != nil {
		u.version = prev // rollback: the prior version stays active
		return errors.Join(ErrUpdateApplyFailed, err)
	}
	u.version = pkg.Version
	return nil
}
