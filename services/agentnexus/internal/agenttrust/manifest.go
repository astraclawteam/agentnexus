package agenttrust

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// ErrManifestSignatureRejected marks a build-manifest signature that does not
// verify against the certified signing key. It is a rejected certification
// request, never a registry outage.
var ErrManifestSignatureRejected = errors.New("build manifest signature rejected")

// VerifyBuildManifestSignature verifies the detached signature over a certified
// release's manifest digest.
//
// This is the check Certification.SignedBuildManifest attests. The registry
// stores that field as an attested FACT (so an enterprise registry can attest it
// through its own path), which means the attestation is only worth what the
// caller did before setting it — this function is that work, and it lives in the
// domain package rather than in an HTTP handler so it cannot be forgotten by the
// next surface that certifies.
//
// The signed message is the release-manifest digest STRING ("sha256:<64 hex>"),
// not the 32 raw digest bytes. The digest is what the contract binds
// (release_manifest_digest is a Sha256Ref) and signing its canonical textual
// form keeps the preimage unambiguous for a publisher that never handles the
// raw bytes.
//
// The signature's key_id must equal the certified signing key's key_id: a
// signature by some OTHER key the publisher also controls proves nothing about
// the key this certification binds, and rotating the key is a new signing
// identity that requires recertification.
func VerifyBuildManifestSignature(key runtime.SigningKey, releaseManifestDigest string, signature runtime.Signature) error {
	if err := key.Validate(); err != nil {
		return errors.Join(ErrManifestSignatureRejected, err)
	}
	if err := signature.Validate(); err != nil {
		return errors.Join(ErrManifestSignatureRejected, err)
	}
	if err := runtime.ValidateSHA256Ref(releaseManifestDigest); err != nil {
		return errors.Join(ErrManifestSignatureRejected, err)
	}
	if signature.KeyID != key.KeyID {
		return errors.Join(ErrManifestSignatureRejected, errors.New("signature key_id does not match the certified signing key"))
	}
	if signature.Algorithm != runtime.SignatureAlgorithmEd25519 || key.Algorithm != runtime.SignatureAlgorithmEd25519 {
		return errors.Join(ErrManifestSignatureRejected, errors.New("only ed25519 is a frozen v1 signature algorithm"))
	}
	publicKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.Join(ErrManifestSignatureRejected, errors.New("signing key is not a base64 ed25519 public key"))
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return errors.Join(ErrManifestSignatureRejected, errors.New("signature is not a base64 ed25519 signature"))
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(releaseManifestDigest), signatureBytes) {
		return errors.Join(ErrManifestSignatureRejected, errors.New("signature does not verify against the certified signing key"))
	}
	return nil
}
