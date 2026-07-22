package agenttrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

const manifestTestDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func manifestFixture(t *testing.T) (runtime.SigningKey, runtime.Signature) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key := runtime.SigningKey{KeyID: "release-key-1", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(public)}
	signature := runtime.Signature{
		Algorithm: runtime.SignatureAlgorithmEd25519,
		KeyID:     key.KeyID,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(manifestTestDigest))),
	}
	return key, signature
}

func TestVerifyBuildManifestSignatureAcceptsASignatureOverTheDigest(t *testing.T) {
	key, signature := manifestFixture(t)
	if err := VerifyBuildManifestSignature(key, manifestTestDigest, signature); err != nil {
		t.Fatalf("a valid manifest signature was rejected: %v", err)
	}
}

func TestVerifyBuildManifestSignatureRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*runtime.SigningKey, *string, *runtime.Signature)
	}{
		{"a different digest", func(_ *runtime.SigningKey, digest *string, _ *runtime.Signature) {
			*digest = "sha256:" + "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
		}},
		{"a key id the certification does not bind", func(_ *runtime.SigningKey, _ *string, s *runtime.Signature) {
			s.KeyID = "some-other-key"
		}},
		{"an unsigned request", func(_ *runtime.SigningKey, _ *string, s *runtime.Signature) {
			*s = runtime.Signature{}
		}},
		{"a non-base64 signature", func(_ *runtime.SigningKey, _ *string, s *runtime.Signature) {
			s.Value = "not base64!!"
		}},
		{"a signature of the wrong length", func(_ *runtime.SigningKey, _ *string, s *runtime.Signature) {
			s.Value = base64.StdEncoding.EncodeToString([]byte("short"))
		}},
		{"a public key of the wrong length", func(k *runtime.SigningKey, _ *string, _ *runtime.Signature) {
			k.PublicKey = base64.StdEncoding.EncodeToString([]byte("short"))
		}},
		{"an algorithm outside the frozen v1 set", func(k *runtime.SigningKey, _ *string, s *runtime.Signature) {
			k.Algorithm = "rsa"
			s.Algorithm = "rsa"
		}},
		{"a digest that is not a canonical sha256 reference", func(_ *runtime.SigningKey, digest *string, _ *runtime.Signature) {
			*digest = "not-a-digest"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, signature := manifestFixture(t)
			digest := manifestTestDigest
			tc.mutate(&key, &digest, &signature)
			err := VerifyBuildManifestSignature(key, digest, signature)
			if !errors.Is(err, ErrManifestSignatureRejected) {
				t.Fatalf("err = %v; want ErrManifestSignatureRejected", err)
			}
		})
	}
}
