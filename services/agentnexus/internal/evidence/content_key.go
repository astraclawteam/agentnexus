package evidence

import (
	"context"
	"errors"
	"fmt"
)

// ContentKeyBytes is the exact content-encryption key length the staging
// encryptor accepts (AES-256; aesGCM rejects any other length outright).
const ContentKeyBytes = 32

// ConfiguredKeyProvider is the deployment-configured KeyProvider: ONE stable
// operator-supplied content-encryption key, named by a stable reference.
//
// Stability is the hard requirement, not a preference. Read resolves a handle's
// key through the KeyRef persisted at locate time (Service.Read -> KeyByRef), so
// a per-process key would silently make every handle staged before a restart
// undecryptable — the read would fail authenticated decryption and report
// 503, with nothing pointing at key rotation as the cause. The reference must
// therefore outlive the process, exactly like the audit signing key it mirrors
// (PostgresGatewayConfig.AuditSigningKeyID/AuditSigningKey), and rotating the
// key material without rotating the ref is a data-loss operation.
//
// The key is tenant-independent, which is safe here but worth stating: the
// sealed blob is bound to tenant and object key through GCM additional data
// (contentAAD), so a blob moved across tenants or object keys fails
// authenticated decryption regardless of the key being shared. A per-tenant or
// envelope-encrypted KMS scheme fits behind this same port later without a
// contract change.
//
// This is the production shape of the port that StaticKeyProvider deliberately
// is not: material is validated at construction, never at seal time, and the
// provider holds a private copy the caller cannot mutate afterwards.
type ConfiguredKeyProvider struct {
	ref string
	key []byte
}

// NewConfiguredKeyProvider builds the provider. Broken material is rejected at
// construction — a deployment learns at startup, not on the first locate.
func NewConfiguredKeyProvider(ref string, key []byte) (*ConfiguredKeyProvider, error) {
	if !canonical(ref) || hasControlBytes(ref) {
		return nil, errors.New("evidence content key requires a canonical key reference")
	}
	if len(key) != ContentKeyBytes {
		return nil, fmt.Errorf("evidence content key must be exactly %d bytes (AES-256), got %d", ContentKeyBytes, len(key))
	}
	return &ConfiguredKeyProvider{ref: ref, key: append([]byte(nil), key...)}, nil
}

func (p *ConfiguredKeyProvider) material() KeyMaterial {
	return KeyMaterial{Ref: p.ref, Key: append([]byte(nil), p.key...)}
}

// ContentKey returns the deployment's current sealing key.
func (p *ConfiguredKeyProvider) ContentKey(_ context.Context, _ string) (KeyMaterial, error) {
	if p == nil || p.ref == "" || len(p.key) != ContentKeyBytes {
		return KeyMaterial{}, ErrUnavailable
	}
	return p.material(), nil
}

// KeyByRef resolves a persisted key reference. An unknown reference fails
// CLOSED: a handle sealed under a key this deployment no longer holds is
// unreadable, never readable under a substitute key.
func (p *ConfiguredKeyProvider) KeyByRef(_ context.Context, _ string, keyRef string) (KeyMaterial, error) {
	if p == nil || p.ref == "" || len(p.key) != ContentKeyBytes || keyRef != p.ref {
		return KeyMaterial{}, ErrUnavailable
	}
	return p.material(), nil
}
