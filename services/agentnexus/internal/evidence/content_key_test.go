package evidence

import (
	"bytes"
	"context"
	"testing"
)

func testContentKey() []byte {
	key := make([]byte, ContentKeyBytes)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestNewConfiguredKeyProviderRejectsUnusableMaterial(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  string
		key  []byte
	}{
		{"empty ref", "", testContentKey()},
		{"untrimmed ref", " evd-key-1 ", testContentKey()},
		{"control byte in ref", "evd\nkey", testContentKey()},
		{"short key", "evd-key-1", make([]byte, 16)},
		{"long key", "evd-key-1", make([]byte, 64)},
		{"no key", "evd-key-1", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Construction is where broken material must be caught: a key that
			// only fails at seal time turns a deployment mistake into an opaque
			// 503 on the first locate.
			if _, err := NewConfiguredKeyProvider(tc.ref, tc.key); err == nil {
				t.Fatal("NewConfiguredKeyProvider accepted unusable material")
			}
		})
	}
}

func TestConfiguredKeyProviderRoundTripsThroughTheStagingEncryptor(t *testing.T) {
	provider, err := NewConfiguredKeyProvider("evd-key-1", testContentKey())
	if err != nil {
		t.Fatalf("NewConfiguredKeyProvider: %v", err)
	}
	ctx := context.Background()
	current, err := provider.ContentKey(ctx, "ent-1")
	if err != nil {
		t.Fatalf("ContentKey: %v", err)
	}
	// The key must be usable by the real staging encryptor, not merely the right
	// length: aesGCM is what actually rejects a wrong-sized AES key.
	sealed, err := seal(current.Key, []byte(`[{"id":"1"}]`), contentAAD("ent-1", "obj1"))
	if err != nil {
		t.Fatalf("seal with the configured key: %v", err)
	}

	// The read path resolves the key by the ref persisted on the handle. This is
	// the property the whole type exists for: same ref, same key, later.
	resolved, err := provider.KeyByRef(ctx, "ent-1", current.Ref)
	if err != nil {
		t.Fatalf("KeyByRef(%q): %v", current.Ref, err)
	}
	plaintext, err := open(resolved.Key, sealed, contentAAD("ent-1", "obj1"))
	if err != nil {
		t.Fatalf("open with the ref-resolved key: %v", err)
	}
	if string(plaintext) != `[{"id":"1"}]` {
		t.Fatalf("round trip returned %q", plaintext)
	}
}

func TestConfiguredKeyProviderFailsClosedOnAnUnknownRef(t *testing.T) {
	provider, err := NewConfiguredKeyProvider("evd-key-1", testContentKey())
	if err != nil {
		t.Fatalf("NewConfiguredKeyProvider: %v", err)
	}
	// A handle sealed under a key this deployment no longer holds must be
	// unreadable, never readable under a substitute key.
	if _, err := provider.KeyByRef(context.Background(), "ent-1", "evd-key-0"); err == nil {
		t.Fatal("KeyByRef resolved an unknown reference")
	}
}

func TestConfiguredKeyProviderDoesNotAliasCallerMaterial(t *testing.T) {
	key := testContentKey()
	provider, err := NewConfiguredKeyProvider("evd-key-1", key)
	if err != nil {
		t.Fatalf("NewConfiguredKeyProvider: %v", err)
	}
	// Mutating the caller's slice, or a slice handed back by the provider, must
	// not change what the provider seals with.
	key[0] ^= 0xff
	handed, err := provider.ContentKey(context.Background(), "ent-1")
	if err != nil {
		t.Fatalf("ContentKey: %v", err)
	}
	handed.Key[1] ^= 0xff
	again, err := provider.ContentKey(context.Background(), "ent-1")
	if err != nil {
		t.Fatalf("ContentKey: %v", err)
	}
	if !bytes.Equal(again.Key, testContentKey()) {
		t.Fatal("the provider's key material changed under external mutation")
	}
}
