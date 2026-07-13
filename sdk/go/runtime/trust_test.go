package runtime

import (
	"reflect"
	"strings"
	"testing"
)

func TestVersionRangeContains(t *testing.T) {
	r := VersionRange{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"}
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},  // inclusive lower bound
		{"1.4.2", true},  // interior
		{"1.9.9", true},  // just under
		{"2.0.0", false}, // exclusive upper bound
		{"0.9.9", false}, // below
		{"2.5.1", false}, // above
		{"1.0", true},    // zero-padded
		{"not-a-ver", false},
	} {
		if got := r.Contains(tc.version); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
	// Open bounds.
	if !(VersionRange{MinInclusive: "1.0.0"}).Contains("9.9.9") {
		t.Error("open upper bound must contain any later version")
	}
	if (VersionRange{MaxExclusive: "1.0.0"}).Contains("1.0.0") {
		t.Error("open lower bound must still exclude the max bound")
	}
}

func TestVersionRangeValidate(t *testing.T) {
	if err := (VersionRange{}).Validate(); err == nil {
		t.Error("an empty range must be rejected")
	}
	if err := (VersionRange{MinInclusive: "2.0.0", MaxExclusive: "1.0.0"}).Validate(); err == nil {
		t.Error("min after max must be rejected")
	}
	if err := (VersionRange{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"}).Validate(); err != nil {
		t.Errorf("a well-formed range must validate: %v", err)
	}
}

func TestCapabilityCeilingNarrowNeverRaises(t *testing.T) {
	certified := CapabilityCeiling{"knowledge.suggest", "knowledge.create"}
	// Customer removes create and tries to add approve — approve must not appear.
	got := certified.Narrow(CapabilityCeiling{"knowledge.suggest", "knowledge.approve_high_risk"})
	want := CapabilityCeiling{"knowledge.suggest"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Narrow = %v, want %v (customer may narrow but never raise)", got, want)
	}
	// A nil customer ceiling leaves the certified ceiling intact (normalized).
	if got := certified.Narrow(nil); !reflect.DeepEqual(got, CapabilityCeiling{"knowledge.create", "knowledge.suggest"}) {
		t.Fatalf("nil customer ceiling must keep the certified ceiling: %v", got)
	}
}

func TestCertificationBindingValidate(t *testing.T) {
	valid := CertificationBinding{
		Publisher: "AgentAtlas", Product: "atlas-runtime",
		VersionRange:          VersionRange{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"},
		SigningKey:            SigningKey{KeyID: "key_1", Algorithm: "ed25519", PublicKey: "cHVi"},
		ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64),
		TrustClass:            TrustFirstParty,
		CapabilityCeiling:     CapabilityCeiling{"knowledge.create"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a well-formed binding must validate: %v", err)
	}
	untrusted := valid
	untrusted.TrustClass = TrustUntrusted
	if err := untrusted.Validate(); err == nil {
		t.Error("a certification binding cannot be untrusted")
	}
	badDigest := valid
	badDigest.ReleaseManifestDigest = "not-a-digest"
	if err := badDigest.Validate(); err == nil {
		t.Error("an unsigned/malformed release manifest digest must be rejected")
	}
	badCap := valid
	badCap.CapabilityCeiling = CapabilityCeiling{"NotNamespaced"}
	if err := badCap.Validate(); err == nil {
		t.Error("a non-namespaced ceiling capability must be rejected")
	}
}

// TestTrustBindingTypesCarryNoTrustedIdentity walks the new public certification
// types and proves no json tag leaks trusted identity or connector topology,
// mirroring TestContractNoTrustedIdentityFieldsInTypes for the 0C additions.
func TestTrustBindingTypesCarryNoTrustedIdentity(t *testing.T) {
	forbidden := map[string]bool{"enterprise_id": true, "actor_user_id": true, "connector_instance_id": true}
	var walk func(typ reflect.Type, owner string)
	walk = func(typ reflect.Type, owner string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" {
				t.Errorf("%s.%s must declare an explicit json tag", owner, field.Name)
				continue
			}
			if forbidden[tag] || strings.Contains(tag, "enterprise") || strings.HasPrefix(tag, "connector_") {
				t.Errorf("%s.%s json tag %q leaks trusted identity or connector topology", owner, field.Name, tag)
			}
			walk(field.Type, owner+"."+field.Name)
		}
	}
	for _, value := range []any{CertificationBinding{}, VersionRange{}, SigningKey{}} {
		typ := reflect.TypeOf(value)
		walk(typ, typ.Name())
	}
}
