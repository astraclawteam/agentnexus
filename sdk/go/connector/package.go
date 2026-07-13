package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Schema versions of the frozen v1 Product Pack and Customer Binding forms.
const (
	ProductPackSchemaVersion     = "connector.product/v1"
	CustomerBindingSchemaVersion = "connector.binding/v1"
)

// SignatureAlgorithmEd25519 mirrors the runtime contract's signing algorithm.
const SignatureAlgorithmEd25519 = "ed25519"

// Sentinel errors that separate the two halves of the contract: a resellable,
// customer-agnostic Product Pack and a customer-specific Customer Binding.
var (
	// ErrCustomerDataInProductPack rejects a Product Pack that carries any
	// customer-identifying data — customer name, endpoint, credential, raw
	// table/API path or field mapping. Those live only in a Customer Binding.
	ErrCustomerDataInProductPack = errors.New("product pack must not carry customer-identifying data (customer name, endpoint, credential, raw table/API path or field mapping)")
	// ErrInlineSecretInBinding rejects a Customer Binding that inlines secret
	// material. Bindings reference secrets; they never contain them.
	ErrInlineSecretInBinding = errors.New("customer binding must reference secrets by reference, never inline secret material")
)

// secretRefRe matches an opaque secret reference (a URI-shaped pointer into a
// secret store, e.g. secretref://vault/acme/erp), never a raw secret value.
var secretRefRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://[^\s]+$`)

// Signature is a detached signature block over the Product Pack content digest.
// Its presence and shape are validated here; its cryptographic AUTHENTICITY
// (ed25519.Verify against a trusted key) is verified by the connector
// certification / key-management task, not by this SDK. See ValidateProductionPack.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// ArtifactRef references an out-of-band artifact (SBOM, provenance attestation)
// by id and content digest.
type ArtifactRef struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// NetworkRequirements declares the semantic egress classes and isolation a pack
// needs — never concrete endpoints.
type NetworkRequirements struct {
	Egress    []string `json:"egress"`
	Isolation string   `json:"isolation,omitempty"`
}

// RuntimeRequirements declares the execution runtime a pack needs.
type RuntimeRequirements struct {
	Runtime     string `json:"runtime"`
	MinMemoryMB int    `json:"min_memory_mb,omitempty"`
}

// Limits declares the pack's default resource envelope.
type Limits struct {
	MaxConcurrency       int `json:"max_concurrency,omitempty"`
	MaxRequestsPerMinute int `json:"max_requests_per_minute,omitempty"`
}

// ProductPack is the reusable, resellable, customer-agnostic connector product.
// It declares semantic capabilities, IO schemas, field policy, side-effect and
// reconciliation declarations, network/runtime requirements, compatibility,
// migration, limits and SBOM/provenance/signature references. It never carries
// customer identity, endpoints, credentials, raw table/API paths or field
// mappings — those belong to a CustomerBinding.
type ProductPack struct {
	SchemaVersion string              `json:"schema_version"`
	ProductKey    string              `json:"product_key"`
	Version       string              `json:"version"`
	Title         string              `json:"title,omitempty"`
	Capabilities  []Capability        `json:"capabilities"`
	FieldPolicy   FieldPolicy         `json:"field_policy"`
	Network       NetworkRequirements `json:"network"`
	Runtime       RuntimeRequirements `json:"runtime"`
	Compatibility Compatibility       `json:"compatibility"`
	Migration     MigrationInfo       `json:"migration"`
	Limits        Limits              `json:"limits"`
	SBOM          ArtifactRef         `json:"sbom"`
	Provenance    ArtifactRef         `json:"provenance"`
	Signature     Signature           `json:"signature"`
	Digest        string              `json:"digest"`
	// Development marks an unsigned pack produced by migrating a generic
	// manifest. A development pack can never be imported as a production pack.
	Development bool `json:"development,omitempty"`
}

// CustomerRef identifies the customer a binding belongs to.
type CustomerRef struct {
	Name string `json:"name"`
	Ref  string `json:"ref,omitempty"`
}

// ProductRef pins the exact Product Pack a binding is paired with, by key,
// version and content digest. A product upgrade re-points this reference; it
// never overwrites the binding.
type ProductRef struct {
	ProductKey string `json:"product_key"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
}

// Endpoint is a concrete customer endpoint — legitimate customer topology that
// lives only in the binding.
type Endpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// SecretRef references a customer secret by opaque pointer. It never carries the
// secret value.
type SecretRef struct {
	Name string `json:"name"`
	Ref  string `json:"ref"`
}

// OrgMapping, ResourceMapping and FieldMapping bind semantic pack concepts to
// concrete customer topology. Field mapping is customer-specific and belongs
// only here, never in the Product Pack.
type OrgMapping struct {
	Unit   string `json:"unit"`
	Source string `json:"source"`
}

type ResourceMapping struct {
	Capability string `json:"capability"`
	Resource   string `json:"resource"`
}

type FieldMapping struct {
	Field  string `json:"field"`
	Source string `json:"source"`
}

// CustomerBinding is the customer-specific half: endpoints, secret references,
// org/resource/field mappings and customer extensions, pinned to one exact
// Product Pack. A product upgrade cannot overwrite it.
type CustomerBinding struct {
	SchemaVersion    string                     `json:"schema_version"`
	BindingKey       string                     `json:"binding_key"`
	Customer         CustomerRef                `json:"customer"`
	Product          ProductRef                 `json:"product"`
	Endpoints        []Endpoint                 `json:"endpoints"`
	Secrets          []SecretRef                `json:"secrets"`
	OrgMappings      []OrgMapping               `json:"org_mappings,omitempty"`
	ResourceMappings []ResourceMapping          `json:"resource_mappings,omitempty"`
	FieldMappings    []FieldMapping             `json:"field_mappings,omitempty"`
	Extensions       map[string]json.RawMessage `json:"extensions,omitempty"`
}

// PackContentDigest returns the canonical sha256 digest over the pack content,
// excluding the Signature and Digest fields themselves. The Signature signs
// this digest; ValidateProductionPack rebinds it.
func PackContentDigest(p ProductPack) string {
	c := p
	c.Signature = Signature{}
	c.Digest = ""
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ParseProductPack decodes and structurally validates Product Pack JSON. It
// rejects any customer-identifying data (ErrCustomerDataInProductPack) and any
// unknown field, then applies the customer-agnostic structural rules. It does
// NOT require a signature: callers choose production or development validation.
func ParseProductPack(data []byte) (ProductPack, error) {
	if err := scanForbiddenPackKeys(data); err != nil {
		return ProductPack{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var pack ProductPack
	if err := dec.Decode(&pack); err != nil {
		return ProductPack{}, fmt.Errorf("decode product pack: %w", err)
	}
	if err := ValidateProductPack(pack); err != nil {
		return ProductPack{}, err
	}
	return pack, nil
}

// ImportProductionPack decodes Product Pack JSON and enforces the full
// production contract: a well-formed signature block, a matching content
// digest, and SBOM/provenance references. A development pack (or any
// unsigned/digestless form) is rejected. This is the only path by which a pack
// becomes production-importable.
//
// This verifies STRUCTURE + content-digest binding only; it does NOT verify
// signature authenticity against a trusted key. See ValidateProductionPack for
// the full scope note — cryptographic verification is deferred to the connector
// certification / key-management task.
func ImportProductionPack(data []byte) (ProductPack, error) {
	pack, err := ParseProductPack(data)
	if err != nil {
		return ProductPack{}, err
	}
	if err := ValidateProductionPack(pack); err != nil {
		return ProductPack{}, err
	}
	return pack, nil
}

// ParseBinding decodes and validates Customer Binding JSON. It rejects any
// inlined secret material (ErrInlineSecretInBinding) and any unknown field.
func ParseBinding(data []byte) (CustomerBinding, error) {
	if err := scanForbiddenSecretKeys(data); err != nil {
		return CustomerBinding{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var binding CustomerBinding
	if err := dec.Decode(&binding); err != nil {
		return CustomerBinding{}, fmt.Errorf("decode customer binding: %w", err)
	}
	if err := ValidateBinding(binding); err != nil {
		return CustomerBinding{}, err
	}
	return binding, nil
}

// UpgradePackReference adopts newPack in a binding by re-pointing only the
// product reference. Every customer-owned field is preserved verbatim: a
// product upgrade touches the pack, never the binding.
func UpgradePackReference(binding CustomerBinding, newPack ProductPack) CustomerBinding {
	binding.Product = ProductRef{
		ProductKey: newPack.ProductKey,
		Version:    newPack.Version,
		Digest:     newPack.Digest,
	}
	return binding
}

// DevelopmentPackFromManifest migrates a generic connector Manifest into an
// unsigned, development-only Product Pack. Raw method/path topology from the
// manifest is dropped; each operation becomes a semantic capability. The result
// is flagged Development and unsigned, so it can never be imported as a
// production pack — production import strictly requires the signed product form.
func DevelopmentPackFromManifest(m Manifest) ProductPack {
	var caps []Capability
	seen := map[string]bool{}
	for _, r := range m.Resources {
		write := !r.IsReadOnly()
		readName := sanitizeCapabilityName(r.Type, r.Name, "read")
		for _, op := range r.Operations {
			name := sanitizeCapabilityName(r.Type, r.Name, op.Name)
			if seen[name] {
				continue
			}
			seen[name] = true
			c := Capability{
				Name:   name,
				Title:  strings.TrimSpace(op.Name + " " + r.Name),
				Effect: EffectRead,
				Input:  IOSchema{Ref: name + ".input", Digest: syntheticDigest(name + ":input")},
				Output: IOSchema{Ref: name + ".output", Digest: syntheticDigest(name + ":output")},
			}
			if write {
				c.Effect = EffectWrite
				c.SideEffects = []SideEffect{{Kind: "external_write", Description: "migrated write capability (development only)", Reversible: false}}
				c.Reconciliation = &Reconciliation{Strategy: "manual_review", VerifyCapability: readName}
			}
			caps = append(caps, c)
		}
		// A migrated write reconciles by re-reading the resource; declare that
		// read capability so the reconciliation reference resolves.
		if write && !seen[readName] {
			seen[readName] = true
			caps = append(caps, Capability{
				Name:   readName,
				Title:  "read " + r.Name,
				Effect: EffectRead,
				Input:  IOSchema{Ref: readName + ".input", Digest: syntheticDigest(readName + ":input")},
				Output: IOSchema{Ref: readName + ".output", Digest: syntheticDigest(readName + ":output")},
			})
		}
	}
	if len(caps) == 0 {
		name := "connector.resource.read"
		caps = []Capability{{
			Name:   name,
			Title:  "read resource",
			Effect: EffectRead,
			Input:  IOSchema{Ref: name + ".input", Digest: syntheticDigest(name + ":input")},
			Output: IOSchema{Ref: name + ".output", Digest: syntheticDigest(name + ":output")},
		}}
	}
	p := ProductPack{
		SchemaVersion: ProductPackSchemaVersion,
		ProductKey:    "connector." + sanitizeSegment(m.Name),
		Version:       defaultString(m.Version, "0.0.0"),
		Title:         m.Name + " (development migration)",
		Capabilities:  caps,
		FieldPolicy:   FieldPolicy{},
		Network:       NetworkRequirements{Egress: []string{"connector.api"}, Isolation: "outbound_only"},
		Runtime:       RuntimeRequirements{Runtime: "development"},
		Compatibility: Compatibility{RuntimeContract: VersionRange{Min: "1.0.0"}, ConnectorRuntime: VersionRange{Min: "0.0.0"}},
		Migration:     MigrationInfo{FromVersions: []string{defaultString(m.Version, "0.0.0")}, Notes: "migrated from generic connector manifest (development only)"},
		Limits:        Limits{},
		Development:   true,
	}
	p.Digest = PackContentDigest(p)
	return p
}

func syntheticDigest(seed string) string {
	sum := sha256.Sum256([]byte("agentnexus:dev-migration:v1:" + seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// scanExtensionsForInlineSecret rejects inline secret material smuggled into a
// binding's free-form customer extensions. It mirrors ParseBinding's byte scan
// so ValidateBinding enforces the same rule on a struct that never went through
// ParseBinding (for example one built in code by a bulk import tool).
func scanExtensionsForInlineSecret(ext map[string]json.RawMessage) error {
	for key, raw := range ext {
		if isForbiddenSecretKey(key) {
			return fmt.Errorf("%w: extensions field %q", ErrInlineSecretInBinding, key)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}
		if err := walkForbiddenKeys(value, isForbiddenSecretKey, ErrInlineSecretInBinding); err != nil {
			return err
		}
	}
	return nil
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// sanitizeSegment lowercases and reduces a manifest identifier to a single valid
// capability segment ([a-z][a-z0-9_]*).
func sanitizeSegment(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	seg := strings.Trim(b.String(), "_")
	if seg == "" {
		return "x"
	}
	if seg[0] >= '0' && seg[0] <= '9' {
		seg = "c" + seg
	}
	return seg
}

func sanitizeCapabilityName(parts ...string) string {
	segs := make([]string, 0, len(parts))
	for _, p := range parts {
		segs = append(segs, sanitizeSegment(p))
	}
	return strings.Join(segs, ".")
}

// --- recursive key scans (mirror the runtime request decoder pattern) ---

var forbiddenPackKeyExact = map[string]bool{
	"customer": true, "customer_name": true, "customer_id": true, "tenant_name": true,
	"endpoint": true, "endpoints": true, "base_url": true, "url": true, "uri": true,
	"host": true, "hostname": true, "port": true,
	"credential": true, "credentials": true, "password": true, "token": true,
	"api_key": true, "apikey": true, "access_key": true, "secret_key": true, "client_secret": true,
	"secret": true, "secrets": true, "secret_ref": true,
	"dsn": true, "connection_string": true, "conn_string": true, "jdbc_url": true,
	"table": true, "table_name": true, "schema_name": true, "collection": true,
	"api_path": true, "path": true, "route": true, "resource_path": true,
	"field_mapping": true, "field_mappings": true, "mapping": true, "mappings": true,
	"org_mapping": true, "org_mappings": true, "resource_mapping": true, "resource_mappings": true,
	"binding": true, "bindings": true, "extensions": true,
}

var forbiddenPackKeySubstrings = []string{"endpoint", "credential", "base_url", "connection_string", "field_mapping", "api_path"}

func isForbiddenPackKey(key string) bool {
	if forbiddenPackKeyExact[key] {
		return true
	}
	for _, sub := range forbiddenPackKeySubstrings {
		if strings.Contains(key, sub) {
			return true
		}
	}
	return false
}

func scanForbiddenPackKeys(data []byte) error {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse product pack JSON: %w", err)
	}
	return walkForbiddenKeys(doc, isForbiddenPackKey, ErrCustomerDataInProductPack)
}

var forbiddenSecretKeyExact = map[string]bool{
	"value": true, "secret": true, "secret_value": true, "password": true, "passwd": true,
	"token": true, "access_token": true, "refresh_token": true, "api_key": true, "apikey": true,
	"private_key": true, "privatekey": true, "credential": true, "credentials": true,
	"access_key": true, "secret_key": true, "client_secret": true, "bearer": true, "passphrase": true,
}

func isForbiddenSecretKey(key string) bool { return forbiddenSecretKeyExact[key] }

func scanForbiddenSecretKeys(data []byte) error {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse customer binding JSON: %w", err)
	}
	return walkForbiddenKeys(doc, isForbiddenSecretKey, ErrInlineSecretInBinding)
}

func walkForbiddenKeys(value any, forbidden func(string) bool, sentinel error) error {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if forbidden(key) {
				return fmt.Errorf("%w: field %q", sentinel, key)
			}
			if err := walkForbiddenKeys(child, forbidden, sentinel); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := walkForbiddenKeys(child, forbidden, sentinel); err != nil {
				return err
			}
		}
	}
	return nil
}
