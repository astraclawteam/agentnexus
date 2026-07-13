package connector

import "fmt"

func ValidateManifest(manifest Manifest) error {
	if manifest.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if manifest.Name == "" {
		return fmt.Errorf("name is required")
	}
	if manifest.Version == "" {
		return fmt.Errorf("version is required")
	}
	if len(manifest.Resources) == 0 {
		return fmt.Errorf("at least one resource is required")
	}

	resourceNames := map[string]struct{}{}
	for _, resource := range manifest.Resources {
		if resource.Name == "" {
			return fmt.Errorf("resource name is required")
		}
		if _, ok := resourceNames[resource.Name]; ok {
			return fmt.Errorf("duplicate resource %q", resource.Name)
		}
		resourceNames[resource.Name] = struct{}{}
		if resource.Type == "" {
			return fmt.Errorf("resource %q type is required", resource.Name)
		}
		fieldNames := map[string]struct{}{}
		for _, field := range resource.Fields {
			if field.Name == "" {
				return fmt.Errorf("resource %q field name is required", resource.Name)
			}
			if _, ok := fieldNames[field.Name]; ok {
				return fmt.Errorf("resource %q duplicate field %q", resource.Name, field.Name)
			}
			fieldNames[field.Name] = struct{}{}
		}
	}
	return nil
}

func JSONSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"schema_version", "name", "version", "resources"},
		"properties": map[string]any{
			"schema_version": map[string]any{"type": "string"},
			"name":           map[string]any{"type": "string"},
			"version":        map[string]any{"type": "string"},
			"resources":      map[string]any{"type": "array"},
			"credentials":    map[string]any{"type": "array"},
		},
	}
}

// --- Connector Product Pack v1 validation (customer-agnostic, resellable) ---

func fieldErrorf(field, format string, args ...any) error {
	return fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...))
}

// ValidateProductPack applies the customer-agnostic structural rules shared by
// production and development packs: a frozen schema version, a semantic product
// key, at least one valid semantic capability, every write capability declaring
// side effects and a reconciliation whose verify/compensation capabilities
// resolve to declared capabilities, a valid field policy, a declared
// compatibility window and declared, non-negative network/runtime/limit
// requirements.
func ValidateProductPack(p ProductPack) error {
	if p.SchemaVersion != ProductPackSchemaVersion {
		return fmt.Errorf("schema_version must be %q", ProductPackSchemaVersion)
	}
	if err := validateProductKey(p.ProductKey); err != nil {
		return err
	}
	if p.Version == "" {
		return fmt.Errorf("version is required")
	}
	if len(p.Capabilities) == 0 {
		return fmt.Errorf("at least one capability is required")
	}
	// Pre-collect capability names (and reject duplicates) so a write
	// capability's reconciliation can be resolved against the pack's own
	// declared capabilities.
	names := map[string]bool{}
	for _, c := range p.Capabilities {
		if names[c.Name] {
			return fmt.Errorf("duplicate capability %q", c.Name)
		}
		names[c.Name] = true
	}
	for _, c := range p.Capabilities {
		if err := validateCapability(c); err != nil {
			return err
		}
		if c.Effect.IsWrite() {
			if !names[c.Reconciliation.VerifyCapability] {
				return fmt.Errorf("write capability %q reconciliation verify_capability %q is not a declared capability", c.Name, c.Reconciliation.VerifyCapability)
			}
			if cc := c.Reconciliation.CompensationCapability; cc != "" && !names[cc] {
				return fmt.Errorf("write capability %q reconciliation compensation_capability %q is not a declared capability", c.Name, cc)
			}
		}
	}
	if err := validateFieldPolicy("field_policy", p.FieldPolicy); err != nil {
		return err
	}
	if err := validateCompatibility(p.Compatibility); err != nil {
		return err
	}
	if len(p.Network.Egress) == 0 {
		return fmt.Errorf("network egress requirements are required")
	}
	if p.Runtime.Runtime == "" {
		return fmt.Errorf("runtime requirements are required")
	}
	if p.Runtime.MinMemoryMB < 0 {
		return fmt.Errorf("runtime min_memory_mb must not be negative")
	}
	if p.Limits.MaxConcurrency < 0 {
		return fmt.Errorf("limits max_concurrency must not be negative")
	}
	if p.Limits.MaxRequestsPerMinute < 0 {
		return fmt.Errorf("limits max_requests_per_minute must not be negative")
	}
	return nil
}

// ValidateProductionPack enforces the full production contract on top of the
// structural rules: the pack must not be a development pack, must carry a
// well-formed signature block, must carry a content digest that matches the
// pack's canonical content, and must reference an SBOM and provenance. An
// unsigned, digestless or development pack is rejected.
//
// SCOPE: this verifies STRUCTURE and content-digest binding only. It does NOT
// verify signature AUTHENTICITY: the ed25519 signature is not checked against a
// trusted signing key here, and the content digest is a plain unkeyed SHA-256,
// so a caller that tampers a capability, recomputes the digest and attaches any
// well-formed signature block would still pass this function. Cryptographic
// signature verification (ed25519.Verify against a trusted, revocation-aware key
// registry) is deferred to the connector certification / key-management task
// (see the GA plan, Task 8/19/20). Treat a pass here as "structurally a signed
// product form", not "authenticated".
func ValidateProductionPack(p ProductPack) error {
	if p.Development {
		return fmt.Errorf("a development pack cannot be imported as a production product pack (development=true)")
	}
	if err := ValidateProductPack(p); err != nil {
		return err
	}
	if err := validateSignature(p.Signature); err != nil {
		return err
	}
	if err := validateDigest("product pack digest", p.Digest); err != nil {
		return err
	}
	if want := PackContentDigest(p); p.Digest != want {
		return fmt.Errorf("product pack digest %q does not match content digest %q", p.Digest, want)
	}
	if err := validateArtifactRef("sbom", p.SBOM); err != nil {
		return err
	}
	if err := validateArtifactRef("provenance", p.Provenance); err != nil {
		return err
	}
	return nil
}

// ValidateDevelopmentPack accepts an unsigned pack that is explicitly flagged
// as development-only. It still enforces every structural rule, but not the
// signature/digest/SBOM/provenance requirements of production.
func ValidateDevelopmentPack(p ProductPack) error {
	if !p.Development {
		return fmt.Errorf("development pack must set development=true")
	}
	return ValidateProductPack(p)
}

// ValidateBinding validates a Customer Binding: it pins one exact Product Pack,
// declares customer endpoints, references (never inlines) secrets and maps
// semantic pack concepts onto concrete customer topology.
func ValidateBinding(b CustomerBinding) error {
	if b.SchemaVersion != CustomerBindingSchemaVersion {
		return fmt.Errorf("schema_version must be %q", CustomerBindingSchemaVersion)
	}
	if b.BindingKey == "" {
		return fmt.Errorf("binding_key is required")
	}
	if b.Customer.Name == "" {
		return fmt.Errorf("customer name is required")
	}
	if b.Product.ProductKey == "" {
		return fmt.Errorf("product reference product_key is required")
	}
	if b.Product.Version == "" {
		return fmt.Errorf("product reference version is required")
	}
	if err := validateDigest("product reference digest", b.Product.Digest); err != nil {
		return err
	}
	if len(b.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint is required")
	}
	for _, e := range b.Endpoints {
		if e.Name == "" || e.URL == "" {
			return fmt.Errorf("endpoint name and url are required")
		}
	}
	for _, s := range b.Secrets {
		if s.Name == "" {
			return fmt.Errorf("secret name is required")
		}
		if s.Ref == "" {
			return fmt.Errorf("secret %q must carry a ref, never an inline secret", s.Name)
		}
		if !secretRefRe.MatchString(s.Ref) {
			return fmt.Errorf("secret %q ref %q is not an opaque secret reference (for example secretref://...)", s.Name, s.Ref)
		}
	}
	for _, rm := range b.ResourceMappings {
		if err := ValidateCapabilityName(rm.Capability); err != nil {
			return err
		}
		if rm.Resource == "" {
			return fmt.Errorf("resource mapping for %q requires a resource", rm.Capability)
		}
	}
	for _, fm := range b.FieldMappings {
		if fm.Field == "" || fm.Source == "" {
			return fmt.Errorf("field mapping requires field and source")
		}
	}
	for _, om := range b.OrgMappings {
		if om.Unit == "" || om.Source == "" {
			return fmt.Errorf("org mapping requires unit and source")
		}
	}
	// Inline secrets are rejected at validate time too, not only in ParseBinding's
	// byte scan: customer extensions are free-form, so they are the most likely
	// place a raw secret would be smuggled in.
	if err := scanExtensionsForInlineSecret(b.Extensions); err != nil {
		return err
	}
	return nil
}

func validateProductKey(key string) error {
	if key == "" {
		return fmt.Errorf("product_key is required")
	}
	if !capabilityRe.MatchString(key) {
		return fmt.Errorf("product_key %q is not a namespaced customer-agnostic identifier (for example sap.s4hana.procurement)", key)
	}
	return nil
}

// validateFieldPolicy enforces the field-policy shape (every classification
// names a business field and a classification). It is applied to both the
// pack-level field policy and each capability's field policy, so the Go and
// JSON Schema layers agree.
func validateFieldPolicy(field string, fp FieldPolicy) error {
	for _, fc := range fp.Classifications {
		if fc.Field == "" || fc.Classification == "" {
			return fmt.Errorf("%s classification requires field and classification", field)
		}
	}
	return nil
}

func validateCapability(c Capability) error {
	if err := ValidateCapabilityName(c.Name); err != nil {
		return err
	}
	if c.Title == "" {
		return fmt.Errorf("capability %q title is required", c.Name)
	}
	if !c.Effect.Valid() {
		return fmt.Errorf("capability %q effect %q is not read or write", c.Name, c.Effect)
	}
	if err := validateIOSchema("input", c.Name, c.Input); err != nil {
		return err
	}
	if err := validateIOSchema("output", c.Name, c.Output); err != nil {
		return err
	}
	if c.FieldPolicy != nil {
		if err := validateFieldPolicy(fmt.Sprintf("capability %q field_policy", c.Name), *c.FieldPolicy); err != nil {
			return err
		}
	}
	if c.Effect.IsWrite() {
		if len(c.SideEffects) == 0 {
			return fmt.Errorf("write capability %q must declare at least one side_effect", c.Name)
		}
		for _, se := range c.SideEffects {
			if se.Kind == "" || se.Description == "" {
				return fmt.Errorf("write capability %q side_effect requires kind and description", c.Name)
			}
		}
		if c.Reconciliation == nil {
			return fmt.Errorf("write capability %q must declare a reconciliation", c.Name)
		}
		if c.Reconciliation.Strategy == "" {
			return fmt.Errorf("write capability %q reconciliation strategy is required", c.Name)
		}
		if err := ValidateCapabilityName(c.Reconciliation.VerifyCapability); err != nil {
			return fmt.Errorf("write capability %q reconciliation verify_capability: %w", c.Name, err)
		}
		if c.Reconciliation.CompensationCapability != "" {
			if err := ValidateCapabilityName(c.Reconciliation.CompensationCapability); err != nil {
				return fmt.Errorf("write capability %q reconciliation compensation_capability: %w", c.Name, err)
			}
		}
	}
	return nil
}

func validateIOSchema(kind, capName string, io IOSchema) error {
	if io.Ref == "" {
		return fmt.Errorf("capability %q %s schema ref is required", capName, kind)
	}
	if !schemaRefRe.MatchString(io.Ref) {
		return fmt.Errorf("capability %q %s schema ref %q is not a semantic schema reference (raw paths and connection strings are forbidden)", capName, kind, io.Ref)
	}
	return validateDigest(fmt.Sprintf("capability %q %s schema digest", capName, kind), io.Digest)
}

// validateSignature checks the STRUCTURE of the signature block only: a
// supported algorithm and non-empty key id and value. It does not perform
// cryptographic verification (ed25519.Verify against a trusted key) — see the
// ValidateProductionPack godoc for why authenticity is deferred.
func validateSignature(s Signature) error {
	if s.Algorithm == "" && s.KeyID == "" && s.Value == "" {
		return fmt.Errorf("product pack signature is required (the pack is unsigned)")
	}
	if s.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("signature algorithm %q is not supported", s.Algorithm)
	}
	if s.KeyID == "" {
		return fmt.Errorf("signature key_id is required")
	}
	if s.Value == "" {
		return fmt.Errorf("signature value is required")
	}
	return nil
}

func validateArtifactRef(kind string, a ArtifactRef) error {
	if a.Ref == "" && a.Digest == "" {
		return fmt.Errorf("%s reference is required", kind)
	}
	if a.Ref == "" {
		return fmt.Errorf("%s ref is required", kind)
	}
	return validateDigest(fmt.Sprintf("%s digest", kind), a.Digest)
}

func validateDigest(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !sha256RefRe.MatchString(value) {
		return fmt.Errorf("%s %q is not a sha256:<64 hex> digest", field, value)
	}
	return nil
}
