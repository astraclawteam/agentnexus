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

// rejectOutcomeAuthorityName rejects a pack-declared machine name that claims
// business-outcome or graph-provider authority (amendment, plan dc81e80). The
// error wraps ErrOutcomeAuthorityInProductPack so callers can test the
// boundary with errors.Is. Applied to declared machine names only; human
// prose (titles, descriptions, notes) is never scanned.
func rejectOutcomeAuthorityName(field, value string) error {
	if assertsBusinessOutcomeName(value) {
		return fmt.Errorf("%w: %s %q (a connector executes and observes; only the calling Agent's domain runtime decides Outcomes)", ErrOutcomeAuthorityInProductPack, field, value)
	}
	return nil
}

// ValidateProductPack applies the customer-agnostic structural rules shared by
// production and development packs: a frozen schema version, a semantic product
// key, at least one valid semantic capability, every write capability declaring
// side effects, a reconciliation whose verify/compensation capabilities resolve
// to declared capabilities, an idempotency declaration, at least one
// authoritative postcondition probe (whose probing capability resolves to a
// declared READ capability) and execution/observation receipt schemas
// (amendment, plan dc81e80), a required technical-safety floor, a valid field
// policy, a declared compatibility window, declared, non-negative
// network/runtime/limit requirements — and no connector-authored business
// Outcome anywhere in the declared machine names.
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
	// Pre-collect capability names and effects (and reject duplicates) so a
	// write capability's reconciliation and every probe can be resolved
	// against the pack's own declared capabilities.
	names := map[string]bool{}
	effects := map[string]Effect{}
	for _, c := range p.Capabilities {
		if names[c.Name] {
			return fmt.Errorf("duplicate capability %q", c.Name)
		}
		names[c.Name] = true
		effects[c.Name] = c.Effect
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
		// A probe is an observation: its probing capability must resolve to a
		// declared capability with effect read.
		for _, probe := range c.PreconditionProbes {
			if err := resolveProbeCapability(fmt.Sprintf("capability %q precondition_probe %q", c.Name, probe.ProbeID), probe.Capability, names, effects); err != nil {
				return err
			}
		}
		for _, probe := range c.PostconditionProbes {
			if err := resolveProbeCapability(fmt.Sprintf("capability %q postcondition_probe %q", c.Name, probe.ProbeID), probe.Capability, names, effects); err != nil {
				return err
			}
		}
	}
	if err := validateTechnicalSafetyFloor(p.TechnicalSafetyFloor, p.Limits); err != nil {
		return err
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
	for _, egress := range p.Network.Egress {
		if err := rejectOutcomeAuthorityName("network egress class", egress); err != nil {
			return err
		}
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

// resolveProbeCapability requires a probe's probing capability to be one of
// the pack's own declared capabilities with effect read.
func resolveProbeCapability(field, capability string, names map[string]bool, effects map[string]Effect) error {
	if !names[capability] {
		return fieldErrorf(field, "probes %q which is not a declared capability", capability)
	}
	if effects[capability] != EffectRead {
		return fieldErrorf(field, "probes %q which is not a read capability (a probe is an observation, never a write)", capability)
	}
	return nil
}

// validateTechnicalSafetyFloor enforces the required pack-level floor: a valid
// effect ceiling, non-negative bounds, and — because it is the STRICTER floor
// — a write-rate bound that never exceeds the pack's own default envelope
// when both are declared.
func validateTechnicalSafetyFloor(f TechnicalSafetyFloor, limits Limits) error {
	if f.EffectCeiling == "" {
		return fieldErrorf("technical_safety_floor", "effect_ceiling is required (the pack must declare the stricter technical-safety floor applied to third-party or uncertified decision contexts)")
	}
	if !f.EffectCeiling.Valid() {
		return fieldErrorf("technical_safety_floor", "effect_ceiling %q is not read or write", f.EffectCeiling)
	}
	if f.MaxWritesPerMinute < 0 {
		return fieldErrorf("technical_safety_floor", "max_writes_per_minute must not be negative")
	}
	if f.MaxPayloadBytes < 0 {
		return fieldErrorf("technical_safety_floor", "max_payload_bytes must not be negative")
	}
	if f.MaxWritesPerMinute > 0 && limits.MaxRequestsPerMinute > 0 && f.MaxWritesPerMinute > limits.MaxRequestsPerMinute {
		return fieldErrorf("technical_safety_floor", "max_writes_per_minute %d exceeds the pack envelope max_requests_per_minute %d (the floor must be stricter, never looser)", f.MaxWritesPerMinute, limits.MaxRequestsPerMinute)
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
	return rejectOutcomeAuthorityName("product_key", key)
}

// validateFieldPolicy enforces the field-policy shape (every classification
// names a business field and a classification; no field name may claim
// outcome authority). It is applied to both the pack-level field policy and
// each capability's field policy, so the Go and JSON Schema layers agree.
func validateFieldPolicy(field string, fp FieldPolicy) error {
	for _, fc := range fp.Classifications {
		if fc.Field == "" || fc.Classification == "" {
			return fmt.Errorf("%s classification requires field and classification", field)
		}
		if err := rejectOutcomeAuthorityName(field+" classification field", fc.Field); err != nil {
			return err
		}
	}
	return nil
}

func validateCapability(c Capability) error {
	if err := ValidateCapabilityName(c.Name); err != nil {
		return err
	}
	if err := rejectOutcomeAuthorityName("capability", c.Name); err != nil {
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
	if err := validateCapabilityProbes(c); err != nil {
		return err
	}
	if c.Effect.IsWrite() {
		if len(c.SideEffects) == 0 {
			return fmt.Errorf("write capability %q must declare at least one side_effect", c.Name)
		}
		for _, se := range c.SideEffects {
			if se.Kind == "" || se.Description == "" {
				return fmt.Errorf("write capability %q side_effect requires kind and description", c.Name)
			}
			if err := rejectOutcomeAuthorityName(fmt.Sprintf("write capability %q side_effect kind", c.Name), se.Kind); err != nil {
				return err
			}
		}
		if c.Reconciliation == nil {
			return fmt.Errorf("write capability %q must declare a reconciliation", c.Name)
		}
		if c.Reconciliation.Strategy == "" {
			return fmt.Errorf("write capability %q reconciliation strategy is required", c.Name)
		}
		if err := rejectOutcomeAuthorityName(fmt.Sprintf("write capability %q reconciliation strategy", c.Name), c.Reconciliation.Strategy); err != nil {
			return err
		}
		if err := ValidateCapabilityName(c.Reconciliation.VerifyCapability); err != nil {
			return fmt.Errorf("write capability %q reconciliation verify_capability: %w", c.Name, err)
		}
		if c.Reconciliation.CompensationCapability != "" {
			if err := ValidateCapabilityName(c.Reconciliation.CompensationCapability); err != nil {
				return fmt.Errorf("write capability %q reconciliation compensation_capability: %w", c.Name, err)
			}
		}
		if err := validateWriteDeclarations(c); err != nil {
			return err
		}
	} else {
		// The write-only declaration set is meaningless on a read and is
		// rejected, mirroring the postcondition-probe rule: a read observes,
		// it never executes a receipted side effect.
		if c.Idempotency != nil {
			return fmt.Errorf("read capability %q must not declare idempotency (a write-only declaration)", c.Name)
		}
		if c.ExecutionReceiptSchema != nil {
			return fmt.Errorf("read capability %q must not declare an execution_receipt_schema (a write-only declaration)", c.Name)
		}
		if c.ObservationReceiptSchema != nil {
			return fmt.Errorf("read capability %q must not declare an observation_receipt_schema (a write-only declaration)", c.Name)
		}
	}
	return nil
}

// validateProbeID enforces the frozen probe identifier form and the
// outcome-authority name ban on one probe id.
func validateProbeID(field, id string) error {
	if id == "" {
		return fieldErrorf(field, "probe_id is required")
	}
	if !probeIDRe.MatchString(id) {
		return fieldErrorf(field, "probe_id %q is not a lowercase probe identifier (%s)", id, ProbeIDPattern)
	}
	return rejectOutcomeAuthorityName(field+" probe_id", id)
}

// validateCapabilityProbes enforces the probe declaration rules shared by
// reads and writes: probe ids are well-formed and unique within the
// capability (probes are addressed as (capability, probe_id)), probing
// capabilities are semantic names (pack-level validation resolves them to
// declared read capabilities), and postcondition probes carry the full
// observation metadata. Postcondition probes belong to writes only.
func validateCapabilityProbes(c Capability) error {
	seen := map[string]bool{}
	for _, probe := range c.PreconditionProbes {
		field := fmt.Sprintf("capability %q precondition_probe", c.Name)
		if err := validateProbeID(field, probe.ProbeID); err != nil {
			return err
		}
		if seen[probe.ProbeID] {
			return fmt.Errorf("capability %q duplicate probe_id %q (probe ids are unique within a capability)", c.Name, probe.ProbeID)
		}
		seen[probe.ProbeID] = true
		if err := ValidateCapabilityName(probe.Capability); err != nil {
			return fmt.Errorf("%s %q capability: %w", field, probe.ProbeID, err)
		}
	}
	if len(c.PostconditionProbes) > 0 && !c.Effect.IsWrite() {
		return fmt.Errorf("read capability %q must not declare postcondition_probes (a postcondition follows a write)", c.Name)
	}
	for _, probe := range c.PostconditionProbes {
		field := fmt.Sprintf("capability %q postcondition_probe", c.Name)
		if err := validateProbeID(field, probe.ProbeID); err != nil {
			return err
		}
		if seen[probe.ProbeID] {
			return fmt.Errorf("capability %q duplicate probe_id %q (probe ids are unique within a capability)", c.Name, probe.ProbeID)
		}
		seen[probe.ProbeID] = true
		if err := ValidateCapabilityName(probe.Capability); err != nil {
			return fmt.Errorf("%s %q capability: %w", field, probe.ProbeID, err)
		}
		// A postcondition probe without source authority/version/freshness
		// and canonical observation schema is invalid: this is exactly the
		// metadata the platform needs to mint a signed ObservationReceipt.
		if probe.SourceAuthority == "" {
			return fmt.Errorf("%s %q source_authority is required (an observation without a declared source authority tier can never back an ObservationReceipt)", field, probe.ProbeID)
		}
		if !probe.SourceAuthority.Valid() {
			return fmt.Errorf("%s %q source_authority %q is not a frozen tier (system_of_record, authoritative_replica, derived)", field, probe.ProbeID, probe.SourceAuthority)
		}
		if probe.SourceVersionSemantics == "" {
			return fmt.Errorf("%s %q source_version_semantics is required (the platform seals the source content version into the ObservationReceipt)", field, probe.ProbeID)
		}
		if !probe.SourceVersionSemantics.Valid() {
			return fmt.Errorf("%s %q source_version_semantics %q is not frozen (monotonic_counter, content_digest, last_modified_timestamp)", field, probe.ProbeID, probe.SourceVersionSemantics)
		}
		if probe.FreshnessBoundSeconds <= 0 {
			return fmt.Errorf("%s %q freshness_bound_seconds must be positive (an observation proves a bounded time window)", field, probe.ProbeID)
		}
		if err := validateIOSchema("observation", c.Name, probe.ObservationSchema); err != nil {
			return err
		}
	}
	return nil
}

// validateWriteDeclarations enforces the amended per-write declaration set:
// an idempotency declaration, at least one postcondition probe, and
// execution/observation receipt schemas.
func validateWriteDeclarations(c Capability) error {
	if c.Idempotency == nil {
		return fmt.Errorf("write capability %q must declare an idempotency declaration", c.Name)
	}
	if c.Idempotency.KeyScheme == "" {
		return fmt.Errorf("write capability %q idempotency key_scheme is required", c.Name)
	}
	// key_scheme and scope are lowercase machine names (the frozen probe-id
	// form): a camel-cased value like "expectedOutcome" would evade the
	// case-sensitive outcome ban, so the pattern closes that hole and the ban
	// catches the all-lowercase forms.
	if !probeIDRe.MatchString(c.Idempotency.KeyScheme) {
		return fmt.Errorf("write capability %q idempotency key_scheme %q is not a lowercase machine name (%s)", c.Name, c.Idempotency.KeyScheme, ProbeIDPattern)
	}
	if err := rejectOutcomeAuthorityName(fmt.Sprintf("write capability %q idempotency key_scheme", c.Name), c.Idempotency.KeyScheme); err != nil {
		return err
	}
	if c.Idempotency.Scope == "" {
		return fmt.Errorf("write capability %q idempotency scope is required", c.Name)
	}
	if !probeIDRe.MatchString(c.Idempotency.Scope) {
		return fmt.Errorf("write capability %q idempotency scope %q is not a lowercase machine name (%s)", c.Name, c.Idempotency.Scope, ProbeIDPattern)
	}
	if err := rejectOutcomeAuthorityName(fmt.Sprintf("write capability %q idempotency scope", c.Name), c.Idempotency.Scope); err != nil {
		return err
	}
	if !c.Idempotency.OnDuplicate.Valid() {
		return fmt.Errorf("write capability %q idempotency on_duplicate %q is not frozen (return_prior_result, reject, no_op)", c.Name, c.Idempotency.OnDuplicate)
	}
	if len(c.PostconditionProbes) == 0 {
		return fmt.Errorf("write capability %q must declare at least one postcondition_probe (an unobservable write can never produce an ObservationReceipt)", c.Name)
	}
	if c.ExecutionReceiptSchema == nil {
		return fmt.Errorf("write capability %q must declare an execution_receipt_schema", c.Name)
	}
	if err := validateIOSchema("execution_receipt", c.Name, *c.ExecutionReceiptSchema); err != nil {
		return err
	}
	if c.ObservationReceiptSchema == nil {
		return fmt.Errorf("write capability %q must declare an observation_receipt_schema", c.Name)
	}
	if err := validateIOSchema("observation_receipt", c.Name, *c.ObservationReceiptSchema); err != nil {
		return err
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
	if err := rejectOutcomeAuthorityName(fmt.Sprintf("capability %q %s schema ref", capName, kind), io.Ref); err != nil {
		return err
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
