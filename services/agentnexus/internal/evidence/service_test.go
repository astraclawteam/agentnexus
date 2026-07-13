package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// Fixture vocabulary. The canaries are the load-bearing part of this suite:
// contentCanary is sensitive business content that may appear ONLY inside an
// allowed read's data envelope, and the connector canaries are internal
// source topology that may never leave the private plane at all.
const (
	testTenant  = "ten_evidence"
	testActor   = "user-1"
	otherActor  = "user-2"
	testPurpose = "payroll-review"

	contentCanary       = "CANARY-SENSITIVE-PAYROLL-CONTENT-9f2d41"
	connectorCanary     = "connector-instance-CLASSIFIED-XJ88"
	connectorPathCanary = "/api/v2/hr/employees"

	connectorClass = "hr.employee_directory"
	openClass      = "kb.articles"
)

// recordingAuditSink records authorization-lineage appends and can be forced
// to fail so the fail-closed lineage requirement is provable.
type recordingAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   error
	n      int
}

func (r *recordingAuditSink) AppendEvidenceAudit(_ context.Context, event AuditEvent) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return "", r.fail
	}
	r.n++
	r.events = append(r.events, event)
	return fmt.Sprintf("audit_%016d", r.n), nil
}

func (r *recordingAuditSink) Events() []AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AuditEvent(nil), r.events...)
}

type evidenceFixture struct {
	svc       *Service
	store     *MemoryStore
	objects   *MemoryObjectStore
	source    *MemoryContentSource
	snapshots *policy.MemorySnapshotSource
	audit     *recordingAuditSink
	logs      *bytes.Buffer
	now       *time.Time
}

func testKeyProvider() StaticKeyProvider {
	// Clearly-labelled TEST key material; never a production key.
	return StaticKeyProvider{Material: KeyMaterial{Ref: "test-key-unit", Key: bytes.Repeat([]byte{0x42}, 32)}}
}

func deterministicIDs() func(string) string {
	counter := 0
	return func(prefix string) string {
		counter++
		return fmt.Sprintf("%s%016d", prefix, counter)
	}
}

func newFixture(t *testing.T, opts ...Option) *evidenceFixture {
	t.Helper()
	now := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	f := &evidenceFixture{
		store:     NewMemoryStore(),
		objects:   NewMemoryObjectStore(),
		source:    NewMemoryContentSource(),
		snapshots: policy.NewMemorySnapshotSource(),
		audit:     &recordingAuditSink{},
		logs:      &bytes.Buffer{},
		now:       &now,
	}
	f.snapshots.StoreSnapshot(testTenant, testActor, policy.SealedAccessSnapshot{
		TenantRef:   testTenant,
		OrgVersion:  7,
		OrgUnits:    []policy.SealedOrgUnit{{ID: "root"}},
		Memberships: []policy.SealedMembership{{OrgUnitID: "root", Role: "suggest"}},
	})
	base := []Option{
		WithClock(func() time.Time { return *f.now }),
		WithIDGenerator(deterministicIDs()),
		WithLogger(slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	}
	f.svc = NewService(f.store, f.objects, testKeyProvider(), f.source,
		policy.NewCapabilityEvaluator(f.snapshots), f.audit, append(base, opts...)...)
	return f
}

// seedConnectorBinding registers the connector-backed data class: its private
// source reference is deliberately connector-shaped and must never leak.
func (f *evidenceFixture) seedConnectorBinding(t *testing.T, cachedReadAllowed bool, records []Record) SourceBinding {
	t.Helper()
	binding, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef:         testTenant,
		DataClass:         connectorClass,
		SourceRef:         connectorCanary + connectorPathCanary,
		SourceVersion:     3,
		AccessCapability:  "knowledge.suggest",
		SourceCapability:  "connector.hr.read",
		ResourceType:      "knowledge",
		ResourceID:        "hr-directory",
		CachedReadAllowed: cachedReadAllowed,
	})
	if err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	if records == nil {
		records = []Record{
			{"employee": "Zhang Wei", "note": contentCanary, "email": "zw@example.com"},
			{"employee": "Li Na", "note": "standard", "email": "ln@example.com"},
		}
	}
	f.source.Seed(binding.SourceRef, records)
	return binding
}

func (f *evidenceFixture) seedOpenBinding(t *testing.T, records []Record) SourceBinding {
	t.Helper()
	binding, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef:         testTenant,
		DataClass:         openClass,
		SourceRef:         "internal-kb-store",
		SourceVersion:     1,
		AccessCapability:  "knowledge.suggest",
		SourceCapability:  "",
		ResourceType:      "knowledge",
		ResourceID:        "kb-space",
		CachedReadAllowed: true,
	})
	if err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	if records == nil {
		records = []Record{{"title": "How to file an expense", "body": "public"}}
	}
	f.source.Seed(binding.SourceRef, records)
	return binding
}

func (f *evidenceFixture) principal(actor string) runtime.PrincipalContext {
	now := *f.now
	return runtime.PrincipalContext{
		TenantRef:       testTenant,
		PrincipalRef:    actor,
		AgentClientRef:  "console",
		AgentReleaseRef: "unregistered",
		TrustClass:      runtime.TrustFirstParty,
		OrgSnapshotRef:  "orgv_7",
		VerifiedAt:      now,
		ExpiresAt:       now.Add(time.Hour),
	}
}

func fullAuthz() Authorization {
	return Authorization{OrgVersion: 7, ConnectorCapabilityAllowed: true}
}

func astraClawAuthz() Authorization {
	return Authorization{OrgVersion: 7, ConnectorCapabilityAllowed: false}
}

func (f *evidenceFixture) locateRequest(dataClass, purpose string, maxResults int64) runtime.EvidenceRequest {
	need := runtime.DataNeed{NeedID: "need-" + dataClass, DataClass: dataClass, Purpose: purpose}
	if maxResults > 0 {
		need.Constraints = &runtime.Constraints{MaxResults: maxResults}
	}
	return runtime.EvidenceRequest{
		RequestID: "req-loc-" + dataClass,
		TraceID:   "trace-loc-" + dataClass,
		DataNeeds: []runtime.DataNeed{need},
		Purpose:   purpose,
		ExpiresAt: f.now.Add(2 * time.Hour),
	}
}

func (f *evidenceFixture) readRequest(businessContextRef, evidenceRef, purpose string, maxResults int64) runtime.EvidenceReadRequest {
	req := runtime.EvidenceReadRequest{
		RequestID:          "req-read-" + evidenceRef,
		TraceID:            "trace-read-" + evidenceRef,
		BusinessContextRef: businessContextRef,
		EvidenceRef:        evidenceRef,
		Purpose:            purpose,
		ExpiresAt:          f.now.Add(2 * time.Hour),
	}
	if maxResults > 0 {
		req.Constraints = &runtime.Constraints{MaxResults: maxResults}
	}
	return req
}

// locateOne is the happy-path locate helper returning the single issued handle.
func (f *evidenceFixture) locateOne(t *testing.T, dataClass, purpose string) (LocateResult, runtime.EvidenceHandle) {
	t.Helper()
	result, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest(dataClass, purpose, 0))
	if err != nil {
		t.Fatalf("Locate(%s): %v", dataClass, err)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("Locate(%s) evidence = %d, want 1", dataClass, len(result.Evidence))
	}
	return result, result.Evidence[0]
}

// --- Semantic resolution without connector topology -------------------------

func TestEvidenceLocateResolvesSemanticNeedWithoutConnectorTopology(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)

	result, handle := f.locateOne(t, connectorClass, testPurpose)

	if err := handle.Validate(); err != nil {
		t.Fatalf("issued handle is not a valid public EvidenceHandle: %v", err)
	}
	if err := runtime.ValidateHandle(handle.EvidenceRef, runtime.HandleEvidence); err != nil {
		t.Fatalf("evidence_ref is not an opaque evd_ handle: %v", err)
	}
	if err := runtime.ValidateHandle(result.BusinessContextRef, runtime.HandleWorkCase); err != nil {
		t.Fatalf("business_context_ref is not an opaque wc_ handle: %v", err)
	}
	if handle.DataClass != connectorClass {
		t.Fatalf("handle data class = %q, want %q", handle.DataClass, connectorClass)
	}
	if !handle.ExpiresAt.After(*f.now) {
		t.Fatalf("handle carries no TTL: %v", handle.ExpiresAt)
	}

	// The public result must carry zero connector topology and zero content.
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{connectorCanary, connectorPathCanary, contentCanary} {
		if strings.Contains(string(payload), banned) {
			t.Fatalf("locate result leaks %q: %s", banned, payload)
		}
	}

	// The full server-side binding exists privately: tenant, actor, agent
	// release, org version, source version, purpose, content hash and lineage.
	stored, err := f.store.GetHandle(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil {
		t.Fatalf("stored handle: %v", err)
	}
	if stored.PrincipalRef != testActor || stored.AgentClientRef != "console" || stored.AgentReleaseRef != "unregistered" {
		t.Fatalf("handle actor/release binding = %+v", stored)
	}
	if stored.OrgVersion != 7 || stored.SourceVersion != 3 || stored.Purpose != testPurpose {
		t.Fatalf("handle org/source/purpose binding = %+v", stored)
	}
	if len(stored.ContentHash) != 64 {
		t.Fatalf("handle content hash = %q, want sha256 hex", stored.ContentHash)
	}
	if stored.AuthorizationRef == "" || len(stored.Lineage) == 0 {
		t.Fatalf("handle carries no authorization lineage: %+v", stored)
	}
}

func TestEvidenceLocateDeniesConnectorBackedEvidenceForAstraClawOrigins(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	f.seedOpenBinding(t, nil)

	// The AstraClaw boundary: no connector capability => connector-backed data
	// classes are denied outright.
	_, err := f.svc.Locate(context.Background(), f.principal(testActor), astraClawAuthz(), f.locateRequest(connectorClass, testPurpose, 0))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("connector-backed locate without connector capability = %v, want ErrDenied", err)
	}
	if err != nil && (strings.Contains(err.Error(), connectorCanary) || strings.Contains(err.Error(), connectorPathCanary)) {
		t.Fatalf("denial leaks connector topology: %v", err)
	}

	// The gate is source-plane specific: the same caller still reaches a
	// non-connector data class.
	result, err := f.svc.Locate(context.Background(), f.principal(testActor), astraClawAuthz(), f.locateRequest(openClass, testPurpose, 0))
	if err != nil || len(result.Evidence) != 1 {
		t.Fatalf("non-connector locate for AstraClaw origin = (%+v, %v), want one handle", result, err)
	}
}

func TestEvidenceLocateFailsClosedWithoutPolicyGrant(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)

	// Sealed org version drift: the caller context pins a version the policy
	// snapshot no longer matches; the evaluator denies and locate fails closed.
	_, err := f.svc.Locate(context.Background(), f.principal(testActor), Authorization{OrgVersion: 6, ConnectorCapabilityAllowed: true}, f.locateRequest(connectorClass, testPurpose, 0))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("locate with drifted sealed org version = %v, want ErrDenied", err)
	}

	// A capability the membership does not grant is denied.
	if _, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef: testTenant, DataClass: "finance.ledger", SourceRef: "ledger-src", SourceVersion: 1,
		AccessCapability: "workflow.edit_advanced", ResourceType: "workflow", ResourceID: "ledger-flow",
		CachedReadAllowed: true,
	}); err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	f.source.Seed("ledger-src", []Record{{"row": 1}})
	_, err = f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest("finance.ledger", testPurpose, 0))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("locate without granting membership = %v, want ErrDenied", err)
	}

	// An unknown data class is indistinguishable from a denial (no existence
	// oracle on the private registry).
	_, err = f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest("does.not_exist", testPurpose, 0))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("locate for unknown data class = %v, want ErrDenied", err)
	}
}

func TestEvidenceRequestValidationFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)

	// A request whose expiry is already in the past is invalid.
	expired := f.locateRequest(connectorClass, testPurpose, 0)
	expired.ExpiresAt = f.now.Add(-time.Minute)
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), expired); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expired locate request = %v, want ErrInvalidRequest", err)
	}

	// A purpose named in prohibited_uses is rejected at locate time.
	prohibited := f.locateRequest(connectorClass, testPurpose, 0)
	prohibited.DataNeeds[0].Constraints = &runtime.Constraints{ProhibitedUses: []string{testPurpose}}
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), prohibited); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("prohibited-purpose locate = %v, want ErrInvalidRequest", err)
	}

	// Nil-service guard fails closed as unavailable.
	var nilService *Service
	if _, err := nilService.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest(connectorClass, testPurpose, 0)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil service locate = %v, want ErrUnavailable", err)
	}
}

// --- Read binding: tenant, actor, purpose, context, release -----------------

func TestSemanticReadReturnsNormalizedEnvelopeWithCacheHonesty(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if read.Decision != DecisionAllow {
		t.Fatalf("read decision = %q, want allow", read.Decision)
	}
	records, ok := read.Data["records"].([]Record)
	if !ok || len(records) != 2 {
		t.Fatalf("read data envelope = %#v, want 2 normalized records", read.Data)
	}
	if records[0]["note"] != contentCanary {
		t.Fatalf("allowed read must return the business content, got %#v", records[0])
	}

	// Cache honesty: a cached response ALWAYS states source version and as-of
	// time and never masquerades as real-time data.
	if read.SourceVersion != 3 {
		t.Fatalf("read source version = %d, want 3", read.SourceVersion)
	}
	if !read.ServedFromCache {
		t.Fatal("read must state served_from_cache explicitly")
	}
	if !read.AsOf.Equal(*f.now) {
		t.Fatalf("read as-of = %v, want staging time %v", read.AsOf, *f.now)
	}
	if read.ContinuationRef != "" {
		t.Fatalf("unbounded read must not paginate, got continuation %q", read.ContinuationRef)
	}

	// The normalized envelope never carries connector topology.
	payload, err := json.Marshal(read)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{connectorCanary, connectorPathCanary} {
		if strings.Contains(string(payload), banned) {
			t.Fatalf("read envelope leaks connector topology %q: %s", banned, payload)
		}
	}
}

func TestSemanticReadEnforcesTenantActorPurposeAndContextBinding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Give the second actor an identical policy grant so the binding checks,
	// not the policy evaluator, are what deny the cross-actor read.
	f.snapshots.StoreSnapshot(testTenant, otherActor, policy.SealedAccessSnapshot{
		TenantRef: testTenant, OrgVersion: 7,
		OrgUnits:    []policy.SealedOrgUnit{{ID: "root"}},
		Memberships: []policy.SealedMembership{{OrgUnitID: "root", Role: "suggest"}},
	})
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	denies := []struct {
		name      string
		principal runtime.PrincipalContext
		request   runtime.EvidenceReadRequest
	}{
		{name: "cross-actor", principal: f.principal(otherActor), request: f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0)},
		{name: "cross-purpose", principal: f.principal(testActor), request: f.readRequest(result.BusinessContextRef, handle.EvidenceRef, "marketing-export", 0)},
		{name: "cross-context", principal: f.principal(testActor), request: f.readRequest("wc_0000000000000099", handle.EvidenceRef, testPurpose, 0)},
		{name: "unknown-handle", principal: f.principal(testActor), request: f.readRequest(result.BusinessContextRef, "evd_0000000000000099", testPurpose, 0)},
	}
	for _, test := range denies {
		read, err := f.svc.Read(context.Background(), test.principal, fullAuthz(), test.request)
		if err != nil {
			t.Fatalf("%s: read error = %v, want typed deny decision", test.name, err)
		}
		if read.Decision != DecisionDeny || read.Data != nil || read.ContinuationRef != "" {
			t.Fatalf("%s: read = %+v, want bare deny", test.name, read)
		}
	}

	// Cross-tenant: the same handle does not exist under another tenant.
	foreign := f.principal(testActor)
	foreign.TenantRef = "ten_other"
	read, err := f.svc.Read(context.Background(), foreign, fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("cross-tenant read = (%+v, %v), want bare deny", read, err)
	}

	// Cross-release: the handle binds the located Agent release.
	otherRelease := f.principal(testActor)
	otherRelease.AgentReleaseRef = "release-2"
	read, err = f.svc.Read(context.Background(), otherRelease, fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("cross-release read = (%+v, %v), want bare deny", read, err)
	}

	// The original binding still reads.
	read, err = f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionAllow {
		t.Fatalf("bound read after denials = (%+v, %v), want allow", read, err)
	}
}

func TestSemanticReadFailsClosedOnExpiredHandle(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	*f.now = f.now.Add(3 * time.Hour) // beyond the 2h requested handle TTL
	request := f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0)
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), request)
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("expired-handle read = (%+v, %v), want bare deny", read, err)
	}
}

func TestSemanticReadFailsClosedAfterSourceDeletion(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	if err := f.svc.DeleteSource(context.Background(), testTenant, connectorClass); err != nil {
		t.Fatalf("DeleteSource: %v", err)
	}
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("read after source deletion = (%+v, %v), want bare deny", read, err)
	}
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest(connectorClass, testPurpose, 0)); !errors.Is(err, ErrDenied) {
		t.Fatalf("locate on deleted source = %v, want ErrDenied", err)
	}
}

func TestEvidenceRevocationPropagatesToIssuedHandles(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	if err := f.svc.RevokeAuthorization(context.Background(), testTenant, handle.EvidenceRef, "acl revoked by admin"); err != nil {
		t.Fatalf("RevokeAuthorization: %v", err)
	}
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("read after revocation = (%+v, %v), want bare deny", read, err)
	}
	events, err := f.store.ListHandleEvents(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil || len(events) == 0 || events[len(events)-1].Kind != HandleEventRevoked {
		t.Fatalf("revocation must persist as a handle event: (%+v, %v)", events, err)
	}
	if err := f.svc.RevokeAuthorization(context.Background(), testTenant, "evd_0000000000000099", "unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking an unknown handle = %v, want ErrNotFound", err)
	}
}

func TestEvidenceReadReEvaluatesPolicyAfterMembershipRevocation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	// The sealed snapshot advances and the granting membership disappears:
	// an already-issued handle must fail closed at read time.
	f.snapshots.StoreSnapshot(testTenant, testActor, policy.SealedAccessSnapshot{
		TenantRef: testTenant, OrgVersion: 8,
		OrgUnits:    []policy.SealedOrgUnit{{ID: "root"}},
		Memberships: nil,
	})
	read, err := f.svc.Read(context.Background(), f.principal(testActor), Authorization{OrgVersion: 8, ConnectorCapabilityAllowed: true}, f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("read after membership revocation = (%+v, %v), want bare deny", read, err)
	}
}

func TestEvidenceInvalidateSourceVersionFailsStaleReadsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	binding, err := f.svc.InvalidateSourceVersion(context.Background(), testTenant, connectorClass)
	if err != nil {
		t.Fatalf("InvalidateSourceVersion: %v", err)
	}
	if binding.SourceVersion != 4 {
		t.Fatalf("source version after invalidation = %d, want 4", binding.SourceVersion)
	}

	// The stale handle NEVER serves outdated content silently.
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("stale-source read = (%+v, %v), want bare deny", read, err)
	}

	// A fresh locate binds the new source version and reads honestly again.
	freshResult, freshHandle := f.locateOne(t, connectorClass, testPurpose)
	fresh, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(freshResult.BusinessContextRef, freshHandle.EvidenceRef, testPurpose, 0))
	if err != nil || fresh.Decision != DecisionAllow || fresh.SourceVersion != 4 || !fresh.ServedFromCache {
		t.Fatalf("fresh read = (%+v, %v), want allow at source version 4", fresh, err)
	}
}

func TestEvidenceReadRequiresExplicitCachedReadPermission(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Deny direction: the data class has NO explicit cached-read grant.
	f.seedConnectorBinding(t, false, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("cached read without explicit permission = (%+v, %v), want bare deny", read, err)
	}

	// Allow direction: the explicit grant enables the cached read.
	f.seedOpenBinding(t, nil)
	openResult, openHandle := f.locateOne(t, openClass, testPurpose)
	allowed, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(openResult.BusinessContextRef, openHandle.EvidenceRef, testPurpose, 0))
	if err != nil || allowed.Decision != DecisionAllow || !allowed.ServedFromCache {
		t.Fatalf("explicitly-permitted cached read = (%+v, %v), want allow", allowed, err)
	}
}

// --- Pagination --------------------------------------------------------------

func TestEvidencePaginationReturnsExplicitContinuationNeverTruncates(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	records := []Record{
		{"seq": "r1"}, {"seq": "r2"}, {"seq": "r3"}, {"seq": "r4"}, {"seq": "r5"},
	}
	f.seedConnectorBinding(t, true, records)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	var got []Record
	ref := handle.EvidenceRef
	pages := 0
	for ref != "" {
		pages++
		if pages > 4 {
			t.Fatal("pagination did not terminate")
		}
		read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, ref, testPurpose, 2))
		if err != nil || read.Decision != DecisionAllow {
			t.Fatalf("page %d read = (%+v, %v), want allow", pages, read, err)
		}
		pageRecords, ok := read.Data["records"].([]Record)
		if !ok {
			t.Fatalf("page %d data = %#v", pages, read.Data)
		}
		if read.SourceVersion != 3 || !read.ServedFromCache {
			t.Fatalf("page %d must keep stating cache provenance: %+v", pages, read)
		}
		if read.ContinuationRef != "" {
			if len(pageRecords) != 2 {
				t.Fatalf("bounded page %d returned %d records, want exactly 2", pages, len(pageRecords))
			}
			if err := runtime.ValidateHandle(read.ContinuationRef, runtime.HandleEvidence); err != nil {
				t.Fatalf("continuation marker is not an opaque evd_ handle: %v", err)
			}
			if read.ContinuationRef == ref {
				t.Fatal("continuation must be a fresh handle")
			}
		}
		got = append(got, pageRecords...)
		ref = read.ContinuationRef
	}
	if pages != 3 || len(got) != 5 {
		t.Fatalf("walk = %d pages / %d records, want 3 pages / all 5 records (never silent truncation)", pages, len(got))
	}
	for i, record := range got {
		if record["seq"] != fmt.Sprintf("r%d", i+1) {
			t.Fatalf("record %d = %#v, out of order", i, record)
		}
	}

	// Continuation handles inherit the full binding: another actor is denied.
	f.snapshots.StoreSnapshot(testTenant, otherActor, policy.SealedAccessSnapshot{
		TenantRef: testTenant, OrgVersion: 7,
		OrgUnits:    []policy.SealedOrgUnit{{ID: "root"}},
		Memberships: []policy.SealedMembership{{OrgUnitID: "root", Role: "suggest"}},
	})
	first, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 2))
	if err != nil || first.ContinuationRef == "" {
		t.Fatalf("expected a continuation page: (%+v, %v)", first, err)
	}
	stolen, err := f.svc.Read(context.Background(), f.principal(otherActor), fullAuthz(), f.readRequest(result.BusinessContextRef, first.ContinuationRef, testPurpose, 2))
	if err != nil || stolen.Decision != DecisionDeny || stolen.Data != nil {
		t.Fatalf("continuation read by another actor = (%+v, %v), want bare deny", stolen, err)
	}
}

// --- Encrypted bounded staging ----------------------------------------------

func TestEvidenceStagingEncryptsAndBoundsContent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	f.locateOne(t, connectorClass, testPurpose)

	objects := f.objects.Objects()
	if len(objects) == 0 {
		t.Fatal("locate must stage content in the object store")
	}
	for key, blob := range objects {
		if bytes.Contains(blob, []byte(contentCanary)) {
			t.Fatalf("object %q stores plaintext content", key)
		}
		if bytes.Contains(blob, []byte(connectorCanary)) {
			t.Fatalf("object %q stores connector topology", key)
		}
	}

	// Oversized content is an explicit error, never silent truncation, and
	// never leaves partially staged objects or readable handles behind. The
	// bound travels INTO the source (a well-behaved source stops early); the
	// misbehaving-source backstop is proven separately.
	bounded := newFixture(t, WithMaxContentBytes(64))
	bounded.seedConnectorBinding(t, true, []Record{{"blob": strings.Repeat("x", 4096)}})
	_, err := bounded.svc.Locate(context.Background(), bounded.principal(testActor), fullAuthz(), bounded.locateRequest(connectorClass, testPurpose, 0))
	if !errors.Is(err, ErrContentTooLarge) {
		t.Fatalf("oversized locate = %v, want ErrContentTooLarge", err)
	}
	if remaining := bounded.objects.Objects(); len(remaining) != 0 {
		t.Fatalf("failed locate left %d staged objects behind", len(remaining))
	}
	if handles := bounded.store.Handles(testTenant); len(handles) != 0 {
		t.Fatalf("failed locate left %d handles behind", len(handles))
	}
}

// recordingBoundSource proves the staging bound travels into the source port.
type recordingBoundSource struct {
	inner       *MemoryContentSource
	gotMaxBytes int
}

func (r *recordingBoundSource) FetchEvidence(ctx context.Context, req ContentRequest) ([]Record, error) {
	r.gotMaxBytes = req.MaxBytes
	return r.inner.FetchEvidence(ctx, req)
}

// misbehavingSource ignores the staging bound and materializes an over-limit
// result — exactly what the service backstop exists to catch.
type misbehavingSource struct{}

func (misbehavingSource) FetchEvidence(context.Context, ContentRequest) ([]Record, error) {
	return []Record{{"blob": strings.Repeat("x", 4096)}}, nil
}

func TestEvidenceLocateBoundsSourceFetchAndNeedCount(t *testing.T) {
	t.Parallel()
	f := newFixture(t, WithMaxContentBytes(64))
	f.seedConnectorBinding(t, true, []Record{{"blob": strings.Repeat("x", 4096)}})

	// A well-behaved source RECEIVES the bound and enforces it before
	// materializing content; the locate fails explicitly.
	recording := &recordingBoundSource{inner: f.source}
	boundAware := NewService(f.store, f.objects, testKeyProvider(), recording,
		policy.NewCapabilityEvaluator(f.snapshots), f.audit,
		WithClock(func() time.Time { return *f.now }),
		WithIDGenerator(deterministicIDs()),
		WithMaxContentBytes(64),
	)
	_, err := boundAware.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest(connectorClass, testPurpose, 0))
	if !errors.Is(err, ErrContentTooLarge) {
		t.Fatalf("bound-aware source locate = %v, want ErrContentTooLarge", err)
	}
	if recording.gotMaxBytes != 64 {
		t.Fatalf("source received MaxBytes=%d, want the 64-byte staging bound", recording.gotMaxBytes)
	}

	// A misbehaving source that ignores the bound is caught by the post-hoc
	// backstop, with no partial state left behind.
	misbehaving := NewService(f.store, f.objects, testKeyProvider(), misbehavingSource{},
		policy.NewCapabilityEvaluator(f.snapshots), f.audit,
		WithClock(func() time.Time { return *f.now }),
		WithIDGenerator(deterministicIDs()),
		WithMaxContentBytes(64),
	)
	_, err = misbehaving.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest(connectorClass, testPurpose, 0))
	if !errors.Is(err, ErrContentTooLarge) {
		t.Fatalf("misbehaving source locate = %v, want backstop ErrContentTooLarge", err)
	}
	if remaining := f.objects.Objects(); len(remaining) != 0 {
		t.Fatalf("backstop left %d staged objects behind", len(remaining))
	}
	if handles := f.store.Handles(testTenant); len(handles) != 0 {
		t.Fatalf("backstop left %d handles behind", len(handles))
	}

	// The per-request need count is bounded explicitly.
	tooMany := f.locateRequest(connectorClass, testPurpose, 0)
	need := tooMany.DataNeeds[0]
	tooMany.DataNeeds = nil
	for i := 0; i < 33; i++ {
		extra := need
		extra.NeedID = fmt.Sprintf("need-%02d", i)
		tooMany.DataNeeds = append(tooMany.DataNeeds, extra)
	}
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), tooMany); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("locate with 33 needs = %v, want ErrInvalidRequest", err)
	}
}

func TestEvidenceSealOpenEnforcesKeyStrengthAndBinding(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte(`[{"k":"v"}]`)
	aad := contentAAD("ten_a", "obj_0000000000000001")

	// AES-128/192 keys are rejected: the documented strength is AES-256.
	for _, short := range []int{16, 24, 31, 33} {
		if _, err := seal(bytes.Repeat([]byte{0x01}, short), plaintext, aad); err == nil {
			t.Fatalf("seal accepted a %d-byte key", short)
		}
	}

	sealed, err := seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	roundtrip, err := open(key, sealed, aad)
	if err != nil || !bytes.Equal(roundtrip, plaintext) {
		t.Fatalf("open under the right binding = (%q, %v)", roundtrip, err)
	}

	// A blob moved to another tenant or object key fails authenticated
	// decryption (the GCM additional data binds it).
	if _, err := open(key, sealed, contentAAD("ten_b", "obj_0000000000000001")); err == nil {
		t.Fatal("open accepted a cross-tenant blob")
	}
	if _, err := open(key, sealed, contentAAD("ten_a", "obj_0000000000000002")); err == nil {
		t.Fatal("open accepted a blob rebound to another object key")
	}
}

func TestEvidenceFileObjectStoreIsAtomicPersistentAndTraversalSafe(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewFileObjectStore(root)
	if err != nil {
		t.Fatalf("NewFileObjectStore: %v", err)
	}
	ctx := context.Background()
	ciphertext := []byte{0x01, 0x02, 0xfe, 0xff, 0x10}
	if err := store.Put(ctx, "obj_0000000000000001", ciphertext); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A fresh store over the same root still resolves the object (durable).
	reopened, err := NewFileObjectStore(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := reopened.Get(ctx, "obj_0000000000000001")
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("Get after reopen = (%v, %v)", got, err)
	}

	if err := reopened.Delete(ctx, "obj_0000000000000001"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := reopened.Get(ctx, "obj_0000000000000001"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("Get after delete = %v, want ErrObjectNotFound", err)
	}

	// Path traversal is rejected structurally.
	for _, hostile := range []string{"../escape", "a/b", `a\b`, "", ".."} {
		if err := store.Put(ctx, hostile, ciphertext); err == nil {
			t.Fatalf("Put(%q) accepted a non-opaque object key", hostile)
		}
	}
}

func TestEvidenceEncryptedStagingWorksOverFileStoreAcrossRestart(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	files, err := NewFileObjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	source := NewMemoryContentSource()
	snapshots := policy.NewMemorySnapshotSource()
	snapshots.StoreSnapshot(testTenant, testActor, policy.SealedAccessSnapshot{
		TenantRef: testTenant, OrgVersion: 7,
		OrgUnits:    []policy.SealedOrgUnit{{ID: "root"}},
		Memberships: []policy.SealedMembership{{OrgUnitID: "root", Role: "suggest"}},
	})
	audit := &recordingAuditSink{}
	newService := func() *Service {
		return NewService(store, files, testKeyProvider(), source,
			policy.NewCapabilityEvaluator(snapshots), audit,
			WithClock(func() time.Time { return now }),
			WithIDGenerator(deterministicIDs()),
		)
	}
	svc := newService()
	if _, err := svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef: testTenant, DataClass: connectorClass,
		SourceRef: connectorCanary + connectorPathCanary, SourceVersion: 3,
		AccessCapability: "knowledge.suggest", SourceCapability: "connector.hr.read",
		ResourceType: "knowledge", ResourceID: "hr-directory", CachedReadAllowed: true,
	}); err != nil {
		t.Fatal(err)
	}
	source.Seed(connectorCanary+connectorPathCanary, []Record{{"note": contentCanary}})

	principal := runtime.PrincipalContext{
		TenantRef: testTenant, PrincipalRef: testActor, AgentClientRef: "console",
		AgentReleaseRef: "unregistered", TrustClass: runtime.TrustFirstParty,
		OrgSnapshotRef: "orgv_7", VerifiedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	request := runtime.EvidenceRequest{
		RequestID: "req-file", DataNeeds: []runtime.DataNeed{{NeedID: "n1", DataClass: connectorClass, Purpose: testPurpose}},
		Purpose: testPurpose, ExpiresAt: now.Add(2 * time.Hour),
	}
	located, err := svc.Locate(context.Background(), principal, fullAuthz(), request)
	if err != nil || len(located.Evidence) != 1 {
		t.Fatalf("Locate = (%+v, %v)", located, err)
	}

	// Encrypted temporary file staging: no plaintext byte sequence on disk.
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte(contentCanary)) || bytes.Contains(raw, []byte(connectorCanary)) {
			t.Fatalf("staged file %s contains plaintext", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk staged files: %v", err)
	}

	// Restart/resume: a brand-new service over the same durable state still
	// resolves and decrypts the handle.
	restarted := newService()
	read, err := restarted.Read(context.Background(), principal, fullAuthz(), runtime.EvidenceReadRequest{
		RequestID: "req-file-read", BusinessContextRef: located.BusinessContextRef,
		EvidenceRef: located.Evidence[0].EvidenceRef, Purpose: testPurpose, ExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil || read.Decision != DecisionAllow {
		t.Fatalf("read after restart = (%+v, %v), want allow", read, err)
	}
	records, ok := read.Data["records"].([]Record)
	if !ok || len(records) != 1 || records[0]["note"] != contentCanary {
		t.Fatalf("decrypted records after restart = %#v", read.Data)
	}
}

// --- Restart / resume over shared state --------------------------------------

func TestEvidenceServiceRestartResumesHandlesAndRevocations(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	f.seedOpenBinding(t, nil)
	keepResult, keepHandle := f.locateOne(t, openClass, testPurpose)
	revokeResult, revokeHandle := f.locateOne(t, connectorClass, testPurpose)
	if err := f.svc.RevokeAuthorization(context.Background(), testTenant, revokeHandle.EvidenceRef, "rotated"); err != nil {
		t.Fatal(err)
	}

	// A NEW service instance over the SAME persistent state: live handles
	// resolve, revocations stay revoked.
	restarted := NewService(f.store, f.objects, testKeyProvider(), f.source,
		policy.NewCapabilityEvaluator(f.snapshots), f.audit,
		WithClock(func() time.Time { return *f.now }),
		WithIDGenerator(deterministicIDs()),
	)
	read, err := restarted.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(keepResult.BusinessContextRef, keepHandle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionAllow {
		t.Fatalf("read of live handle after restart = (%+v, %v), want allow", read, err)
	}
	revoked, err := restarted.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(revokeResult.BusinessContextRef, revokeHandle.EvidenceRef, testPurpose, 0))
	if err != nil || revoked.Decision != DecisionDeny || revoked.Data != nil {
		t.Fatalf("read of revoked handle after restart = (%+v, %v), want bare deny", revoked, err)
	}
}

// --- Raw-content retention TTL ----------------------------------------------

func TestEvidenceRetentionExpiryRemovesContentButKeepsHandleAuditable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	binding, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef: testTenant, DataClass: connectorClass,
		SourceRef: connectorCanary + connectorPathCanary, SourceVersion: 3,
		AccessCapability: "knowledge.suggest", SourceCapability: "connector.hr.read",
		ResourceType: "knowledge", ResourceID: "hr-directory",
		CachedReadAllowed: true, RetentionTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.source.Seed(binding.SourceRef, []Record{{"note": contentCanary}})
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	stored, err := f.store.GetHandle(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil || stored.RetentionExpiresAt.IsZero() {
		t.Fatalf("handle must carry the optional raw-content retention TTL: (%+v, %v)", stored, err)
	}

	// Before retention expiry the sweep removes nothing.
	if removed, err := f.svc.SweepRetention(context.Background(), testTenant); err != nil || removed != 0 {
		t.Fatalf("early sweep = (%d, %v), want 0 removals", removed, err)
	}

	*f.now = f.now.Add(31 * time.Minute)
	removed, err := f.svc.SweepRetention(context.Background(), testTenant)
	if err != nil || removed != 1 {
		t.Fatalf("sweep = (%d, %v), want exactly 1 removal", removed, err)
	}
	if objects := f.objects.Objects(); len(objects) != 0 {
		t.Fatalf("retention sweep must remove staged content, %d objects remain", len(objects))
	}

	// The handle metadata stays auditable: the row, its content hash and the
	// content_expired event remain; the content itself is unreadable.
	after, err := f.store.GetHandle(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil || after.ContentHash != stored.ContentHash {
		t.Fatalf("handle metadata must survive retention expiry: (%+v, %v)", after, err)
	}
	events, err := f.store.ListHandleEvents(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil || len(events) == 0 || events[len(events)-1].Kind != HandleEventContentExpired {
		t.Fatalf("retention removal must persist as a content_expired event: (%+v, %v)", events, err)
	}
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("read after retention expiry = (%+v, %v), want bare deny", read, err)
	}

	// Idempotent: a second sweep removes nothing more.
	if removed, err := f.svc.SweepRetention(context.Background(), testTenant); err != nil || removed != 0 {
		t.Fatalf("second sweep = (%d, %v), want 0", removed, err)
	}
}

// --- Authorization lineage and audit provenance ------------------------------

func TestEvidenceLocateAppendsAuthorizationLineage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	events := f.audit.Events()
	var located *AuditEvent
	for i := range events {
		if events[i].Action == "evidence_located" && events[i].ResourceID == handle.EvidenceRef {
			located = &events[i]
		}
	}
	if located == nil {
		t.Fatalf("no evidence_located audit event for %s in %+v", handle.EvidenceRef, events)
	}
	if located.TenantRef != testTenant || located.PrincipalRef != testActor {
		t.Fatalf("lineage identity = %+v", located)
	}
	for _, key := range []string{"data_class", "source_version", "content_hash", "org_version", "decision"} {
		if _, ok := located.Details[key]; !ok {
			t.Fatalf("evidence_located details missing %q: %+v", key, located.Details)
		}
	}

	stored, err := f.store.GetHandle(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AuthorizationRef == "" {
		t.Fatal("handle must reference its authorization lineage head")
	}
	foundLineage := false
	for _, ref := range stored.Lineage {
		if ref == stored.AuthorizationRef {
			foundLineage = true
		}
	}
	if !foundLineage {
		t.Fatalf("lineage %v must contain the authorization ref %q", stored.Lineage, stored.AuthorizationRef)
	}

	// Reads append to the lineage through evidence_read events.
	if _, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0)); err != nil {
		t.Fatal(err)
	}
	readSeen := false
	for _, event := range f.audit.Events() {
		if event.Action == "evidence_read" && event.ResourceID == handle.EvidenceRef {
			readSeen = true
		}
	}
	if !readSeen {
		t.Fatal("allowed read must append an evidence_read lineage event")
	}

	// Lineage is mandatory: when the audit sink fails, issuance fails closed.
	f.audit.mu.Lock()
	f.audit.fail = errors.New("audit sink offline")
	f.audit.mu.Unlock()
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest(connectorClass, testPurpose, 0)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("locate without lineage sink = %v, want ErrUnavailable", err)
	}
}

// --- Sensitive-data absence from logs, events and support metadata -----------

func TestEvidenceSensitiveContentAbsentFromLogsEventsAndErrors(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	// Exercise allow, deny and error paths so every logging site runs.
	var errorTexts []string
	if _, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0)); err != nil {
		t.Fatal(err)
	}
	deny, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, "wrong-purpose", 0))
	if err != nil || deny.Decision != DecisionDeny {
		t.Fatalf("expected deny, got (%+v, %v)", deny, err)
	}
	if payload, err := json.Marshal(deny); err != nil || strings.Contains(string(payload), contentCanary) {
		t.Fatalf("deny response leaks content: %s (%v)", payload, err)
	}
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), astraClawAuthz(), f.locateRequest(connectorClass, testPurpose, 0)); err != nil {
		errorTexts = append(errorTexts, err.Error())
	}
	if err := f.svc.RevokeAuthorization(context.Background(), testTenant, handle.EvidenceRef, "cleanup"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0)); err != nil {
		errorTexts = append(errorTexts, err.Error())
	}

	stored, err := f.store.GetHandle(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}

	logText := f.logs.String()
	auditPayload, err := json.Marshal(f.audit.Events())
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{contentCanary, connectorCanary, connectorPathCanary}
	for _, needle := range banned {
		if strings.Contains(logText, needle) {
			t.Fatalf("log output leaks %q:\n%s", needle, logText)
		}
		if strings.Contains(string(auditPayload), needle) {
			t.Fatalf("audit lineage leaks %q: %s", needle, auditPayload)
		}
		for _, text := range errorTexts {
			if strings.Contains(text, needle) {
				t.Fatalf("error text leaks %q: %s", needle, text)
			}
		}
	}

	// Provenance stays visible the safe way: the content HASH (never the
	// content) appears in the lineage.
	if !strings.Contains(string(auditPayload), stored.ContentHash) {
		t.Fatalf("audit lineage must reference the content hash %s: %s", stored.ContentHash, auditPayload)
	}
	if !strings.Contains(logText, handle.EvidenceRef) {
		t.Fatalf("logs should reference the opaque handle for support: %s", logText)
	}
}

// --- Fix-round coverage: retention at read time, blob lifecycle, bounds ------

func TestEvidenceReadDeniesPastRetentionWithoutSweep(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	binding, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef: testTenant, DataClass: connectorClass,
		SourceRef: connectorCanary + connectorPathCanary, SourceVersion: 3,
		AccessCapability: "knowledge.suggest", SourceCapability: "connector.hr.read",
		ResourceType: "knowledge", ResourceID: "hr-directory",
		CachedReadAllowed: true, RetentionTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.source.Seed(binding.SourceRef, []Record{{"note": contentCanary}})
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	// Inside the retention window the read serves.
	if read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0)); err != nil || read.Decision != DecisionAllow {
		t.Fatalf("read inside retention = (%+v, %v), want allow", read, err)
	}

	// Past retention but INSIDE the 2h handle TTL, with NO sweep having run:
	// the read itself denies — the sweeper is purely janitorial and a delayed
	// sweep never extends data availability.
	*f.now = f.now.Add(31 * time.Minute)
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("read past retention without sweep = (%+v, %v), want bare deny", read, err)
	}
}

func TestEvidenceRetentionDefaultsToHandleExpiryAndSweepsSharedBlobs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// The binding sets NO retention TTL: raw content must still never outlive
	// the handle, so retention defaults to the handle expiry.
	f.seedConnectorBinding(t, true, []Record{{"seq": "r1"}, {"seq": "r2"}, {"seq": "r3"}})
	result, handle := f.locateOne(t, connectorClass, testPurpose)
	stored, err := f.store.GetHandle(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.RetentionExpiresAt.Equal(stored.ExpiresAt) {
		t.Fatalf("retention must default to the handle expiry: retention=%v expiry=%v", stored.RetentionExpiresAt, stored.ExpiresAt)
	}

	// A bounded read mints a continuation sharing the SAME object key with the
	// SAME deadlines (the shared-blob sweep-safety invariant).
	first, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 2))
	if err != nil || first.ContinuationRef == "" {
		t.Fatalf("expected continuation: (%+v, %v)", first, err)
	}
	continuation, err := f.store.GetHandle(context.Background(), testTenant, first.ContinuationRef)
	if err != nil {
		t.Fatal(err)
	}
	if continuation.ObjectKey != stored.ObjectKey ||
		!continuation.RetentionExpiresAt.Equal(stored.RetentionExpiresAt) ||
		!continuation.ExpiresAt.Equal(stored.ExpiresAt) {
		t.Fatalf("continuation must share object key and deadlines: parent=%+v continuation=%+v", stored, continuation)
	}

	// After the handle expiry the sweep drains BOTH handles and removes the
	// shared blob exactly once; no orphaned ciphertext remains.
	*f.now = f.now.Add(3 * time.Hour)
	removed, err := f.svc.SweepRetention(context.Background(), testTenant)
	if err != nil || removed != 2 {
		t.Fatalf("sweep = (%d, %v), want both handles drained", removed, err)
	}
	if objects := f.objects.Objects(); len(objects) != 0 {
		t.Fatalf("sweep left %d objects behind", len(objects))
	}
	for _, ref := range []string{handle.EvidenceRef, first.ContinuationRef} {
		events, err := f.store.ListHandleEvents(context.Background(), testTenant, ref)
		if err != nil || len(events) == 0 || events[len(events)-1].Kind != HandleEventContentExpired {
			t.Fatalf("%s must carry a content_expired event: (%+v, %v)", ref, events, err)
		}
	}
	// Idempotent afterwards.
	if removed, err := f.svc.SweepRetention(context.Background(), testTenant); err != nil || removed != 0 {
		t.Fatalf("second sweep = (%d, %v), want 0", removed, err)
	}
}

func TestEvidenceReadCannotRaiseLocateTimePageBound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, []Record{{"seq": "r1"}, {"seq": "r2"}, {"seq": "r3"}})
	// Locate binds a page bound of 2 (need constraint).
	result, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), f.locateRequest(connectorClass, testPurpose, 2))
	if err != nil || len(result.Evidence) != 1 {
		t.Fatalf("Locate = (%+v, %v)", result, err)
	}
	handle := result.Evidence[0]

	// A read asking for 10 must still get pages of AT MOST 2: the locate-time
	// bound is a ceiling the read can narrow but never raise.
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 10))
	if err != nil || read.Decision != DecisionAllow {
		t.Fatalf("read = (%+v, %v)", read, err)
	}
	records, ok := read.Data["records"].([]Record)
	if !ok || len(records) != 2 || read.ContinuationRef == "" {
		t.Fatalf("read exceeded the locate-time page bound: %d records, continuation %q", len(records), read.ContinuationRef)
	}
	// Narrowing below the ceiling stays allowed.
	narrow, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 1))
	if err != nil || narrow.Decision != DecisionAllow {
		t.Fatalf("narrow read = (%+v, %v)", narrow, err)
	}
	if narrowRecords, ok := narrow.Data["records"].([]Record); !ok || len(narrowRecords) != 1 {
		t.Fatalf("narrow read records = %#v, want 1", narrow.Data)
	}
}

func TestEvidenceLocateBindsOnePurposeAndRecordsLineagePurpose(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)

	// One request carries ONE justification: a need whose purpose diverges
	// from the request purpose is invalid, not silently accepted.
	conflicted := f.locateRequest(connectorClass, testPurpose, 0)
	conflicted.DataNeeds[0].Purpose = "unrelated-justification"
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), conflicted); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("purpose-conflicted locate = %v, want ErrInvalidRequest", err)
	}

	// The agreed purpose and the need id are recorded in the authorization
	// lineage (they are binding facts, not decoration).
	_, handle := f.locateOne(t, connectorClass, testPurpose)
	var located *AuditEvent
	events := f.audit.Events()
	for i := range events {
		if events[i].Action == "evidence_located" && events[i].ResourceID == handle.EvidenceRef {
			located = &events[i]
		}
	}
	if located == nil {
		t.Fatalf("no evidence_located lineage for %s", handle.EvidenceRef)
	}
	if located.Details["purpose"] != testPurpose {
		t.Fatalf("lineage purpose = %v, want %q", located.Details["purpose"], testPurpose)
	}
	if located.Details["need_id"] != "need-"+connectorClass {
		t.Fatalf("lineage need_id = %v", located.Details["need_id"])
	}

	// A non-canonical need id is rejected outright.
	badNeed := f.locateRequest(connectorClass, testPurpose, 0)
	badNeed.DataNeeds[0].NeedID = " padded "
	if _, err := f.svc.Locate(context.Background(), f.principal(testActor), fullAuthz(), badNeed); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("non-canonical need_id locate = %v, want ErrInvalidRequest", err)
	}
}

func TestEvidenceSourceRevivalNeverRevivesStaleHandles(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	binding := f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	if err := f.svc.DeleteSource(context.Background(), testTenant, connectorClass); err != nil {
		t.Fatal(err)
	}
	// Revive the tombstoned binding at the SAME declared source version: the
	// registry must bump PAST the tombstoned version, so handles that were
	// denied by the deletion stay denied (stale) instead of silently reviving.
	revived, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef: testTenant, DataClass: connectorClass,
		SourceRef: binding.SourceRef, SourceVersion: binding.SourceVersion,
		AccessCapability: "knowledge.suggest", SourceCapability: "connector.hr.read",
		ResourceType: "knowledge", ResourceID: "hr-directory", CachedReadAllowed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if revived.SourceVersion != binding.SourceVersion+1 {
		t.Fatalf("revived source version = %d, want %d (bump past the tombstone)", revived.SourceVersion, binding.SourceVersion+1)
	}
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if err != nil || read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("pre-revival handle after revival = (%+v, %v), want bare deny", read, err)
	}
	// A fresh locate against the revived source reads at the bumped version.
	freshResult, freshHandle := f.locateOne(t, connectorClass, testPurpose)
	fresh, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(freshResult.BusinessContextRef, freshHandle.EvidenceRef, testPurpose, 0))
	if err != nil || fresh.Decision != DecisionAllow || fresh.SourceVersion != revived.SourceVersion {
		t.Fatalf("fresh read after revival = (%+v, %v), want allow at version %d", fresh, err, revived.SourceVersion)
	}
}

func TestEvidenceReadFailsClosedWhenLineageSinkUnavailable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.seedConnectorBinding(t, true, nil)
	result, handle := f.locateOne(t, connectorClass, testPurpose)

	// An ALLOWED read without a recorded lineage append is no read at all:
	// the audit outage fails the read closed instead of egressing unaudited
	// data.
	f.audit.mu.Lock()
	f.audit.fail = errors.New("audit sink offline")
	f.audit.mu.Unlock()
	read, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), f.readRequest(result.BusinessContextRef, handle.EvidenceRef, testPurpose, 0))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("read with failing lineage sink = (%+v, %v), want ErrUnavailable", read, err)
	}
	if read.Data != nil || read.Decision == DecisionAllow {
		t.Fatalf("failed-lineage read must not egress data: %+v", read)
	}
}
