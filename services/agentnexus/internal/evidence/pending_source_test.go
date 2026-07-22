package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

func TestPendingContentSourceNeverReturnsRecords(t *testing.T) {
	t.Parallel()
	records, err := NewPendingContentSource().FetchEvidence(context.Background(), ContentRequest{
		TenantRef: testTenant, SourceRef: "internal-kb-store", DataClass: openClass, MaxBytes: 1024,
	})
	if records != nil {
		t.Fatalf("the pending source returned %d records; it must never fabricate evidence", len(records))
	}
	if !errors.Is(err, ErrNoContentSource) {
		t.Fatalf("FetchEvidence error = %v, want ErrNoContentSource", err)
	}
	// ErrUnavailable is what makes the gateway answer 503 rather than treating an
	// absent integration as a policy denial or a caller mistake.
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("FetchEvidence error = %v, want it to wrap ErrUnavailable", err)
	}
	// It must NOT look like a staging-bound failure, which the service maps to
	// 422 content_bound_exceeded — that would misreport a missing integration as
	// oversized customer data.
	if errors.Is(err, ErrContentTooLarge) {
		t.Fatal("the pending source must not report a staging-bound failure")
	}
}

// A locate through a FULLY constructed service over the pending source must
// fail closed at the fetch: no handle issued, nothing staged. This is what the
// composition root ships today, so it is worth proving rather than assuming.
func TestLocateOverThePendingSourceIssuesNoHandleAndStagesNothing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	objects := NewMemoryObjectStore()
	snapshots := policy.NewMemorySnapshotSource()
	snapshots.StoreSnapshot(testTenant, testActor, policy.SealedAccessSnapshot{
		TenantRef:   testTenant,
		OrgVersion:  7,
		OrgUnits:    []policy.SealedOrgUnit{{ID: "root"}},
		Memberships: []policy.SealedMembership{{OrgUnitID: "root", Role: "suggest"}},
	})
	keys, err := NewConfiguredKeyProvider("evd-key-1", testContentKey())
	if err != nil {
		t.Fatalf("NewConfiguredKeyProvider: %v", err)
	}
	audit := &recordingAuditSink{}
	svc := NewService(store, objects, keys, NewPendingContentSource(),
		policy.NewCapabilityEvaluator(snapshots), audit,
		WithClock(func() time.Time { return now }), WithIDGenerator(deterministicIDs()))

	// The binding resolves and the capability check PASSES; the fetch is the
	// only thing that fails, which is exactly the boundary under test.
	if _, err := svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef: testTenant, DataClass: openClass, SourceRef: "internal-kb-store", SourceVersion: 1,
		AccessCapability: "knowledge.suggest", ResourceType: "knowledge", ResourceID: "kb-space",
		CachedReadAllowed: true,
	}); err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}

	fixture := &evidenceFixture{now: &now}
	_, err = svc.Locate(context.Background(), fixture.principal(testActor), fullAuthz(),
		fixture.locateRequest(openClass, testPurpose, 0))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Locate error = %v, want ErrUnavailable", err)
	}
	if errors.Is(err, ErrDenied) {
		t.Fatal("an absent content source must not masquerade as an authorization denial")
	}
	if handles := store.Handles(testTenant); len(handles) != 0 {
		t.Fatalf("a failed fetch issued %d handles", len(handles))
	}
	if staged := objects.Objects(); len(staged) != 0 {
		t.Fatalf("a failed fetch staged %d objects", len(staged))
	}
}
