package iam

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestEnterpriseIAMAndOrgGraphLifecycle(t *testing.T) {
	ctx := context.Background()
	service := NewService(
		NewMemoryStore(),
		WithIDGenerator(sequenceIDs("event_1", "version_1")),
	)

	enterprise, err := service.CreateEnterprise(ctx, CreateEnterpriseInput{
		ID:   "ent_1",
		Name: "Astraclaw",
	})
	if err != nil {
		t.Fatalf("CreateEnterprise returned error: %v", err)
	}
	if enterprise.ID != "ent_1" || enterprise.Name != "Astraclaw" {
		t.Fatalf("enterprise = %+v, want ent_1 Astraclaw", enterprise)
	}

	user, err := service.UpsertEnterpriseUser(ctx, UpsertEnterpriseUserInput{
		ID:           "user_1",
		EnterpriseID: "ent_1",
		DisplayName:  "Original Name",
		Email:        "original@example.com",
	})
	if err != nil {
		t.Fatalf("UpsertEnterpriseUser insert returned error: %v", err)
	}
	user, err = service.UpsertEnterpriseUser(ctx, UpsertEnterpriseUserInput{
		ID:           user.ID,
		EnterpriseID: user.EnterpriseID,
		DisplayName:  "Updated Name",
		Email:        "updated@example.com",
		Phone:        "+8613800000000",
	})
	if err != nil {
		t.Fatalf("UpsertEnterpriseUser update returned error: %v", err)
	}
	if user.DisplayName != "Updated Name" || user.Email != "updated@example.com" {
		t.Fatalf("user = %+v, want updated fields", user)
	}

	identity, err := service.BindExternalIdentity(ctx, BindExternalIdentityInput{
		ID:               "identity_1",
		EnterpriseID:     "ent_1",
		EnterpriseUserID: "user_1",
		Provider:         "wecom",
		ExternalSubject:  "external_user_1",
	})
	if err != nil {
		t.Fatalf("BindExternalIdentity returned error: %v", err)
	}
	if identity.Provider != "wecom" || identity.ExternalSubject != "external_user_1" {
		t.Fatalf("identity = %+v, want wecom external subject", identity)
	}

	department, err := service.UpsertOrgUnit(ctx, UpsertOrgUnitInput{
		ID:           "dept_legal",
		EnterpriseID: "ent_1",
		Name:         "Legal",
		UnitType:     OrgUnitTypeDepartment,
	})
	if err != nil {
		t.Fatalf("UpsertOrgUnit department returned error: %v", err)
	}
	if department.UnitType != OrgUnitTypeDepartment {
		t.Fatalf("department type = %q, want %q", department.UnitType, OrgUnitTypeDepartment)
	}

	projectGroup, err := service.UpsertOrgUnit(ctx, UpsertOrgUnitInput{
		ID:           "pg_contracts",
		EnterpriseID: "ent_1",
		ParentID:     "dept_legal",
		Name:         "Contracts",
		UnitType:     OrgUnitTypeProjectGroup,
	})
	if err != nil {
		t.Fatalf("UpsertOrgUnit project group returned error: %v", err)
	}
	if projectGroup.ParentID != "dept_legal" {
		t.Fatalf("projectGroup parent = %q, want dept_legal", projectGroup.ParentID)
	}

	membership, err := service.AddOrgMembership(ctx, AddOrgMembershipInput{
		EnterpriseID:     "ent_1",
		EnterpriseUserID: "user_1",
		OrgUnitID:        "dept_legal",
		Role:             OrgRoleManager,
	})
	if err != nil {
		t.Fatalf("AddOrgMembership returned error: %v", err)
	}
	if membership.Role != OrgRoleManager {
		t.Fatalf("membership role = %q, want %q", membership.Role, OrgRoleManager)
	}

	version, err := service.CreateOrgVersion(ctx, CreateOrgVersionInput{
		EnterpriseID:  "ent_1",
		VersionNumber: 1,
		SourceHash:    "sha256:org-source",
	})
	if err != nil {
		t.Fatalf("CreateOrgVersion returned error: %v", err)
	}
	if version.VersionNumber != 1 || version.SourceEventID != "event_1" {
		t.Fatalf("version = %+v, want version 1 from event_1", version)
	}
}

func TestMemoryStorePublishesEventVersionAndImmutableSnapshotAtomically(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	service := NewService(store, WithIDGenerator(sequenceIDs("event-1", "version-1")))
	if _, err := service.UpsertOrgUnit(ctx, UpsertOrgUnitInput{ID: "dept", EnterpriseID: "enterprise-1", Name: "Original", UnitType: OrgUnitTypeDepartment}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddOrgMembership(ctx, AddOrgMembershipInput{EnterpriseID: "enterprise-1", EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateOrgVersion(ctx, CreateOrgVersionInput{EnterpriseID: "enterprise-1", VersionNumber: 7, SourceHash: "source"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpsertOrgUnit(ctx, UpsertOrgUnitInput{ID: "dept", EnterpriseID: "enterprise-1", Name: "Changed", ParentID: "new-parent", UnitType: OrgUnitTypeDepartment}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddOrgMembership(ctx, AddOrgMembershipInput{EnterpriseID: "enterprise-1", EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: OrgRole("edit")}); err != nil {
		t.Fatal(err)
	}

	snapshot, ok := store.policySnapshot("enterprise-1", 7)
	if !ok {
		t.Fatal("published memory snapshot missing")
	}
	if len(snapshot.units) != 1 || snapshot.units[0].Name != "Original" || snapshot.units[0].ParentID != "" {
		t.Fatalf("snapshot units changed with live state: %#v", snapshot.units)
	}
	if !reflect.DeepEqual(snapshot.memberships, []OrgMembership{{EnterpriseID: "enterprise-1", EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: OrgRoleMember, CreatedAt: snapshot.memberships[0].CreatedAt}}) {
		t.Fatalf("snapshot memberships changed with live state: %#v", snapshot.memberships)
	}
	if _, eventOK := store.orgEvents[key("enterprise-1", "event-1")]; !eventOK {
		t.Fatal("atomic publication did not store event")
	}
}

type failingOrgPolicyPublisherStore struct {
	Store
	err              error
	publishCalls     int
	createEventCalls int
}

func (s *failingOrgPolicyPublisherStore) PublishOrgVersion(context.Context, OrgEvent, OrgVersion) (OrgVersion, error) {
	s.publishCalls++
	return OrgVersion{}, s.err
}

func (s *failingOrgPolicyPublisherStore) CreateOrgEvent(context.Context, OrgEvent) (OrgEvent, error) {
	s.createEventCalls++
	return OrgEvent{}, nil
}

func TestServiceAtomicPublisherFailureDoesNotFallBackAndOrphanEvent(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("publication failed")
	store := &failingOrgPolicyPublisherStore{err: sentinel}
	service := NewService(store, WithIDGenerator(sequenceIDs("event-1", "version-1")))
	_, err := service.CreateOrgVersion(context.Background(), CreateOrgVersionInput{EnterpriseID: "enterprise-1", VersionNumber: 1})
	if !errors.Is(err, sentinel) || store.publishCalls != 1 || store.createEventCalls != 0 {
		t.Fatalf("error=%v publish=%d createEvent=%d", err, store.publishCalls, store.createEventCalls)
	}
}

func TestMemoryStoreCreateOrgVersionDirectlyCapturesSnapshot(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	if _, err := store.UpsertOrgUnit(context.Background(), OrgUnit{ID: "dept", EnterpriseID: "enterprise-1", Name: "Before"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateOrgVersion(context.Background(), OrgVersion{ID: "version-2", EnterpriseID: "enterprise-1", VersionNumber: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertOrgUnit(context.Background(), OrgUnit{ID: "dept", EnterpriseID: "enterprise-1", Name: "After"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateOrgVersion(context.Background(), OrgVersion{ID: "version-2-retry", EnterpriseID: "enterprise-1", VersionNumber: 2}); err == nil {
		t.Fatal("direct duplicate version was accepted")
	}
	snapshot, ok := store.policySnapshot("enterprise-1", 2)
	if !ok || len(snapshot.units) != 1 || snapshot.units[0].Name != "Before" {
		t.Fatalf("direct version snapshot = %#v, ok=%t", snapshot, ok)
	}
}

func TestMemoryStoreRejectsNonMonotonicPublicationWithoutOverwritingSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	store.orgVersions[key("enterprise-1", "legacy-42")] = OrgVersion{ID: "legacy-42", EnterpriseID: "enterprise-1", VersionNumber: 42}
	if _, err := store.UpsertOrgUnit(ctx, OrgUnit{ID: "dept", EnterpriseID: "enterprise-1", Name: "Before"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishOrgVersion(ctx,
		OrgEvent{ID: "event-1", EnterpriseID: "enterprise-1", EventType: "org_import"},
		OrgVersion{ID: "version-1", EnterpriseID: "enterprise-1", VersionNumber: 1, SourceEventID: "event-1"},
	); err == nil {
		t.Fatal("publication below legacy maximum was accepted")
	}
	if len(store.orgEvents) != 0 || len(store.policySnapshots) != 0 {
		t.Fatalf("failed publication wrote state: events=%d snapshots=%d", len(store.orgEvents), len(store.policySnapshots))
	}
	if _, err := store.PublishOrgVersion(ctx,
		OrgEvent{ID: "event-43", EnterpriseID: "enterprise-1", EventType: "org_import"},
		OrgVersion{ID: "version-43", EnterpriseID: "enterprise-1", VersionNumber: 43, SourceEventID: "event-43"},
	); err != nil {
		t.Fatalf("publication above legacy maximum failed: %v", err)
	}
	if _, err := store.UpsertOrgUnit(ctx, OrgUnit{ID: "dept", EnterpriseID: "enterprise-1", Name: "After"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishOrgVersion(ctx,
		OrgEvent{ID: "event-duplicate", EnterpriseID: "enterprise-1", EventType: "org_import"},
		OrgVersion{ID: "version-duplicate", EnterpriseID: "enterprise-1", VersionNumber: 43, SourceEventID: "event-duplicate"},
	); err == nil {
		t.Fatal("duplicate version publication was accepted")
	}
	snapshot, ok := store.policySnapshot("enterprise-1", 43)
	if !ok || len(snapshot.units) != 1 || snapshot.units[0].Name != "Before" {
		t.Fatalf("duplicate publication overwrote snapshot: %#v, ok=%t", snapshot, ok)
	}
	if _, ok := store.orgEvents[key("enterprise-1", "event-duplicate")]; ok {
		t.Fatal("failed duplicate publication orphaned an event")
	}
}

func TestMemoryStoreConcurrentSameVersionOnlyOnePublishes(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, suffix := range []string{"a", "b"} {
		suffix := suffix
		go func() {
			<-start
			_, err := store.PublishOrgVersion(context.Background(),
				OrgEvent{ID: "event-" + suffix, EnterpriseID: "enterprise-1", EventType: "org_import"},
				OrgVersion{ID: "version-" + suffix, EnterpriseID: "enterprise-1", VersionNumber: 1, SourceEventID: "event-" + suffix},
			)
			results <- err
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 || len(store.orgEvents) != 1 || len(store.orgVersions) != 1 || len(store.policySnapshots) != 1 {
		t.Fatalf("successes=%d events=%d versions=%d snapshots=%d", successes, len(store.orgEvents), len(store.orgVersions), len(store.policySnapshots))
	}
}

func TestMemoryStoreRejectsInvalidPublicationBeforeWriting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ctx     context.Context
		event   OrgEvent
		version OrgVersion
	}{
		{name: "enterprise mismatch", ctx: context.Background(), event: OrgEvent{ID: "event", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version", EnterpriseID: "enterprise-2", VersionNumber: 1, SourceEventID: "event"}},
		{name: "source event mismatch", ctx: context.Background(), event: OrgEvent{ID: "event", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version", EnterpriseID: "enterprise-1", VersionNumber: 1, SourceEventID: "other"}},
		{name: "noncanonical identifier", ctx: context.Background(), event: OrgEvent{ID: " event", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version", EnterpriseID: "enterprise-1", VersionNumber: 1, SourceEventID: " event"}},
		{name: "zero version", ctx: context.Background(), event: OrgEvent{ID: "event", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version", EnterpriseID: "enterprise-1", VersionNumber: 0, SourceEventID: "event"}},
		{name: "negative version", ctx: context.Background(), event: OrgEvent{ID: "event", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version", EnterpriseID: "enterprise-1", VersionNumber: -1, SourceEventID: "event"}},
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests = append(tests, struct {
		name    string
		ctx     context.Context
		event   OrgEvent
		version OrgVersion
	}{name: "canceled context", ctx: canceled, event: OrgEvent{ID: "event", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version", EnterpriseID: "enterprise-1", VersionNumber: 1, SourceEventID: "event"}})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryStore()
			if _, err := store.PublishOrgVersion(test.ctx, test.event, test.version); err == nil {
				t.Fatal("invalid publication was accepted")
			}
			if len(store.orgEvents) != 0 || len(store.orgVersions) != 0 || len(store.policySnapshots) != 0 {
				t.Fatalf("invalid publication wrote state: events=%d versions=%d snapshots=%d", len(store.orgEvents), len(store.orgVersions), len(store.policySnapshots))
			}
		})
	}
}

func sequenceIDs(ids ...string) func() string {
	index := 0
	return func() string {
		if index >= len(ids) {
			return "extra_id"
		}
		id := ids[index]
		index++
		return id
	}
}
