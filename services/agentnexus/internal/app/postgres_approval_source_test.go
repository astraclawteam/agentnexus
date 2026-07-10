package app

import (
	"context"
	"errors"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type fakeApprovalSnapshotTx struct {
	version     int64
	units       []db.OrgPolicySnapshotUnit
	memberships []db.OrgPolicySnapshotMembership
	users       []db.ListApprovalUsersRow
	err         error
	committed   bool
	rolledBack  bool
}

func (t *fakeApprovalSnapshotTx) GetLatestApprovalOrgVersion(context.Context, string) (int64, error) {
	return t.version, t.err
}
func (t *fakeApprovalSnapshotTx) ListApprovalOrgUnits(context.Context, db.ListApprovalOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error) {
	return t.units, t.err
}
func (t *fakeApprovalSnapshotTx) ListApprovalMemberships(context.Context, db.ListApprovalMembershipsParams) ([]db.OrgPolicySnapshotMembership, error) {
	return t.memberships, t.err
}
func (t *fakeApprovalSnapshotTx) ListApprovalUsers(context.Context, db.ListApprovalUsersParams) ([]db.ListApprovalUsersRow, error) {
	return t.users, t.err
}
func (t *fakeApprovalSnapshotTx) Commit(context.Context) error   { t.committed = true; return nil }
func (t *fakeApprovalSnapshotTx) Rollback(context.Context) error { t.rolledBack = true; return nil }

type fakeApprovalSnapshotPool struct {
	tx      *fakeApprovalSnapshotTx
	options pgx.TxOptions
}

func (p *fakeApprovalSnapshotPool) BeginApprovalSnapshotTx(_ context.Context, options pgx.TxOptions) (approvalSnapshotTx, error) {
	p.options = options
	return p.tx, nil
}

func TestPostgresApprovalSourceLoadsExactSealedRepeatableReadSnapshot(t *testing.T) {
	tx := validApprovalSnapshotTx()
	pool := &fakeApprovalSnapshotPool{tx: tx}
	loaded, err := newPostgresApprovalSourceWithPool(pool).LoadApprovalSnapshot(context.Background(), "enterprise-1", 7, "requester")
	if err != nil {
		t.Fatal(err)
	}
	if pool.options.IsoLevel != pgx.RepeatableRead || pool.options.AccessMode != pgx.ReadOnly || !tx.committed {
		t.Fatalf("options=%+v committed=%v", pool.options, tx.committed)
	}
	req := approval.Request{EnterpriseID: "enterprise-1", RequesterUserID: "requester", OrgVersion: 7, OrgUnitID: "team", ResourceType: "workflow", ResourceID: "workflow-1", Action: "workflow.update", Risk: approval.RiskInput{ExternalSideEffect: true}}
	route, err := approval.NewResolver(loaded.Permissions, approval.DefaultPolicy()).Resolve(context.Background(), req, loaded.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if route.ReviewerUserID != "reviewer" || route.ReviewerDisplayName != "Reviewer" {
		t.Fatalf("route=%+v", route)
	}
}

func TestPostgresApprovalSourceDoesNotGiveManagerImplicitPermission(t *testing.T) {
	tx := validApprovalSnapshotTx()
	tx.memberships = tx.memberships[:1]
	loaded, err := newPostgresApprovalSourceWithPool(&fakeApprovalSnapshotPool{tx: tx}).LoadApprovalSnapshot(context.Background(), "enterprise-1", 7, "requester")
	if err != nil {
		t.Fatal(err)
	}
	req := approval.Request{EnterpriseID: "enterprise-1", RequesterUserID: "requester", OrgVersion: 7, OrgUnitID: "team", ResourceType: "workflow", ResourceID: "workflow-1", Action: "workflow.update", Risk: approval.RiskInput{ExternalSideEffect: true}}
	route, err := approval.NewResolver(loaded.Permissions, approval.DefaultPolicy()).Resolve(context.Background(), req, loaded.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != approval.ModeEnterpriseKnowledgeAdminQueue {
		t.Fatalf("route=%+v", route)
	}
}

func TestPostgresApprovalSourceFailsClosedForStaleCrossTenantLimitsAndCancellation(t *testing.T) {
	tests := []struct {
		name    string
		version int64
		mutate  func(*fakeApprovalSnapshotTx)
		ctx     func() context.Context
	}{
		{name: "stale", version: 6},
		{name: "cross tenant unit", version: 7, mutate: func(tx *fakeApprovalSnapshotTx) { tx.units[0].EnterpriseID = "other" }},
		{name: "unit limit", version: 7, mutate: func(tx *fakeApprovalSnapshotTx) {
			tx.units = make([]db.OrgPolicySnapshotUnit, approval.MaxSnapshotOrgUnits+1)
		}},
		{name: "membership limit", version: 7, mutate: func(tx *fakeApprovalSnapshotTx) {
			tx.memberships = make([]db.OrgPolicySnapshotMembership, approval.MaxSnapshotPrincipals+1)
		}},
		{name: "cancel", version: 7, ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := validApprovalSnapshotTx()
			if tt.mutate != nil {
				tt.mutate(tx)
			}
			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx()
			}
			_, err := newPostgresApprovalSourceWithPool(&fakeApprovalSnapshotPool{tx: tx}).LoadApprovalSnapshot(ctx, "enterprise-1", tt.version, "requester")
			if !errors.Is(err, approval.ErrApprovalUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func validApprovalSnapshotTx() *fakeApprovalSnapshotTx {
	return &fakeApprovalSnapshotTx{
		version: 7,
		units: []db.OrgPolicySnapshotUnit{
			{EnterpriseID: "enterprise-1", VersionNumber: 7, OrgUnitID: "root"},
			{EnterpriseID: "enterprise-1", VersionNumber: 7, OrgUnitID: "team", ParentID: pgtype.Text{String: "root", Valid: true}},
		},
		memberships: []db.OrgPolicySnapshotMembership{
			{EnterpriseID: "enterprise-1", VersionNumber: 7, EnterpriseUserID: "reviewer", OrgUnitID: "team", Role: "manager"},
			{EnterpriseID: "enterprise-1", VersionNumber: 7, EnterpriseUserID: "reviewer", OrgUnitID: "team", Role: "approve_high_risk"},
		},
		users: []db.ListApprovalUsersRow{{ID: "reviewer", EnterpriseID: "enterprise-1", DisplayName: "Reviewer"}},
	}
}
