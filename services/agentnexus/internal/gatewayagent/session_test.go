package gatewayagent

import (
	"context"
	"errors"
	"testing"

	adksession "google.golang.org/adk/v2/session"
)

const testAppName = "gateway-agent"

// TestSessionsAreTenantIsolated is the security property of this package.
//
// ADK addresses a session by (AppName, UserID, SessionID) and none of those is
// a tenant. Two tenants that happen to use the same operator identifier and the
// same session identifier would otherwise share one conversation - including
// whatever the assistant learned about the other tenant's environment. The
// scoped service must make that collision impossible rather than unlikely.
func TestSessionsAreTenantIsolated(t *testing.T) {
	scoped := NewTenantScopedSessionService(adksession.InMemoryService(), testAppName)

	tenantA := WithTenant(context.Background(), "ent-a")
	tenantB := WithTenant(context.Background(), "ent-b")

	// Same UserID and SessionID under both tenants: the worst case.
	const sharedUser, sharedSession = "operator-1", "sess-1"
	if _, err := scoped.Create(tenantA, &adksession.CreateRequest{UserID: sharedUser, SessionID: sharedSession}); err != nil {
		t.Fatalf("create under tenant A: %v", err)
	}

	got, err := scoped.Get(tenantB, &adksession.GetRequest{UserID: sharedUser, SessionID: sharedSession})
	if err == nil && got != nil && got.Session != nil {
		t.Fatal("tenant B read tenant A's session")
	}

	// Tenant A must still see its own.
	own, err := scoped.Get(tenantA, &adksession.GetRequest{UserID: sharedUser, SessionID: sharedSession})
	if err != nil {
		t.Fatalf("tenant A cannot read its own session: %v", err)
	}
	if own == nil || own.Session == nil {
		t.Fatal("tenant A's own session is missing")
	}
}

// TestSessionsRefuseWithoutTenant is the fail-closed half. A context with no
// tenant must be an error, never a fallback to a shared namespace: silently
// sharing is exactly the leak this type exists to prevent.
func TestSessionsRefuseWithoutTenant(t *testing.T) {
	scoped := NewTenantScopedSessionService(adksession.InMemoryService(), testAppName)
	ctx := context.Background()

	if _, err := scoped.Create(ctx, &adksession.CreateRequest{UserID: "u", SessionID: "s"}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("Create without tenant = %v; want ErrNoTenant", err)
	}
	if _, err := scoped.Get(ctx, &adksession.GetRequest{UserID: "u", SessionID: "s"}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("Get without tenant = %v; want ErrNoTenant", err)
	}
	if _, err := scoped.List(ctx, &adksession.ListRequest{UserID: "u"}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("List without tenant = %v; want ErrNoTenant", err)
	}
	if err := scoped.Delete(ctx, &adksession.DeleteRequest{UserID: "u", SessionID: "s"}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("Delete without tenant = %v; want ErrNoTenant", err)
	}
}

// TestSessionsIgnoreCallerSuppliedAppName stops a caller from escaping its
// namespace by setting AppName itself. The scoped service authors that field;
// whatever arrives in the request is overwritten, not merged.
func TestSessionsIgnoreCallerSuppliedAppName(t *testing.T) {
	scoped := NewTenantScopedSessionService(adksession.InMemoryService(), testAppName)
	tenantA := WithTenant(context.Background(), "ent-a")

	if _, err := scoped.Create(tenantA, &adksession.CreateRequest{
		AppName:   "gateway-agent/ent-b", // an attempt to land in another tenant
		UserID:    "operator-1",
		SessionID: "sess-escape",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Reading it back as tenant B must fail: the forged AppName was discarded.
	tenantB := WithTenant(context.Background(), "ent-b")
	got, err := scoped.Get(tenantB, &adksession.GetRequest{UserID: "operator-1", SessionID: "sess-escape"})
	if err == nil && got != nil && got.Session != nil {
		t.Fatal("a caller-supplied AppName escaped its tenant namespace")
	}
}

// TestAppendEventRefusesForeignTenantSession covers the write half of the
// boundary.
//
// AppendEvent receives the session itself, and the inner service keys the
// append by that session's own AppName - not by anything derived from ctx. A
// check that merely confirms SOME tenant is present therefore lets an append
// land in whichever namespace the session names, which is a cross-tenant
// write. The session here is a real one opened under tenant A, so the only
// thing standing between tenant B and A's conversation is the scope check.
func TestAppendEventRefusesForeignTenantSession(t *testing.T) {
	scoped := NewTenantScopedSessionService(adksession.InMemoryService(), testAppName)
	tenantA := WithTenant(context.Background(), "ent-a")
	tenantB := WithTenant(context.Background(), "ent-b")

	created, err := scoped.Create(tenantA, &adksession.CreateRequest{UserID: "operator-1", SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("create under tenant A: %v", err)
	}
	if created == nil || created.Session == nil {
		t.Fatal("create under tenant A returned no session")
	}
	sessionOfA := created.Session

	foreign := adksession.NewEvent(tenantB, "invocation-b")
	foreign.Author = "tenant-b"
	if err := scoped.AppendEvent(tenantB, sessionOfA, foreign); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("AppendEvent into tenant A's session as tenant B = %v; want ErrTenantMismatch", err)
	}

	// The refusal must be a refusal to write, not just a returned error.
	if got := eventCount(t, scoped, tenantA); got != 0 {
		t.Fatalf("tenant A's session holds %d event(s) after a refused foreign append; want 0", got)
	}

	// Tenant A must still be able to append to its own session: a check that
	// refuses everything would satisfy the assertion above while breaking the
	// only path this method exists to serve.
	own := adksession.NewEvent(tenantA, "invocation-a")
	own.Author = "tenant-a"
	if err := scoped.AppendEvent(tenantA, sessionOfA, own); err != nil {
		t.Fatalf("tenant A cannot append to its own session: %v", err)
	}
	if got := eventCount(t, scoped, tenantA); got != 1 {
		t.Fatalf("tenant A's session holds %d event(s) after its own append; want 1", got)
	}
}

// TestAppendEventAcceptsSessionFromGet guards the legitimate path against the
// check added for the foreign-tenant case.
//
// ADK's Runner resolves a session with Get (falling back to Create) and then
// appends every event of the turn against that value. Get returns a session
// carrying the stored - already scoped - AppName, so the check must pass here.
// A scope check that compared against the unscoped app name, or that refused
// any session it did not itself create, would still refuse tenant B above
// while breaking every real turn; this test is what separates the two.
func TestAppendEventAcceptsSessionFromGet(t *testing.T) {
	scoped := NewTenantScopedSessionService(adksession.InMemoryService(), testAppName)
	tenantA := WithTenant(context.Background(), "ent-a")

	if _, err := scoped.Create(tenantA, &adksession.CreateRequest{UserID: "operator-1", SessionID: "sess-1"}); err != nil {
		t.Fatalf("create under tenant A: %v", err)
	}
	// Resolve the session the way the runner does, rather than reusing the
	// value Create returned.
	got, err := scoped.Get(tenantA, &adksession.GetRequest{UserID: "operator-1", SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("get under tenant A: %v", err)
	}

	event := adksession.NewEvent(tenantA, "invocation-a")
	event.Author = "tenant-a"
	if err := scoped.AppendEvent(tenantA, got.Session, event); err != nil {
		t.Fatalf("append to a session resolved via Get: %v", err)
	}
	if n := eventCount(t, scoped, tenantA); n != 1 {
		t.Fatalf("session holds %d event(s) after a legitimate append; want 1", n)
	}
}

// TestAppendEventRefusesWithoutTenant is the fail-closed half for the write
// path, alongside the read paths in TestSessionsRefuseWithoutTenant.
func TestAppendEventRefusesWithoutTenant(t *testing.T) {
	scoped := NewTenantScopedSessionService(adksession.InMemoryService(), testAppName)
	tenantA := WithTenant(context.Background(), "ent-a")

	created, err := scoped.Create(tenantA, &adksession.CreateRequest{UserID: "operator-1", SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("create under tenant A: %v", err)
	}

	ctx := context.Background()
	event := adksession.NewEvent(ctx, "invocation-none")
	if err := scoped.AppendEvent(ctx, created.Session, event); !errors.Is(err, ErrNoTenant) {
		t.Errorf("AppendEvent without tenant = %v; want ErrNoTenant", err)
	}
}

// eventCount reads a tenant's session back through the scoped service and
// reports how many events it holds.
func eventCount(t *testing.T, scoped *TenantScopedSessionService, ctx context.Context) int {
	t.Helper()
	got, err := scoped.Get(ctx, &adksession.GetRequest{UserID: "operator-1", SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("read session back: %v", err)
	}
	if got == nil || got.Session == nil {
		t.Fatal("session missing on read-back")
	}
	return got.Session.Events().Len()
}

// TestListIsTenantScoped covers enumeration: a tenant must not learn that
// another tenant's sessions exist.
func TestListIsTenantScoped(t *testing.T) {
	scoped := NewTenantScopedSessionService(adksession.InMemoryService(), testAppName)
	tenantA := WithTenant(context.Background(), "ent-a")
	tenantB := WithTenant(context.Background(), "ent-b")

	for _, id := range []string{"s1", "s2"} {
		if _, err := scoped.Create(tenantA, &adksession.CreateRequest{UserID: "operator-1", SessionID: id}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	listed, err := scoped.List(tenantB, &adksession.ListRequest{UserID: "operator-1"})
	if err != nil {
		t.Fatalf("list under tenant B: %v", err)
	}
	if listed != nil && len(listed.Sessions) != 0 {
		t.Fatalf("tenant B enumerated %d of tenant A's sessions", len(listed.Sessions))
	}
}
