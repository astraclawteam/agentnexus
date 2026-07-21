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
