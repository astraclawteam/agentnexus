package e2e_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/authorization"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

func TestRuntimePolicyTicketAudit(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

	checker := authorization.NewInMemoryRelationshipChecker()
	writeRuntimeRelation(t, ctx, checker, "user_ada", authorization.RelationViewer, "knowledge_space", "ks_legal")
	writeRuntimeRelation(t, ctx, checker, "user_ada", authorization.RelationViewer, "connector_resource", "payroll")

	auditLog := audit.NewHashChainLog(audit.WithIDGenerator(sequenceIDs(
		"audit_locate",
		"audit_read_policy",
		"audit_read_grant",
		"audit_read_connector",
		"audit_read_masking",
		"audit_deny_relation",
		"audit_receipt_wait",
	)))
	runtime := app.NewAuthorizedRuntimeAPI(app.AuthorizedRuntimeConfig{
		Authorizer: authorization.NewAuthorizer(checker),
		PolicyEvaluator: policy.NewEvaluator(policy.Policy{Rules: []policy.Rule{
			{
				ResourceType: "knowledge_space",
				Action:       "read",
				Decision:     policy.DecisionAllowWithMasking,
				DataScope:    []string{"department:legal"},
				MaskFields:   []string{"owner_email"},
				RiskLevel:    policy.RiskMedium,
			},
			{
				ResourceType: "connector_resource",
				Action:       "export",
				Decision:     policy.DecisionNeedExternalReceipt,
				DataScope:    []string{"finance:payroll"},
				RiskLevel:    policy.RiskHigh,
			},
		}}),
		TicketService: tickets.NewService(
			tickets.NewMemoryStore(),
			tickets.WithClock(func() time.Time { return now }),
			tickets.WithIDGenerator(sequenceIDs("case_ticket_1", "step_grant_1")),
		),
		AuditSink: auditLog,
		DataProvider: app.StaticRuntimeDataProvider{ReadData: map[string]any{
			"title":       "Legal Contract",
			"body":        "Agreement body",
			"owner_email": "owner@example.test",
		}},
	})

	locate, err := runtime.Locate(nil, app.RuntimeLocateRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_ada", RequestID: "req_locate", TraceID: "trace_1"},
		Intent:          "find legal contracts",
		ResourceTypes:   []string{"knowledge_space"},
	})
	if err != nil {
		t.Fatalf("Locate returned error: %v", err)
	}
	if locate.CaseTicketID != "case_ticket_1" {
		t.Fatalf("CaseTicketID = %q, want case_ticket_1", locate.CaseTicketID)
	}

	allowedRead, err := runtime.Read(nil, app.RuntimeReadRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_ada", RequestID: "req_read", TraceID: "trace_1"},
		CaseTicketID:    locate.CaseTicketID,
		Resource:        app.RuntimeResourceRef{Type: "knowledge_space", ID: "ks_legal"},
		Fields:          []string{"title", "owner_email"},
	})
	if err != nil {
		t.Fatalf("Read allowed returned error: %v", err)
	}
	if allowedRead.Decision != string(policy.DecisionAllowWithMasking) {
		t.Fatalf("Read decision = %q, want allow_with_masking", allowedRead.Decision)
	}
	if allowedRead.StepGrantID != "step_grant_1" {
		t.Fatalf("StepGrantID = %q, want step_grant_1", allowedRead.StepGrantID)
	}
	if allowedRead.Data["owner_email"] != app.MaskedValue {
		t.Fatalf("owner_email = %v, want masked value", allowedRead.Data["owner_email"])
	}

	deniedRead, err := runtime.Read(nil, app.RuntimeReadRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_bob", RequestID: "req_denied"},
		CaseTicketID:    locate.CaseTicketID,
		Resource:        app.RuntimeResourceRef{Type: "knowledge_space", ID: "ks_legal"},
		Fields:          []string{"title"},
	})
	if err != nil {
		t.Fatalf("Read denied returned error: %v", err)
	}
	if deniedRead.Decision != string(policy.DecisionDeny) || deniedRead.Data != nil {
		t.Fatalf("denied read = %+v, want deny without data", deniedRead)
	}

	waiting, err := runtime.Act(nil, app.RuntimeActRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_ada", RequestID: "req_export"},
		CaseTicketID:    locate.CaseTicketID,
		Resource:        app.RuntimeResourceRef{Type: "connector_resource", ID: "payroll"},
		Action:          "export",
	})
	if err != nil {
		t.Fatalf("Act receipt-wait returned error: %v", err)
	}
	if waiting.Decision != string(policy.DecisionNeedExternalReceipt) || waiting.WaitingExternalReceiptID == "" {
		t.Fatalf("waiting action = %+v, want receipt wait", waiting)
	}

	if err := audit.VerifyHashChain(auditLog.Events()); err != nil {
		t.Fatalf("audit hash chain failed: %v", err)
	}
}

func TestRuntimeHighRiskAuditFailClosed(t *testing.T) {
	checker := authorization.NewInMemoryRelationshipChecker()
	writeRuntimeRelation(t, context.Background(), checker, "user_ada", authorization.RelationViewer, "connector_resource", "payroll")
	ticketService := tickets.NewService(tickets.NewMemoryStore(), tickets.WithIDGenerator(sequenceIDs("case_ticket_1", "grant_ignored")))
	if _, err := ticketService.CreateCaseTicket(tickets.CreateCaseTicketInput{
		EnterpriseID: "ent_1",
		ActorUserID:  "user_ada",
		RequestID:    "req_locate",
		TTL:          30 * time.Minute,
	}); err != nil {
		t.Fatalf("CreateCaseTicket returned error: %v", err)
	}

	runtime := app.NewAuthorizedRuntimeAPI(app.AuthorizedRuntimeConfig{
		Authorizer: authorization.NewAuthorizer(checker),
		PolicyEvaluator: policy.NewEvaluator(policy.Policy{Rules: []policy.Rule{{
			ResourceType: "connector_resource",
			Action:       "export",
			Decision:     policy.DecisionAllow,
			RiskLevel:    policy.RiskHigh,
		}}}),
		TicketService: ticketService,
		AuditSink:     failingAuditSink{err: errors.New("audit unavailable")},
		DataProvider: app.StaticRuntimeDataProvider{ActResult: map[string]any{
			"export_id": "export_1",
		}},
	})

	resp, err := runtime.Act(nil, app.RuntimeActRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_ada", RequestID: "req_export"},
		CaseTicketID:    "case_ticket_1",
		Resource:        app.RuntimeResourceRef{Type: "connector_resource", ID: "payroll"},
		Action:          "export",
	})
	if err == nil {
		t.Fatal("Act returned nil error when high-risk audit append failed")
	}
	if resp.Decision != string(policy.DecisionDeny) || resp.Result != nil {
		t.Fatalf("fail-closed response = %+v, want deny without result", resp)
	}
}

func TestRuntimeAuditFailureAlwaysFailClosed(t *testing.T) {
	checker := authorization.NewInMemoryRelationshipChecker()
	writeRuntimeRelation(t, context.Background(), checker, "user_ada", authorization.RelationViewer, "knowledge_space", "ks_legal")
	ticketService := tickets.NewService(tickets.NewMemoryStore(), tickets.WithIDGenerator(sequenceIDs("case_ticket_1", "grant_ignored")))
	if _, err := ticketService.CreateCaseTicket(tickets.CreateCaseTicketInput{
		EnterpriseID: "ent_1",
		ActorUserID:  "user_ada",
		RequestID:    "req_locate",
		TTL:          30 * time.Minute,
	}); err != nil {
		t.Fatalf("CreateCaseTicket returned error: %v", err)
	}

	runtime := app.NewAuthorizedRuntimeAPI(app.AuthorizedRuntimeConfig{
		Authorizer: authorization.NewAuthorizer(checker),
		PolicyEvaluator: policy.NewEvaluator(policy.Policy{Rules: []policy.Rule{{
			ResourceType: "knowledge_space",
			Action:       "read",
			Decision:     policy.DecisionAllow,
			RiskLevel:    policy.RiskLow,
		}}}),
		TicketService: ticketService,
		AuditSink:     failingAuditSink{err: errors.New("audit unavailable")},
		DataProvider:  app.StaticRuntimeDataProvider{ReadData: map[string]any{"title": "Legal Contract"}},
	})

	resp, err := runtime.Read(nil, app.RuntimeReadRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_ada", RequestID: "req_read"},
		CaseTicketID:    "case_ticket_1",
		Resource:        app.RuntimeResourceRef{Type: "knowledge_space", ID: "ks_legal"},
		Fields:          []string{"title"},
	})
	if err == nil {
		t.Fatal("Read returned nil error when audit append failed")
	}
	if resp.Decision != string(policy.DecisionDeny) || resp.Data != nil {
		t.Fatalf("fail-closed response = %+v, want deny without data", resp)
	}
}

func TestRuntimeRejectsExpiredCaseTicket(t *testing.T) {
	checker := authorization.NewInMemoryRelationshipChecker()
	writeRuntimeRelation(t, context.Background(), checker, "user_ada", authorization.RelationViewer, "knowledge_space", "ks_legal")
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	ticketService := tickets.NewService(
		tickets.NewMemoryStore(),
		tickets.WithClock(func() time.Time { return now }),
		tickets.WithIDGenerator(sequenceIDs("case_ticket_1")),
	)
	if _, err := ticketService.CreateCaseTicket(tickets.CreateCaseTicketInput{
		EnterpriseID: "ent_1",
		ActorUserID:  "user_ada",
		RequestID:    "req_locate",
		TTL:          time.Minute,
	}); err != nil {
		t.Fatalf("CreateCaseTicket returned error: %v", err)
	}
	now = now.Add(2 * time.Minute)

	runtime := app.NewAuthorizedRuntimeAPI(app.AuthorizedRuntimeConfig{
		Authorizer: authorization.NewAuthorizer(checker),
		PolicyEvaluator: policy.NewEvaluator(policy.Policy{Rules: []policy.Rule{{
			ResourceType: "knowledge_space",
			Action:       "read",
			Decision:     policy.DecisionAllow,
			RiskLevel:    policy.RiskLow,
		}}}),
		TicketService: ticketService,
		AuditSink:     audit.NewHashChainLog(),
		DataProvider:  app.StaticRuntimeDataProvider{ReadData: map[string]any{"title": "Legal Contract"}},
	})

	resp, err := runtime.Read(nil, app.RuntimeReadRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_ada", RequestID: "req_read"},
		CaseTicketID:    "case_ticket_1",
		Resource:        app.RuntimeResourceRef{Type: "knowledge_space", ID: "ks_legal"},
		Fields:          []string{"title"},
	})
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if resp.Decision != string(policy.DecisionDeny) || resp.Data != nil {
		t.Fatalf("expired ticket response = %+v, want deny without data", resp)
	}
}

func TestRuntimeRejectsUnknownCaseTicket(t *testing.T) {
	checker := authorization.NewInMemoryRelationshipChecker()
	writeRuntimeRelation(t, context.Background(), checker, "user_ada", authorization.RelationViewer, "knowledge_space", "ks_legal")

	runtime := app.NewAuthorizedRuntimeAPI(app.AuthorizedRuntimeConfig{
		Authorizer: authorization.NewAuthorizer(checker),
		PolicyEvaluator: policy.NewEvaluator(policy.Policy{Rules: []policy.Rule{{
			ResourceType: "knowledge_space",
			Action:       "read",
			Decision:     policy.DecisionAllow,
			RiskLevel:    policy.RiskLow,
		}}}),
		TicketService: tickets.NewService(tickets.NewMemoryStore()),
		AuditSink:     audit.NewHashChainLog(),
		DataProvider:  app.StaticRuntimeDataProvider{ReadData: map[string]any{"title": "Legal Contract"}},
	})

	resp, err := runtime.Read(nil, app.RuntimeReadRequest{
		RequestEnvelope: app.RequestEnvelope{EnterpriseID: "ent_1", ActorUserID: "user_ada", RequestID: "req_read"},
		CaseTicketID:    "missing_ticket",
		Resource:        app.RuntimeResourceRef{Type: "knowledge_space", ID: "ks_legal"},
		Fields:          []string{"title"},
	})
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if resp.Decision != string(policy.DecisionDeny) || resp.Data != nil {
		t.Fatalf("unknown ticket response = %+v, want deny without data", resp)
	}
}

type failingAuditSink struct {
	err error
}

func (s failingAuditSink) Append(context.Context, audit.EventInput) (audit.Event, error) {
	return audit.Event{}, s.err
}

func writeRuntimeRelation(t *testing.T, ctx context.Context, checker *authorization.InMemoryRelationshipChecker, userID, relation, resourceType, resourceID string) {
	t.Helper()
	if err := checker.Write(ctx, authorization.RelationshipTuple{
		UserID:       userID,
		Relation:     relation,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}); err != nil {
		t.Fatalf("write relation: %v", err)
	}
}
