package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/authorization"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/storage"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

func TestPostgresRuntimePersistsTicketAndStepGrant(t *testing.T) {
	dsn := os.Getenv("AGENTNEXUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTNEXUS_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	adminPool, err := storage.OpenPostgres(ctx, storage.PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatalf("open admin postgres pool: %v", err)
	}
	defer adminPool.Close()

	schema := fmt.Sprintf("agentnexus_runtime_ticket_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer adminPool.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)

	pool, err := storage.OpenPostgres(ctx, storage.PostgresConfig{DSN: dsn, SearchPath: schema})
	if err != nil {
		t.Fatalf("open schema postgres pool: %v", err)
	}
	defer pool.Close()
	if err := storage.ApplyEmbeddedMigrations(ctx, pool); err != nil {
		t.Fatalf("apply embedded migrations: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1, $2)`, "ent_1", "Enterprise 1"); err != nil {
		t.Fatalf("insert enterprise: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO enterprise_users (id, enterprise_id, display_name) VALUES ($1, $2, $3)`, "user_1", "ent_1", "User 1"); err != nil {
		t.Fatalf("insert enterprise user: %v", err)
	}

	checker := authorization.NewInMemoryRelationshipChecker()
	if err := checker.Write(ctx, authorization.RelationshipTuple{
		UserID:       "user_1",
		Relation:     authorization.RelationViewer,
		ResourceType: "connector_resource",
		ResourceID:   "resource_dev_preview",
	}); err != nil {
		t.Fatalf("write relation: %v", err)
	}
	runtime := app.NewAuthorizedRuntimeAPI(app.AuthorizedRuntimeConfig{
		Authorizer: authorization.NewAuthorizer(checker),
		PolicyEvaluator: policy.NewEvaluator(policy.Policy{Rules: []policy.Rule{{
			ResourceType: "connector_resource",
			Action:       "read",
			Decision:     policy.DecisionAllow,
			RiskLevel:    policy.RiskLow,
		}}}),
		TicketService: tickets.NewService(
			tickets.NewPostgresStore(pool),
			tickets.WithIDGenerator(postgresRuntimeSequenceIDs("case_ticket_1", "step_grant_1")),
		),
		AuditSink:    audit.NewHashChainLog(audit.WithIDGenerator(postgresRuntimeSequenceIDs("audit_locate", "audit_policy", "audit_grant", "audit_connector"))),
		DataProvider: app.StaticRuntimeDataProvider{ReadData: map[string]any{"title": "Contract A"}},
	})
	mux := http.NewServeMux()
	app.RegisterRuntimeAPIRoutes(mux, runtime)

	locateBody := []byte(`{"enterprise_id":"ent_1","actor_user_id":"user_1","request_id":"req_locate","intent":"find legal contracts"}`)
	locateRec := httptest.NewRecorder()
	mux.ServeHTTP(locateRec, httptest.NewRequest(http.MethodPost, "/v1/runtime/locate", bytes.NewReader(locateBody)))
	if locateRec.Code != http.StatusOK {
		t.Fatalf("locate status = %d, body = %s", locateRec.Code, locateRec.Body.String())
	}
	var locateResp struct {
		CaseTicketID string `json:"case_ticket_id"`
	}
	if err := json.Unmarshal(locateRec.Body.Bytes(), &locateResp); err != nil {
		t.Fatalf("decode locate response: %v", err)
	}

	readBody := []byte(`{
		"enterprise_id":"ent_1",
		"actor_user_id":"user_1",
		"request_id":"req_read",
		"case_ticket_id":"` + locateResp.CaseTicketID + `",
		"resource":{"type":"connector_resource","id":"resource_dev_preview","connector_instance_id":"conn_1","resource_name":"legal_contracts"},
		"fields":["title"]
	}`)
	readRec := httptest.NewRecorder()
	mux.ServeHTTP(readRec, httptest.NewRequest(http.MethodPost, "/v1/runtime/read", bytes.NewReader(readBody)))
	if readRec.Code != http.StatusOK {
		t.Fatalf("read status = %d, body = %s", readRec.Code, readRec.Body.String())
	}

	var persistedTicketStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM case_tickets WHERE id = $1 AND enterprise_id = $2`, "case_ticket_1", "ent_1").Scan(&persistedTicketStatus); err != nil {
		t.Fatalf("select case ticket: %v", err)
	}
	if persistedTicketStatus != tickets.TicketStatusActive {
		t.Fatalf("persisted ticket status = %q", persistedTicketStatus)
	}
	var persistedGrantAction string
	if err := pool.QueryRow(ctx, `SELECT action FROM step_grants WHERE id = $1 AND enterprise_id = $2`, "step_grant_1", "ent_1").Scan(&persistedGrantAction); err != nil {
		t.Fatalf("select step grant: %v", err)
	}
	if persistedGrantAction != "read" {
		t.Fatalf("persisted grant action = %q", persistedGrantAction)
	}
}

func postgresRuntimeSequenceIDs(ids ...string) func() string {
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
