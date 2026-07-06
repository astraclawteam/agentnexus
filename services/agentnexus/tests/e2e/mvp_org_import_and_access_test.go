package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/manifest"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"gopkg.in/yaml.v3"
)

func TestMVPOrgImportAndAccess(t *testing.T) {
	ctx := context.Background()
	snapshot := loadJSONFixture[orgsource.Snapshot](t, "org_import", "wecom_org_sample.json")
	provider := orgsource.NewMockWeComProvider(snapshot)

	preview, err := app.BuildOrgImportPreview(ctx, provider)
	if err != nil {
		t.Fatalf("BuildOrgImportPreview returned error: %v", err)
	}
	if preview.RequiresConfirmation {
		t.Fatalf("preview requires confirmation: %+v", preview.Conflicts)
	}
	if len(preview.AutoImportableEmployeeIDs) != len(snapshot.Employees) {
		t.Fatalf("auto importable employees = %+v, want %d employees", preview.AutoImportableEmployeeIDs, len(snapshot.Employees))
	}

	iamService := iam.NewService(iam.NewMemoryStore(), iam.WithIDGenerator(sequenceIDs("org_event_1", "org_version_1")))
	enterprise, err := iamService.CreateEnterprise(ctx, iam.CreateEnterpriseInput{ID: "ent_demo", Name: "Demo Enterprise"})
	if err != nil {
		t.Fatalf("CreateEnterprise returned error: %v", err)
	}
	for _, department := range snapshot.Departments {
		if _, err := iamService.UpsertOrgUnit(ctx, iam.UpsertOrgUnitInput{
			ID:           department.ID,
			EnterpriseID: enterprise.ID,
			ParentID:     department.ParentID,
			Name:         department.Name,
			UnitType:     iam.OrgUnitTypeDepartment,
		}); err != nil {
			t.Fatalf("UpsertOrgUnit(%s) returned error: %v", department.ID, err)
		}
	}
	for _, employee := range snapshot.Employees {
		if _, err := iamService.UpsertEnterpriseUser(ctx, iam.UpsertEnterpriseUserInput{
			ID:           employee.ID,
			EnterpriseID: enterprise.ID,
			DisplayName:  employee.DisplayName,
			Email:        employee.Email,
			Phone:        employee.Phone,
		}); err != nil {
			t.Fatalf("UpsertEnterpriseUser(%s) returned error: %v", employee.ID, err)
		}
		if _, err := iamService.BindExternalIdentity(ctx, iam.BindExternalIdentityInput{
			ID:               "identity_" + employee.ID,
			EnterpriseID:     enterprise.ID,
			EnterpriseUserID: employee.ID,
			Provider:         provider.Name(),
			ExternalSubject:  employee.ID,
		}); err != nil {
			t.Fatalf("BindExternalIdentity(%s) returned error: %v", employee.ID, err)
		}
	}
	for _, membership := range snapshot.Memberships {
		if _, err := iamService.AddOrgMembership(ctx, iam.AddOrgMembershipInput{
			EnterpriseID:     enterprise.ID,
			EnterpriseUserID: membership.EmployeeID,
			OrgUnitID:        membership.DepartmentID,
			Role:             iamRole(membership.Role),
		}); err != nil {
			t.Fatalf("AddOrgMembership(%s) returned error: %v", membership.EmployeeID, err)
		}
	}
	orgVersion, err := iamService.CreateOrgVersion(ctx, iam.CreateOrgVersionInput{
		EnterpriseID:  enterprise.ID,
		VersionNumber: 1,
		SourceHash:    hashAny(snapshot),
	})
	if err != nil {
		t.Fatalf("CreateOrgVersion returned error: %v", err)
	}
	if orgVersion.VersionNumber != 1 || orgVersion.SourceEventID == "" {
		t.Fatalf("orgVersion = %+v, want version 1 with source event", orgVersion)
	}

	checker := policy.NewInMemoryOpenFGA()
	writeRelation(t, ctx, checker, policy.TupleKey{User: "user:user_ada", Relation: policy.RelationManager, Object: "department:dept_legal"})
	writeRelation(t, ctx, checker, policy.TupleKey{User: "department:dept_legal", Relation: policy.RelationParent, Object: "knowledge_space:ks_legal_contracts"})
	allowedByOrg, err := checker.Check(ctx, policy.TupleKey{User: "user:user_ada", Relation: policy.RelationViewer, Object: "knowledge_space:ks_legal_contracts"})
	if err != nil {
		t.Fatalf("OpenFGA Check returned error: %v", err)
	}
	if !allowedByOrg {
		t.Fatal("expected department manager to view legal knowledge space")
	}

	policyConfig := loadPolicyFixture(t)
	policyResult := policy.NewEvaluator(policyConfig).Evaluate(policy.Request{
		ResourceType: "knowledge_space",
		ResourceID:   "ks_legal_contracts",
		Action:       "read",
		Fields:       []string{"title", "body", "owner_email"},
	})
	if policyResult.Decision != policy.DecisionAllowWithMasking {
		t.Fatalf("policy decision = %q, want %q", policyResult.Decision, policy.DecisionAllowWithMasking)
	}
	if len(policyResult.MaskFields) != 1 || policyResult.MaskFields[0] != "owner_email" {
		t.Fatalf("mask fields = %+v, want owner_email", policyResult.MaskFields)
	}

	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	ticketService := tickets.NewService(tickets.NewMemoryStore(), tickets.WithClock(func() time.Time { return now }), tickets.WithIDGenerator(sequenceIDs("case_ticket_1", "step_grant_1")))
	caseTicket, err := ticketService.CreateCaseTicket(tickets.CreateCaseTicketInput{
		EnterpriseID: enterprise.ID,
		ActorUserID:  "user_ada",
		RequestID:    "claw_req_1",
		TraceID:      "trace_mvp_1",
		TTL:          30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateCaseTicket returned error: %v", err)
	}
	stepGrant, err := ticketService.CreateStepGrant(tickets.CreateStepGrantInput{
		EnterpriseID: enterprise.ID,
		CaseTicketID: caseTicket.ID,
		ResourceType: "knowledge_space",
		ResourceID:   "ks_legal_contracts",
		Action:       "read",
		Scopes:       policyResult.DataScope,
		TTL:          10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateStepGrant returned error: %v", err)
	}
	if ticketService.IsGrantExpired(stepGrant, now.Add(5*time.Minute)) {
		t.Fatal("step grant expired before connector read")
	}

	connectorManifest := loadConnectorManifestFixture(t)
	if err := manifest.Validate(connectorManifest); err != nil {
		t.Fatalf("manifest validation returned error: %v", err)
	}
	runtime := connectorruntime.New(connectorruntime.RuntimeConfig{
		Manifest: connectorManifest,
		SecretResolver: connectorruntime.SecretResolverFunc(func(context.Context, string) (string, error) {
			return "resolved-dev-credential", nil
		}),
	})
	connectorResult, err := runtime.Execute(ctx, connectorruntime.Request{
		Resource:      "legal_contracts",
		Operation:     "read",
		Action:        connectorruntime.ActionRead,
		Fields:        []string{"title", "body", "owner_email"},
		CredentialRef: "secret://agentnexus/dev/file-storage",
	})
	if err != nil {
		t.Fatalf("connector Execute returned error: %v", err)
	}
	if connectorResult.Adapter != "file_storage" || !connectorResult.Audit.CredentialResolved {
		t.Fatalf("connector result = %+v, want file_storage with credential resolved", connectorResult)
	}

	events := appendAuditEvents(enterprise.ID, caseTicket.ID, stepGrant.ID, connectorResult, policyResult)
	if err := audit.VerifyHashChain(events); err != nil {
		t.Fatalf("VerifyHashChain returned error: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("audit event count = %d, want 5", len(events))
	}
}

func appendAuditEvents(enterpriseID, caseTicketID, stepGrantID string, connectorResult connectorruntime.Result, policyResult policy.Result) []audit.Event {
	inputs := []audit.EventInput{
		{
			ID:           "audit_org_import",
			EnterpriseID: enterpriseID,
			ActorUserID:  "user_ada",
			Action:       "org_import",
			Decision:     string(policy.DecisionAllow),
			OutputHash:   hashString("org_version_1"),
		},
		{
			ID:           "audit_case_ticket",
			EnterpriseID: enterpriseID,
			CaseTicketID: caseTicketID,
			ActorUserID:  "user_ada",
			Action:       "create_case_ticket",
			Decision:     string(policy.DecisionAllow),
			OutputHash:   hashString(caseTicketID),
		},
		{
			ID:           "audit_policy_decision",
			EnterpriseID: enterpriseID,
			CaseTicketID: caseTicketID,
			ActorUserID:  "user_ada",
			ResourceType: "knowledge_space",
			ResourceID:   "ks_legal_contracts",
			Action:       "read",
			Decision:     string(policyResult.Decision),
			InputHash:    hashString("ks_legal_contracts:read"),
			OutputHash:   hashAny(policyResult),
		},
		{
			ID:           "audit_step_grant",
			EnterpriseID: enterpriseID,
			CaseTicketID: caseTicketID,
			StepGrantID:  stepGrantID,
			ActorUserID:  "user_ada",
			ResourceType: "knowledge_space",
			ResourceID:   "ks_legal_contracts",
			Action:       "create_step_grant",
			Decision:     string(policy.DecisionAllow),
			OutputHash:   hashString(stepGrantID),
		},
		{
			ID:                  "audit_connector_read",
			EnterpriseID:        enterpriseID,
			CaseTicketID:        caseTicketID,
			StepGrantID:         stepGrantID,
			ActorUserID:         "user_ada",
			ConnectorInstanceID: "connector_file_storage_1",
			ResourceType:        "connector_resource",
			ResourceID:          connectorResult.Resource,
			Action:              "read",
			Decision:            string(policyResult.Decision),
			InputHash:           hashAny(connectorResult.Audit),
			OutputHash:          hashAny(connectorResult.Data),
			EvidencePointer:     "file://demo/legal/contracts",
		},
	}

	events := make([]audit.Event, 0, len(inputs))
	prevHash := ""
	for _, input := range inputs {
		event := audit.NewEvent(input, prevHash)
		events = append(events, event)
		prevHash = event.EventHash
	}
	return events
}

func loadConnectorManifestFixture(t *testing.T) connector.Manifest {
	t.Helper()
	fixture := loadYAMLFixture[manifestFixture](t, "connectors", "file_storage_manifest.yaml")
	result := connector.Manifest{
		SchemaVersion: fixture.SchemaVersion,
		Name:          fixture.Name,
		Version:       fixture.Version,
	}
	for _, resource := range fixture.Resources {
		readOnly := resource.ReadOnly
		result.Resources = append(result.Resources, connector.Resource{
			Name:       resource.Name,
			Type:       resource.Type,
			ReadOnly:   &readOnly,
			File:       &connector.FileConfig{Bucket: resource.File.Bucket, Prefix: resource.File.Prefix},
			Fields:     resource.Fields,
			Operations: resource.Operations,
		})
	}
	for _, credential := range fixture.Credentials {
		result.Credentials = append(result.Credentials, connector.Credential{
			Name:          credential.Name,
			CredentialRef: credential.CredentialRef,
		})
	}
	return result
}

func loadPolicyFixture(t *testing.T) policy.Policy {
	t.Helper()
	fixture := loadYAMLFixture[policyFixture](t, "policies", "basic_policy.yaml")
	result := policy.Policy{}
	for _, rule := range fixture.Rules {
		result.Rules = append(result.Rules, policy.Rule{
			ResourceType: rule.ResourceType,
			Action:       rule.Action,
			Decision:     policy.Decision(rule.Decision),
			DataScope:    rule.DataScope,
			MaskFields:   rule.MaskFields,
			RiskLevel:    rule.RiskLevel,
		})
	}
	return result
}

func loadJSONFixture[T any](t *testing.T, parts ...string) T {
	t.Helper()
	var result T
	bytes, err := os.ReadFile(fixturePath(parts...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := json.Unmarshal(bytes, &result); err != nil {
		t.Fatalf("unmarshal JSON fixture: %v", err)
	}
	return result
}

func loadYAMLFixture[T any](t *testing.T, parts ...string) T {
	t.Helper()
	var result T
	bytes, err := os.ReadFile(fixturePath(parts...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := yaml.Unmarshal(bytes, &result); err != nil {
		t.Fatalf("unmarshal YAML fixture: %v", err)
	}
	return result
}

func fixturePath(parts ...string) string {
	pathParts := append([]string{"..", "fixtures"}, parts...)
	return filepath.Join(pathParts...)
}

func writeRelation(t *testing.T, ctx context.Context, checker policy.RelationshipChecker, tuple policy.TupleKey) {
	t.Helper()
	if err := checker.WriteRelation(ctx, tuple); err != nil {
		t.Fatalf("WriteRelation(%+v) returned error: %v", tuple, err)
	}
}

func iamRole(role orgsource.Role) iam.OrgRole {
	if role == orgsource.RoleManager {
		return iam.OrgRoleManager
	}
	return iam.OrgRoleMember
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

func hashAny(value any) string {
	bytes, _ := json.Marshal(value)
	return hashBytes(bytes)
}

func hashString(value string) string {
	return hashBytes([]byte(value))
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type manifestFixture struct {
	SchemaVersion string `yaml:"schema_version"`
	Name          string `yaml:"name"`
	Version       string `yaml:"version"`
	Resources     []struct {
		Name       string                `yaml:"name"`
		Type       string                `yaml:"type"`
		ReadOnly   bool                  `yaml:"read_only"`
		File       connector.FileConfig  `yaml:"file"`
		Fields     []connector.Field     `yaml:"fields"`
		Operations []connector.Operation `yaml:"operations"`
	} `yaml:"resources"`
	Credentials []struct {
		Name          string `yaml:"name"`
		CredentialRef string `yaml:"credential_ref"`
	} `yaml:"credentials"`
}

type policyFixture struct {
	Rules []struct {
		ResourceType string   `yaml:"resource_type"`
		Action       string   `yaml:"action"`
		Decision     string   `yaml:"decision"`
		DataScope    []string `yaml:"data_scope"`
		MaskFields   []string `yaml:"mask_fields"`
		RiskLevel    int      `yaml:"risk_level"`
	} `yaml:"rules"`
}
