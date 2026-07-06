package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/authorization"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

const MaskedValue = "***MASKED***"

type RuntimePolicyEvaluator interface {
	Evaluate(policy.Request) policy.Result
}

type RuntimeDataProvider interface {
	Read(context.Context, RuntimeReadRequest) (map[string]any, error)
	Act(context.Context, RuntimeActRequest) (map[string]any, error)
}

type AuthorizedRuntimeConfig struct {
	Authorizer       authorization.Authorizer
	PolicyEvaluator  RuntimePolicyEvaluator
	TicketService    *tickets.Service
	AuditSink        audit.Sink
	DataProvider     RuntimeDataProvider
	TaskOrchestrator *tasks.Orchestrator
}

type AuthorizedRuntimeAPI struct {
	authorizer       authorization.Authorizer
	policyEvaluator  RuntimePolicyEvaluator
	ticketService    *tickets.Service
	auditSink        audit.Sink
	dataProvider     RuntimeDataProvider
	taskOrchestrator *tasks.Orchestrator
}

func NewAuthorizedRuntimeAPI(cfg AuthorizedRuntimeConfig) *AuthorizedRuntimeAPI {
	return &AuthorizedRuntimeAPI{
		authorizer:       cfg.Authorizer,
		policyEvaluator:  cfg.PolicyEvaluator,
		ticketService:    cfg.TicketService,
		auditSink:        cfg.AuditSink,
		dataProvider:     cfg.DataProvider,
		taskOrchestrator: cfg.TaskOrchestrator,
	}
}

func NewDefaultAuthorizedRuntimeAPI() *AuthorizedRuntimeAPI {
	checker := authorization.NewInMemoryRelationshipChecker()
	_ = checker.Write(context.Background(), authorization.RelationshipTuple{
		UserID:       "dev_user",
		Relation:     authorization.RelationViewer,
		ResourceType: "connector_resource",
		ResourceID:   "resource_dev_preview",
	})
	return NewAuthorizedRuntimeAPI(AuthorizedRuntimeConfig{
		Authorizer: authorization.NewAuthorizer(checker),
		PolicyEvaluator: policy.NewEvaluator(policy.Policy{Rules: []policy.Rule{{
			ResourceType: "connector_resource",
			Action:       "read",
			Decision:     policy.DecisionAllow,
			RiskLevel:    policy.RiskLow,
		}, {
			ResourceType: "connector_resource",
			Action:       "act",
			Decision:     policy.DecisionAllow,
			RiskLevel:    policy.RiskLow,
		}}}),
		TicketService:    tickets.NewService(tickets.NewMemoryStore()),
		AuditSink:        audit.NewHashChainLog(),
		TaskOrchestrator: tasks.NewOrchestrator(tasks.NewMemoryStore(), nil),
		DataProvider: StaticRuntimeDataProvider{ReadData: map[string]any{
			"resource_id": "resource_dev_preview",
		}},
	})
}

func (api *AuthorizedRuntimeAPI) Locate(r *http.Request, req RuntimeLocateRequest) (RuntimeLocateResponse, error) {
	if api.ticketService == nil {
		return RuntimeLocateResponse{}, fmt.Errorf("ticket service is required")
	}
	ctx := requestContext(r)
	taskRunID, err := api.createTaskRun(ctx, req)
	if err != nil {
		return RuntimeLocateResponse{}, err
	}
	ticket, err := api.ticketService.CreateCaseTicket(tickets.CreateCaseTicketInput{
		EnterpriseID: req.EnterpriseID,
		ActorUserID:  req.ActorUserID,
		RequestID:    req.RequestID,
		TraceID:      req.TraceID,
		TTL:          30 * time.Minute,
	})
	if err != nil {
		return RuntimeLocateResponse{}, err
	}
	if err := api.appendAudit(ctx, policy.RiskLow, audit.EventInput{
		EnterpriseID: req.EnterpriseID,
		CaseTicketID: ticket.ID,
		ActorUserID:  req.ActorUserID,
		Action:       "locate",
		Decision:     string(policy.DecisionAllow),
		InputHash:    hashRuntimeValue(req),
		OutputHash:   hashRuntimeValue(ticket),
	}); err != nil {
		return RuntimeLocateResponse{}, err
	}

	resourceType := "connector_resource"
	if len(req.ResourceTypes) > 0 && req.ResourceTypes[0] != "" {
		resourceType = req.ResourceTypes[0]
	}
	return RuntimeLocateResponse{
		CaseTicketID: ticket.ID,
		TaskRunID:    taskRunID,
		Resources: []RuntimeLocatedResource{{
			Resource: RuntimeResourceRef{
				Type: resourceType,
				ID:   "resource_dev_preview",
			},
			Summary: "runtime location requires authorization before read or act",
		}},
	}, nil
}

func (api *AuthorizedRuntimeAPI) createTaskRun(ctx context.Context, req RuntimeLocateRequest) (string, error) {
	if api.taskOrchestrator == nil {
		return "", nil
	}
	run, err := api.taskOrchestrator.CreateTaskRun(ctx, tasks.CreateTaskRunInput{
		EnterpriseID: req.EnterpriseID,
		ActorUserID:  req.ActorUserID,
		RequestID:    req.RequestID,
		TraceID:      req.TraceID,
	})
	if err != nil {
		return "", err
	}
	return run.ID, nil
}

func (api *AuthorizedRuntimeAPI) Read(r *http.Request, req RuntimeReadRequest) (RuntimeReadResponse, error) {
	if req.CaseTicketID == "" {
		return RuntimeReadResponse{}, fmt.Errorf("case_ticket_id is required")
	}
	ctx := requestContext(r)
	if !api.hasActiveCaseTicket(req.EnterpriseID, req.CaseTicketID) {
		_ = api.appendAudit(ctx, policy.RiskLow, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       "read",
			Decision:     string(policy.DecisionDeny),
			InputHash:    hashRuntimeValue(req),
		})
		return RuntimeReadResponse{Decision: string(policy.DecisionDeny)}, nil
	}
	allowed, err := api.authorizer.CanView(ctx, authorization.RelationshipTuple{
		UserID:       req.ActorUserID,
		ResourceType: req.Resource.Type,
		ResourceID:   req.Resource.ID,
	})
	if err != nil {
		return RuntimeReadResponse{}, err
	}
	if !allowed {
		_ = api.appendAudit(ctx, policy.RiskLow, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       "read",
			Decision:     string(policy.DecisionDeny),
			InputHash:    hashRuntimeValue(req),
		})
		return RuntimeReadResponse{Decision: string(policy.DecisionDeny)}, nil
	}

	result := api.evaluatePolicy(policy.Request{
		ResourceType: req.Resource.Type,
		ResourceID:   req.Resource.ID,
		Action:       "read",
		Fields:       req.Fields,
	})
	if result.Decision == policy.DecisionDeny {
		_ = api.appendAudit(ctx, result.RiskLevel, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       "read",
			Decision:     string(policy.DecisionDeny),
			InputHash:    hashRuntimeValue(req),
			OutputHash:   hashRuntimeValue(result),
		})
		return RuntimeReadResponse{Decision: string(policy.DecisionDeny)}, nil
	}
	if result.Decision == policy.DecisionNeedExternalReceipt {
		waitID := runtimeID("external_receipt", req.EnterpriseID, req.RequestID)
		if err := api.appendAudit(ctx, result.RiskLevel, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       "receipt_wait",
			Decision:     string(result.Decision),
			InputHash:    hashRuntimeValue(req),
			OutputHash:   hashRuntimeValue(waitID),
		}); err != nil {
			return RuntimeReadResponse{Decision: string(policy.DecisionDeny)}, err
		}
		return RuntimeReadResponse{Decision: string(result.Decision), WaitingExternalReceiptID: waitID}, nil
	}

	return api.readAllowed(ctx, req, result)
}

func (api *AuthorizedRuntimeAPI) Act(r *http.Request, req RuntimeActRequest) (RuntimeActResponse, error) {
	if req.CaseTicketID == "" {
		return RuntimeActResponse{}, fmt.Errorf("case_ticket_id is required")
	}
	ctx := requestContext(r)
	if !api.hasActiveCaseTicket(req.EnterpriseID, req.CaseTicketID) {
		_ = api.appendAudit(ctx, policy.RiskLow, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       req.Action,
			Decision:     string(policy.DecisionDeny),
			InputHash:    hashRuntimeValue(req),
		})
		return RuntimeActResponse{Decision: string(policy.DecisionDeny)}, nil
	}
	allowed, err := api.authorizer.CanView(ctx, authorization.RelationshipTuple{
		UserID:       req.ActorUserID,
		ResourceType: req.Resource.Type,
		ResourceID:   req.Resource.ID,
	})
	if err != nil {
		return RuntimeActResponse{}, err
	}
	if !allowed {
		_ = api.appendAudit(ctx, policy.RiskLow, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       req.Action,
			Decision:     string(policy.DecisionDeny),
			InputHash:    hashRuntimeValue(req),
		})
		return RuntimeActResponse{Decision: string(policy.DecisionDeny)}, nil
	}

	result := api.evaluatePolicy(policy.Request{
		ResourceType: req.Resource.Type,
		ResourceID:   req.Resource.ID,
		Action:       req.Action,
	})
	if result.Decision == policy.DecisionDeny {
		_ = api.appendAudit(ctx, result.RiskLevel, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       req.Action,
			Decision:     string(policy.DecisionDeny),
			InputHash:    hashRuntimeValue(req),
			OutputHash:   hashRuntimeValue(result),
		})
		return RuntimeActResponse{Decision: string(policy.DecisionDeny)}, nil
	}
	if result.Decision == policy.DecisionNeedExternalReceipt {
		waitID := runtimeID("external_receipt", req.EnterpriseID, req.RequestID)
		if err := api.appendAudit(ctx, result.RiskLevel, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       "receipt_wait",
			Decision:     string(result.Decision),
			InputHash:    hashRuntimeValue(req),
			OutputHash:   hashRuntimeValue(waitID),
		}); err != nil {
			return RuntimeActResponse{Decision: string(policy.DecisionDeny)}, err
		}
		return RuntimeActResponse{Decision: string(result.Decision), WaitingExternalReceiptID: waitID}, nil
	}

	return api.actAllowed(ctx, req, result)
}

func (api *AuthorizedRuntimeAPI) GetTicket(_ *http.Request, id string) (RuntimeTicketResponse, error) {
	if id == "" {
		return RuntimeTicketResponse{}, fmt.Errorf("ticket id is required")
	}
	return RuntimeTicketResponse{CaseTicketID: id, Status: tickets.TicketStatusActive}, nil
}

func (api *AuthorizedRuntimeAPI) readAllowed(ctx context.Context, req RuntimeReadRequest, result policy.Result) (RuntimeReadResponse, error) {
	grant, err := api.createGrant(req.EnterpriseID, req.CaseTicketID, req.Resource, "read", result)
	if err != nil {
		return RuntimeReadResponse{}, err
	}
	if err := api.appendDecisionAndGrantAudit(ctx, result.RiskLevel, req.RequestEnvelope, req.CaseTicketID, grant.ID, req.Resource, "read", result); err != nil {
		return RuntimeReadResponse{Decision: string(policy.DecisionDeny)}, err
	}

	data, err := api.readData(ctx, req)
	if err != nil {
		return RuntimeReadResponse{}, err
	}
	data = selectFields(data, req.Fields)
	if result.Decision == policy.DecisionAllowWithMasking {
		data = maskFields(data, result.MaskFields)
	}
	if err := api.appendAudit(ctx, result.RiskLevel, audit.EventInput{
		EnterpriseID:        req.EnterpriseID,
		CaseTicketID:        req.CaseTicketID,
		StepGrantID:         grant.ID,
		ActorUserID:         req.ActorUserID,
		ConnectorInstanceID: req.Resource.ConnectorInstanceID,
		ResourceType:        req.Resource.Type,
		ResourceID:          req.Resource.ID,
		Action:              "connector_read",
		Decision:            string(result.Decision),
		InputHash:           hashRuntimeValue(req),
		OutputHash:          hashRuntimeValue(data),
	}); err != nil {
		return RuntimeReadResponse{Decision: string(policy.DecisionDeny)}, err
	}
	if result.Decision == policy.DecisionAllowWithMasking {
		if err := api.appendAudit(ctx, result.RiskLevel, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			StepGrantID:  grant.ID,
			ActorUserID:  req.ActorUserID,
			ResourceType: req.Resource.Type,
			ResourceID:   req.Resource.ID,
			Action:       "masking",
			Decision:     string(result.Decision),
			InputHash:    hashRuntimeValue(result.MaskFields),
			OutputHash:   hashRuntimeValue(data),
		}); err != nil {
			return RuntimeReadResponse{Decision: string(policy.DecisionDeny)}, err
		}
	}
	return RuntimeReadResponse{Decision: string(result.Decision), StepGrantID: grant.ID, Data: data}, nil
}

func (api *AuthorizedRuntimeAPI) actAllowed(ctx context.Context, req RuntimeActRequest, result policy.Result) (RuntimeActResponse, error) {
	grant, err := api.createGrant(req.EnterpriseID, req.CaseTicketID, req.Resource, req.Action, result)
	if err != nil {
		return RuntimeActResponse{}, err
	}
	if err := api.appendDecisionAndGrantAudit(ctx, result.RiskLevel, req.RequestEnvelope, req.CaseTicketID, grant.ID, req.Resource, req.Action, result); err != nil {
		return RuntimeActResponse{Decision: string(policy.DecisionDeny)}, err
	}
	actionResult, err := api.actData(ctx, req)
	if err != nil {
		return RuntimeActResponse{}, err
	}
	if err := api.appendAudit(ctx, result.RiskLevel, audit.EventInput{
		EnterpriseID:        req.EnterpriseID,
		CaseTicketID:        req.CaseTicketID,
		StepGrantID:         grant.ID,
		ActorUserID:         req.ActorUserID,
		ConnectorInstanceID: req.Resource.ConnectorInstanceID,
		ResourceType:        req.Resource.Type,
		ResourceID:          req.Resource.ID,
		Action:              req.Action,
		Decision:            string(result.Decision),
		InputHash:           hashRuntimeValue(req),
		OutputHash:          hashRuntimeValue(actionResult),
	}); err != nil {
		return RuntimeActResponse{Decision: string(policy.DecisionDeny)}, err
	}
	return RuntimeActResponse{Decision: string(result.Decision), StepGrantID: grant.ID, Result: actionResult}, nil
}

func (api *AuthorizedRuntimeAPI) evaluatePolicy(req policy.Request) policy.Result {
	if api.policyEvaluator == nil {
		return policy.Result{Decision: policy.DecisionDeny, RiskLevel: policy.RiskHigh}
	}
	return api.policyEvaluator.Evaluate(req)
}

func (api *AuthorizedRuntimeAPI) createGrant(enterpriseID, caseTicketID string, resource RuntimeResourceRef, action string, result policy.Result) (tickets.StepGrant, error) {
	if api.ticketService == nil {
		return tickets.StepGrant{}, fmt.Errorf("ticket service is required")
	}
	return api.ticketService.CreateStepGrant(tickets.CreateStepGrantInput{
		EnterpriseID: enterpriseID,
		CaseTicketID: caseTicketID,
		ResourceType: resource.Type,
		ResourceID:   resource.ID,
		Action:       action,
		Scopes:       result.DataScope,
		TTL:          10 * time.Minute,
	})
}

func (api *AuthorizedRuntimeAPI) hasActiveCaseTicket(enterpriseID, caseTicketID string) bool {
	if api.ticketService == nil {
		return false
	}
	ticket, err := api.ticketService.GetCaseTicket(enterpriseID, caseTicketID)
	if err != nil {
		return false
	}
	return api.ticketService.IsTicketActive(ticket)
}

func (api *AuthorizedRuntimeAPI) appendDecisionAndGrantAudit(ctx context.Context, risk int, envelope RequestEnvelope, caseTicketID, stepGrantID string, resource RuntimeResourceRef, action string, result policy.Result) error {
	if err := api.appendAudit(ctx, risk, audit.EventInput{
		EnterpriseID: envelope.EnterpriseID,
		CaseTicketID: caseTicketID,
		ActorUserID:  envelope.ActorUserID,
		ResourceType: resource.Type,
		ResourceID:   resource.ID,
		Action:       action,
		Decision:     string(result.Decision),
		InputHash:    hashRuntimeValue(resource),
		OutputHash:   hashRuntimeValue(result),
	}); err != nil {
		return err
	}
	return api.appendAudit(ctx, risk, audit.EventInput{
		EnterpriseID: envelope.EnterpriseID,
		CaseTicketID: caseTicketID,
		StepGrantID:  stepGrantID,
		ActorUserID:  envelope.ActorUserID,
		ResourceType: resource.Type,
		ResourceID:   resource.ID,
		Action:       "create_step_grant",
		Decision:     string(policy.DecisionAllow),
		OutputHash:   hashRuntimeValue(stepGrantID),
	})
}

func (api *AuthorizedRuntimeAPI) appendAudit(ctx context.Context, risk int, input audit.EventInput) error {
	if api.auditSink == nil {
		return fmt.Errorf("audit sink is required for runtime action")
	}
	if _, err := api.auditSink.Append(ctx, input); err != nil {
		return fmt.Errorf("audit append failed for runtime action: %w", err)
	}
	return nil
}

func (api *AuthorizedRuntimeAPI) readData(ctx context.Context, req RuntimeReadRequest) (map[string]any, error) {
	if api.dataProvider == nil {
		return map[string]any{"resource_id": req.Resource.ID}, nil
	}
	return api.dataProvider.Read(ctx, req)
}

func (api *AuthorizedRuntimeAPI) actData(ctx context.Context, req RuntimeActRequest) (map[string]any, error) {
	if api.dataProvider == nil {
		return map[string]any{"resource_id": req.Resource.ID, "action": req.Action}, nil
	}
	return api.dataProvider.Act(ctx, req)
}

func requestContext(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return r.Context()
}

func selectFields(data map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return cloneMap(data)
	}
	result := map[string]any{}
	for _, field := range fields {
		if value, ok := data[field]; ok {
			result[field] = value
		}
	}
	return result
}

func maskFields(data map[string]any, fields []string) map[string]any {
	result := cloneMap(data)
	for _, field := range fields {
		if _, ok := result[field]; ok {
			result[field] = MaskedValue
		}
	}
	return result
}

func cloneMap(data map[string]any) map[string]any {
	result := make(map[string]any, len(data))
	for key, value := range data {
		result[key] = value
	}
	return result
}

type StaticRuntimeDataProvider struct {
	ReadData  map[string]any
	ActResult map[string]any
}

func (p StaticRuntimeDataProvider) Read(context.Context, RuntimeReadRequest) (map[string]any, error) {
	return cloneMap(p.ReadData), nil
}

func (p StaticRuntimeDataProvider) Act(_ context.Context, req RuntimeActRequest) (map[string]any, error) {
	if len(p.ActResult) > 0 {
		return cloneMap(p.ActResult), nil
	}
	return map[string]any{"resource_id": req.Resource.ID, "action": req.Action}, nil
}
