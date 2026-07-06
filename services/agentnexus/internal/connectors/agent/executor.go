package agent

import (
	"context"
	"errors"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
)

var (
	ErrUnknownConnectorInstance = errors.New("unknown connector instance")
	ErrDynamicCodeRejected      = errors.New("dynamic code payload rejected")
)

type ExecutionRequest struct {
	ConnectorInstanceID string
	Resource            string
	Operation           string
	Action              runtime.Action
	Fields              []string
	CredentialRef       string
	DynamicCode         string
	Script              string
}

type ExecutionResult struct {
	Data  map[string]any
	Audit ExecutionAuditContext
}

type ExecutionAuditContext struct {
	ConnectorInstanceID string
	Resource            string
	Operation           string
	Action              runtime.Action
	Fields              []string
}

type Executor struct {
	instances map[string]*runtime.Runtime
}

func NewExecutor(instances map[string]*runtime.Runtime) *Executor {
	return &Executor{instances: instances}
}

func (e *Executor) Execute(ctx context.Context, req ExecutionRequest) (ExecutionResult, error) {
	instanceRuntime, ok := e.instances[req.ConnectorInstanceID]
	if !ok {
		return ExecutionResult{}, ErrUnknownConnectorInstance
	}
	if req.DynamicCode != "" || req.Script != "" {
		return ExecutionResult{}, ErrDynamicCodeRejected
	}

	result, err := instanceRuntime.Execute(ctx, runtime.Request{
		Resource:      req.Resource,
		Operation:     req.Operation,
		Action:        req.Action,
		Fields:        req.Fields,
		CredentialRef: req.CredentialRef,
	})
	if err != nil {
		return ExecutionResult{}, err
	}

	return ExecutionResult{
		Data: result.Data,
		Audit: ExecutionAuditContext{
			ConnectorInstanceID: req.ConnectorInstanceID,
			Resource:            result.Audit.Resource,
			Operation:           result.Audit.Operation,
			Action:              result.Audit.Action,
			Fields:              result.Audit.Fields,
		},
	}, nil
}
