package agent

import (
	"context"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
)

// runOnHost executes ONE resolved connector operation at the customer edge. It
// assembles the operation the SAME way the central Worker does
// (worker.BuildHostOperation), runs it through the shared isolated host — the
// connector and its operation-scoped Secret Handle stay LOCAL — and classifies
// the outcome with the Worker's provenance rules (worker.ClassifyHostResult).
//
// This is the whole of Task 6's executor: there is NO Agent-supplied connector
// id, no dynamic code and no forked operation assembly or provenance. The legacy
// runtime.Runtime / ConnectorInstanceID / DynamicCode path is retired.
func runOnHost(ctx context.Context, rb worker.ResolvedBinding, action actions.Action, msg actions.DispatchMessage) (host.Result, runtime.ActionStatus, bool) {
	op := worker.BuildHostOperation(action, msg, rb)
	result := rb.Host.Run(ctx, op)
	status, uncertain := worker.ClassifyHostResult(result.Status)
	return result, status, uncertain
}
