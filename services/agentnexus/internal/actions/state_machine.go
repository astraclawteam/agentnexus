package actions

import "github.com/astraclawteam/agentnexus/sdk/go/runtime"

// allowedEdges is the deterministic transition table of the frozen Action
// lifecycle. Every edge not present is rejected. The table encodes the crash-
// safety invariants of GA Task 0F:
//
//   - requested -> awaiting_approval (an ApprovalPlanRef is present) OR
//     requested -> granted (no approval required; the signed RiskDecision of a
//     trusted authority is sufficient);
//   - awaiting_approval -> granted (approval evidence consumed one-shot);
//   - granted -> dispatched (the one-use grant is consumed and the outbox row is
//     written atomically before any dispatch);
//   - dispatched -> executing (the connector picked up the dispatch) OR
//     dispatched -> succeeded|failed DIRECTLY (a verified ActionReceipt may
//     complete the action without an intervening executing step — this is the
//     ONLY path the wired system exercises today: no component calls
//     MarkExecuting anywhere; ingestRuntimeActionReceipt is documented as
//     reporting the result of a dispatched action). Both dispatched->executing
//     and executing->{succeeded,failed} stay valid for a future connector-host
//     that reports pickup explicitly before the result;
//   - executing -> succeeded (ONLY a verified ActionReceipt completes an Action)
//     | failed (a bounded technical failure)
//     | result_unknown (a timeout AFTER the side effect may already have run —
//       BLIND RETRY IS FORBIDDEN);
//   - result_unknown -> reconciling -> succeeded|failed (the true outcome is
//     determined, never guessed);
//   - a compensable live state -> compensating (compensation is a separately
//     authorized new Action; the original rests in compensating);
//   - any live state -> human_takeover (escalation / cancellation-after-dispatch).
//
// Authority boundary: no edge asserts a business Outcome. `succeeded` is the
// declared TECHNICAL execution only.
var allowedEdges = map[runtime.ActionStatus]map[runtime.ActionStatus]struct{}{
	StatusRequested: {
		StatusAwaitingApproval: {},
		StatusGranted:          {},
		StatusFailed:           {},
		StatusHumanTakeover:    {},
	},
	StatusAwaitingApproval: {
		StatusGranted:       {},
		StatusFailed:        {},
		StatusHumanTakeover: {},
	},
	StatusGranted: {
		StatusDispatched:    {},
		StatusFailed:        {},
		StatusHumanTakeover: {},
	},
	StatusDispatched: {
		StatusExecuting:     {},
		StatusSucceeded:     {},
		StatusFailed:        {},
		StatusResultUnknown: {},
		StatusCompensating:  {},
		StatusHumanTakeover: {},
	},
	StatusExecuting: {
		StatusSucceeded:     {},
		StatusFailed:        {},
		StatusResultUnknown: {},
		StatusCompensating:  {},
		StatusHumanTakeover: {},
	},
	StatusResultUnknown: {
		StatusReconciling:   {},
		StatusCompensating:  {},
		StatusHumanTakeover: {},
	},
	StatusReconciling: {
		StatusSucceeded:     {},
		StatusFailed:        {},
		StatusHumanTakeover: {},
	},
	StatusSucceeded: {
		StatusCompensating:  {},
		StatusHumanTakeover: {},
	},
	StatusFailed: {
		StatusCompensating:  {},
		StatusHumanTakeover: {},
	},
	StatusCompensating: {
		StatusHumanTakeover: {},
	},
	// human_takeover is resolved out of band by a human; the runtime records no
	// further automatic edge.
	StatusHumanTakeover: {},
}

// canTransition reports whether from -> to is an allowed edge.
func canTransition(from, to runtime.ActionStatus) bool {
	targets, ok := allowedEdges[from]
	if !ok {
		return false
	}
	_, ok = targets[to]
	return ok
}

// compensable reports whether a compensation may be initiated from the current
// status: only states where a side effect may have executed (dispatched and
// beyond, excluding the resting human_takeover/compensating states).
func compensable(status runtime.ActionStatus) bool {
	switch status {
	case StatusDispatched, StatusExecuting, StatusSucceeded, StatusFailed, StatusResultUnknown, StatusReconciling:
		return true
	}
	return false
}

// terminalReceiptStatus maps a connector receipt status onto the executing->X
// completion edge. Only succeeded/failed are terminal execution outcomes; any
// other status on an ingested result is rejected.
func terminalReceiptStatus(status runtime.ActionStatus) (runtime.ActionStatus, bool) {
	switch status {
	case StatusSucceeded, StatusFailed:
		return status, true
	}
	return "", false
}
