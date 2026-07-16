package runtime

// db_readonly.go is the generic read-only database connector family, qualified
// to GA Product Pack v1. It executes over an INJECTED row-source/query port. The
// family is STRICTLY READ-ONLY: any write/DDL/DML intent (a write action, or an
// INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/TRUNCATE/MERGE/REPLACE/GRANT/... verb)
// is refused before any query runs (ErrReadOnlyFamily -> StatusDenied) and never
// executed. On a read it covers keyset pagination, deadline -> bounded failure,
// ACL/deletion invalidation, output-schema validation and field masking, and
// authoritative source/version/freshness metadata. It never receives a master
// credential and never leaks connector topology into its output.

import (
	"context"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
)

// writeVerbs is the frozen set of SQL write/DDL/DML leading verbs the read-only
// family refuses. Matching is on the first token, case-insensitive.
var writeVerbs = map[string]bool{
	"insert": true, "update": true, "delete": true, "drop": true, "alter": true,
	"create": true, "truncate": true, "merge": true, "replace": true, "upsert": true,
	"grant": true, "revoke": true, "call": true, "exec": true, "execute": true,
}

// DBRowPage is one keyset page the injected DB client returns.
type DBRowPage struct {
	NextKeyset    string
	Denied        bool // the source denied/rowless-invalidated the read (ACL/deletion)
	Rows          []map[string]any
	Source        string
	SourceVersion int64
	Authority     string
}

// DBQuery is one bounded read query to the injected DB client.
type DBQuery struct {
	Resource  string
	Operation string
	Keyset    string
	Auth      string
}

// DBClient is the injected read-only row-source/query port.
type DBClient interface {
	Query(ctx context.Context, q DBQuery) (DBRowPage, error)
}

// DBReadonlyAdapter is the read-only database family adapter.
type DBReadonlyAdapter struct {
	client DBClient
	now    func() time.Time
}

// NewDBReadonlyAdapter binds the family to its injected read-only DB client.
func NewDBReadonlyAdapter(client DBClient) *DBReadonlyAdapter {
	return &DBReadonlyAdapter{client: client, now: func() time.Time { return time.Unix(0, 0).UTC() }}
}

// Name identifies the family for audit.
func (*DBReadonlyAdapter) Name() string { return "db_readonly" }

// Execute refuses any write intent BEFORE any query runs (the family is strictly
// read-only), then runs a keyset-paginated, ACL-checked, masked and
// schema-validated read over the injected client, surfacing source/version/
// freshness metadata.
func (a *DBReadonlyAdapter) Execute(ctx context.Context, req FamilyRequest) (FamilyResponse, error) {
	if isWriteIntent(req.Action, req.Operation, req.Capability.Effect.IsWrite()) {
		return FamilyResponse{Status: host.StatusDenied, Reason: "read-only database family refuses a write operation"}, nil
	}
	fetch := func(ctx context.Context, token string) (pageData, error) {
		page, err := a.client.Query(ctx, DBQuery{Resource: req.Resource, Operation: req.Operation, Keyset: token, Auth: req.Auth})
		if err != nil {
			return pageData{}, err
		}
		d := pageData{
			records:       toRecords(page.Rows),
			next:          page.NextKeyset,
			denied:        page.Denied,
			source:        page.Source,
			sourceVersion: page.SourceVersion,
			authority:     page.Authority,
		}
		return d, nil
	}
	return runReadPipeline(ctx, fetch, req.FieldPolicy, sleepCtx, a.now)
}

// isWriteIntent reports whether the resolved action/operation is a write. It is
// the read-only family's single refusal predicate: a write action, a write-effect
// capability, or an operation whose leading token is a SQL write/DDL/DML verb.
func isWriteIntent(action, operation string, capabilityIsWrite bool) bool {
	if capabilityIsWrite {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(action), "write") {
		return true
	}
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(operation)))
	if len(fields) == 0 {
		return false
	}
	return writeVerbs[fields[0]]
}
