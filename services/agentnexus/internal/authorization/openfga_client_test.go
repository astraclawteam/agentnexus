package authorization

import (
	"context"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

func TestOpenFGAClientAdaptsRelationshipChecker(t *testing.T) {
	ctx := context.Background()
	checker := policy.NewInMemoryOpenFGA()
	if err := checker.WriteRelation(ctx, policy.TupleKey{User: "user:user_ada", Relation: policy.RelationManager, Object: "department:dept_legal"}); err != nil {
		t.Fatalf("WriteRelation manager returned error: %v", err)
	}
	if err := checker.WriteRelation(ctx, policy.TupleKey{User: "department:dept_legal", Relation: policy.RelationParent, Object: "knowledge_space:ks_legal"}); err != nil {
		t.Fatalf("WriteRelation parent returned error: %v", err)
	}

	client := NewOpenFGAClient(checker)
	allowed, err := client.Check(ctx, RelationshipTuple{
		UserID:       "user_ada",
		Relation:     RelationViewer,
		ResourceType: "knowledge_space",
		ResourceID:   "ks_legal",
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !allowed {
		t.Fatal("expected inherited OpenFGA viewer relation to allow access")
	}
}
