package integration

import (
	"context"
	"os"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

func TestOpenFGAVisibilityModel(t *testing.T) {
	if os.Getenv("AGENTNEXUS_TEST_OPENFGA_API_URL") == "" {
		t.Skip("AGENTNEXUS_TEST_OPENFGA_API_URL is not set")
	}

	ctx := context.Background()
	checker := policy.NewInMemoryOpenFGA()

	if err := checker.WriteRelation(ctx, policy.TupleKey{
		User:     "user:manager_1",
		Relation: policy.RelationManager,
		Object:   "department:legal",
	}); err != nil {
		t.Fatalf("write manager relation: %v", err)
	}
	if err := checker.WriteRelation(ctx, policy.TupleKey{
		User:     "department:legal",
		Relation: policy.RelationParent,
		Object:   "knowledge_space:legal_contracts",
	}); err != nil {
		t.Fatalf("write parent relation: %v", err)
	}

	allowed, err := checker.Check(ctx, policy.TupleKey{
		User:     "user:manager_1",
		Relation: policy.RelationViewer,
		Object:   "knowledge_space:legal_contracts",
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !allowed {
		t.Fatal("manager was not allowed to view department knowledge space")
	}
}
