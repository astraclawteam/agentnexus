package policy

import (
	"context"
	"testing"
)

func TestDepartmentManagerCanViewDepartmentKnowledgeSpace(t *testing.T) {
	ctx := context.Background()
	checker := NewInMemoryOpenFGA()

	if err := checker.WriteRelation(ctx, TupleKey{
		User:     "user:manager_1",
		Relation: RelationManager,
		Object:   "department:legal",
	}); err != nil {
		t.Fatalf("write manager relation: %v", err)
	}
	if err := checker.WriteRelation(ctx, TupleKey{
		User:     "department:legal",
		Relation: RelationParent,
		Object:   "knowledge_space:legal_contracts",
	}); err != nil {
		t.Fatalf("write parent relation: %v", err)
	}

	allowed, err := checker.Check(ctx, TupleKey{
		User:     "user:manager_1",
		Relation: RelationViewer,
		Object:   "knowledge_space:legal_contracts",
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !allowed {
		t.Fatal("manager was not allowed to view department knowledge space")
	}
}

func TestUnrelatedEmployeeCannotViewRestrictedSpace(t *testing.T) {
	ctx := context.Background()
	checker := NewInMemoryOpenFGA()

	if err := checker.WriteRelation(ctx, TupleKey{
		User:     "user:manager_1",
		Relation: RelationManager,
		Object:   "department:legal",
	}); err != nil {
		t.Fatalf("write manager relation: %v", err)
	}
	if err := checker.WriteRelation(ctx, TupleKey{
		User:     "department:legal",
		Relation: RelationParent,
		Object:   "knowledge_space:legal_contracts",
	}); err != nil {
		t.Fatalf("write parent relation: %v", err)
	}

	allowed, err := checker.Check(ctx, TupleKey{
		User:     "user:employee_2",
		Relation: RelationViewer,
		Object:   "knowledge_space:legal_contracts",
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if allowed {
		t.Fatal("unrelated employee was allowed to view restricted space")
	}
}
