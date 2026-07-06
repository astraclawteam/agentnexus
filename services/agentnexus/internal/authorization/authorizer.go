package authorization

import (
	"context"
	"sync"
)

type Authorizer struct {
	checker RelationshipChecker
}

func NewAuthorizer(checker RelationshipChecker) Authorizer {
	return Authorizer{checker: checker}
}

func (a Authorizer) CanView(ctx context.Context, input RelationshipTuple) (bool, error) {
	if a.checker == nil {
		return false, nil
	}
	input.Relation = RelationViewer
	return a.checker.Check(ctx, input)
}

type InMemoryRelationshipChecker struct {
	mu        sync.RWMutex
	relations map[RelationshipTuple]struct{}
}

func NewInMemoryRelationshipChecker() *InMemoryRelationshipChecker {
	return &InMemoryRelationshipChecker{relations: map[RelationshipTuple]struct{}{}}
}

func (c *InMemoryRelationshipChecker) Write(_ context.Context, tuple RelationshipTuple) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.relations[tuple] = struct{}{}
	return nil
}

func (c *InMemoryRelationshipChecker) Check(_ context.Context, tuple RelationshipTuple) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.relations[tuple]
	return ok, nil
}
