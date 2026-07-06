package authorization

import (
	"context"
	"fmt"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

const (
	RelationViewer  = "viewer"
	RelationMember  = "member"
	RelationManager = "manager"
)

type RelationshipTuple struct {
	UserID       string
	Relation     string
	ResourceType string
	ResourceID   string
}

type RelationshipChecker interface {
	Check(context.Context, RelationshipTuple) (bool, error)
}

type OpenFGAClient struct {
	checker policy.RelationshipChecker
}

func NewOpenFGAClient(checker policy.RelationshipChecker) *OpenFGAClient {
	return &OpenFGAClient{checker: checker}
}

func (c *OpenFGAClient) Check(ctx context.Context, tuple RelationshipTuple) (bool, error) {
	if c.checker == nil {
		return false, nil
	}
	return c.checker.Check(ctx, policy.TupleKey{
		User:     "user:" + tuple.UserID,
		Relation: tuple.Relation,
		Object:   fmt.Sprintf("%s:%s", tuple.ResourceType, tuple.ResourceID),
	})
}
