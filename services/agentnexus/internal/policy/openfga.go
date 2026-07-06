package policy

import (
	"context"
	"strings"
	"sync"
)

const (
	TypeUser              = "user"
	TypeDepartment        = "department"
	TypeProjectGroup      = "project_group"
	TypeKnowledgeSpace    = "knowledge_space"
	TypeConnectorResource = "connector_resource"
)

const (
	RelationMember  = "member"
	RelationManager = "manager"
	RelationParent  = "parent"
	RelationViewer  = "viewer"
)

const OpenFGAModel = `
model
  schema 1.1

type user

type department
  relations
    define member: [user]
    define manager: [user]

type project_group
  relations
    define parent: [department]
    define member: [user]
    define manager: [user]

type knowledge_space
  relations
    define parent: [department, project_group]
    define viewer: [user] or member from parent or manager from parent

type connector_resource
  relations
    define parent: [department, project_group]
    define viewer: [user] or member from parent or manager from parent
`

type TupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type RelationshipChecker interface {
	WriteRelation(context.Context, TupleKey) error
	Check(context.Context, TupleKey) (bool, error)
}

type InMemoryOpenFGA struct {
	mu     sync.RWMutex
	tuples map[TupleKey]struct{}
}

func NewInMemoryOpenFGA() *InMemoryOpenFGA {
	return &InMemoryOpenFGA{tuples: map[TupleKey]struct{}{}}
}

func (f *InMemoryOpenFGA) WriteRelation(_ context.Context, tuple TupleKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.tuples[tuple] = struct{}{}
	return nil
}

func (f *InMemoryOpenFGA) Check(_ context.Context, tuple TupleKey) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.has(tuple) {
		return true, nil
	}
	if tuple.Relation != RelationViewer {
		return false, nil
	}

	objectType := objectType(tuple.Object)
	if objectType != TypeKnowledgeSpace && objectType != TypeConnectorResource {
		return false, nil
	}

	for parent := range f.parentsOf(tuple.Object) {
		if f.has(TupleKey{User: tuple.User, Relation: RelationManager, Object: parent}) {
			return true, nil
		}
		if f.has(TupleKey{User: tuple.User, Relation: RelationMember, Object: parent}) {
			return true, nil
		}
	}
	return false, nil
}

func (f *InMemoryOpenFGA) has(tuple TupleKey) bool {
	_, ok := f.tuples[tuple]
	return ok
}

func (f *InMemoryOpenFGA) parentsOf(object string) map[string]struct{} {
	parents := map[string]struct{}{}
	for tuple := range f.tuples {
		if tuple.Relation == RelationParent && tuple.Object == object {
			parents[tuple.User] = struct{}{}
		}
	}
	return parents
}

func objectType(object string) string {
	before, _, ok := strings.Cut(object, ":")
	if !ok {
		return ""
	}
	return before
}
