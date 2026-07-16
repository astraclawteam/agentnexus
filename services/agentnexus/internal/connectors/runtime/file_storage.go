package runtime

// file_storage.go is the generic object-store (file/S3) read connector family,
// qualified to GA Product Pack v1. It executes over an INJECTED object-store
// port. It REJECTS path traversal (a ".." segment, an absolute/rooted key, or a
// volume/backslash escape) before any fetch (ErrPathTraversal -> StatusDenied),
// surfaces the object version-id/ETag as the source version, and otherwise
// covers listing pagination, deadline -> bounded failure, ACL/deletion
// invalidation (a deleted/forbidden object -> fail closed, no stale handle),
// output-schema validation and field masking, and source/version/freshness
// metadata. It never receives a master credential and never leaks topology.

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
)

// ObjectPage is one listing page the injected object store returns.
type ObjectPage struct {
	NextPageToken string
	Forbidden     bool // a 403/deletion: fail closed, no stale handle
	Objects       []map[string]any
	Source        string
	SourceVersion int64
	Authority     string
	ObjectVersion string // the S3 version-id / ETag surfaced as the source version
}

// ObjectFetch is one bounded listing request to the injected object store.
type ObjectFetch struct {
	Key       string // the (validated) object key/prefix
	Operation string
	PageToken string
	Auth      string
}

// ObjectStore is the injected object-store port.
type ObjectStore interface {
	List(ctx context.Context, req ObjectFetch) (ObjectPage, error)
}

// FileStorageAdapter is the object-store read family adapter.
type FileStorageAdapter struct {
	store ObjectStore
	now   func() time.Time
}

// NewFileStorageAdapter binds the family to its injected object store.
func NewFileStorageAdapter(store ObjectStore) *FileStorageAdapter {
	return &FileStorageAdapter{store: store, now: func() time.Time { return time.Unix(0, 0).UTC() }}
}

// Name identifies the family for audit.
func (*FileStorageAdapter) Name() string { return "file_storage" }

// Execute rejects a traversal object key BEFORE any fetch (fail closed), then
// lists objects over the injected store — paginated, ACL-checked, masked and
// schema-validated — surfacing the object version/ETag as the source version.
func (a *FileStorageAdapter) Execute(ctx context.Context, req FamilyRequest) (FamilyResponse, error) {
	if rejectTraversal(req.Resource) {
		return FamilyResponse{Status: host.StatusDenied, Reason: "object key escapes the sandbox root"}, nil
	}
	fetch := func(ctx context.Context, token string) (pageData, error) {
		page, err := a.store.List(ctx, ObjectFetch{Key: req.Resource, Operation: req.Operation, PageToken: token, Auth: req.Auth})
		if err != nil {
			return pageData{}, err
		}
		d := pageData{
			records:       toRecords(page.Objects),
			next:          page.NextPageToken,
			denied:        page.Forbidden,
			source:        page.Source,
			sourceVersion: page.SourceVersion,
			authority:     page.Authority,
			objectVersion: page.ObjectVersion,
		}
		return d, nil
	}
	return runReadPipeline(ctx, fetch, req.FieldPolicy, sleepCtx, a.now)
}

// rejectTraversal reports whether an object key escapes its root. It rejects an
// empty key, an absolute/rooted key, a backslash (Windows volume/UNC escape) and
// any ".." segment (including one that path.Clean would resolve to a "../"
// prefix). This mirrors the spirit of host.Policy.AllowPath for object keys,
// which are not filesystem paths but must never escape their declared prefix.
func rejectTraversal(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return true
	}
	if strings.HasPrefix(key, "/") || strings.HasPrefix(key, "\\") || strings.Contains(key, "\\") {
		return true
	}
	// A Windows drive-letter prefix (C:\ or C:/) is an absolute escape.
	if len(key) >= 2 && key[1] == ':' {
		return true
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return true
		}
	}
	cleaned := path.Clean(key)
	return cleaned == ".." || strings.HasPrefix(cleaned, "../")
}
