package app

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
)

type orgImportPreviewRequest struct {
	EnterpriseID    string `json:"enterprise_id"`
	Provider        string `json:"provider"`
	BaseURL         string `json:"base_url"`
	DepartmentsPath string `json:"departments_path"`
	EmployeesPath   string `json:"employees_path"`
	TokenRef        string `json:"token_ref"`
	CredentialRef   string `json:"credential_ref"`
	Token           string `json:"token"`
}

type orgImportPreviewResponse struct {
	Provider                  string               `json:"provider"`
	SnapshotHash              string               `json:"snapshot_hash"`
	DepartmentCount           int                  `json:"department_count"`
	EmployeeCount             int                  `json:"employee_count"`
	MembershipCount           int                  `json:"membership_count"`
	RequiresConfirmation      bool                 `json:"requires_confirmation"`
	AutoImportableEmployeeIDs []string             `json:"auto_importable_employee_ids"`
	Conflicts                 []orgsource.Conflict `json:"conflicts"`
}

type orgImportPreviewCacheEntry struct {
	EnterpriseID string
	Provider     string
	Snapshot     orgsource.Snapshot
}

type orgImportPreviewStore interface {
	Save(string, orgImportPreviewCacheEntry)
	Get(string) (orgImportPreviewCacheEntry, bool)
}

type memoryOrgImportPreviewStore struct {
	mu      sync.Mutex
	entries map[string]orgImportPreviewCacheEntry
}

func newMemoryOrgImportPreviewStore() *memoryOrgImportPreviewStore {
	return &memoryOrgImportPreviewStore{entries: map[string]orgImportPreviewCacheEntry{}}
}

func (s *memoryOrgImportPreviewStore) Save(hash string, entry orgImportPreviewCacheEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[hash] = entry
}

func (s *memoryOrgImportPreviewStore) Get(hash string) (orgImportPreviewCacheEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[hash]
	return entry, ok
}

func HandleOrgImportPreview(secretResolver connectorruntime.SecretResolver, auditSink audit.Sink, previewStore orgImportPreviewStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req orgImportPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		if req.Token != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "raw token is not accepted; use token_ref or credential_ref"})
			return
		}
		if !supportedOrgImportProvider(req.Provider) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported org import provider"})
			return
		}

		token := ""
		credentialRef := req.CredentialRef
		if credentialRef == "" {
			credentialRef = req.TokenRef
		}
		if credentialRef != "" {
			if secretResolver == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret resolver is required for token_ref"})
				return
			}
			resolved, err := secretResolver.ResolveSecret(r.Context(), credentialRef)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to resolve token_ref"})
				return
			}
			token = resolved
		}

		provider := orgImportProvider(req, token, credentialRef, secretResolver)
		snapshot, err := provider.Fetch(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to build org import preview"})
			return
		}
		preview := orgsource.PreviewImport(snapshot)
		snapshotHash := hashRuntimeValue(snapshot)
		appendOrgImportAudit(r, auditSink, audit.EventInput{
			Action:     "org_import_preview",
			Decision:   "preview",
			InputHash:  hashRuntimeValue(req),
			OutputHash: snapshotHash,
		})
		if previewStore != nil {
			previewStore.Save(snapshotHash, orgImportPreviewCacheEntry{
				EnterpriseID: req.EnterpriseID,
				Provider:     req.Provider,
				Snapshot:     snapshot,
			})
		}

		writeJSON(w, http.StatusOK, orgImportPreviewResponse{
			Provider:                  req.Provider,
			SnapshotHash:              snapshotHash,
			DepartmentCount:           len(snapshot.Departments),
			EmployeeCount:             len(snapshot.Employees),
			MembershipCount:           previewMembershipCount(snapshot),
			RequiresConfirmation:      preview.RequiresConfirmation,
			AutoImportableEmployeeIDs: preview.AutoImportableEmployeeIDs,
			Conflicts:                 preview.Conflicts,
		})
	}
}

func supportedOrgImportProvider(provider string) bool {
	switch provider {
	case "oa_http", "wecom", "feishu", "dingtalk":
		return true
	default:
		return false
	}
}

func orgImportProvider(req orgImportPreviewRequest, token, credentialRef string, resolver connectorruntime.SecretResolver) orgsource.Provider {
	switch req.Provider {
	case "wecom":
		return orgsource.NewWeComHTTPProvider(vendorHTTPConfig(req, credentialRef, resolver))
	case "feishu":
		return orgsource.NewFeishuHTTPProvider(vendorHTTPConfig(req, credentialRef, resolver))
	case "dingtalk":
		return orgsource.NewDingTalkHTTPProvider(vendorHTTPConfig(req, credentialRef, resolver))
	default:
		return orgsource.NewOAHTTPProvider(orgsource.OAHTTPConfig{
			BaseURL:         req.BaseURL,
			DepartmentsPath: req.DepartmentsPath,
			EmployeesPath:   req.EmployeesPath,
			Token:           token,
		})
	}
}

func vendorHTTPConfig(req orgImportPreviewRequest, credentialRef string, resolver connectorruntime.SecretResolver) orgsource.VendorHTTPConfig {
	return orgsource.VendorHTTPConfig{
		BaseURL:         req.BaseURL,
		DepartmentsPath: req.DepartmentsPath,
		EmployeesPath:   req.EmployeesPath,
		CredentialRef:   credentialRef,
		TokenResolver:   orgSourceTokenResolver{resolver: resolver},
	}
}

type orgSourceTokenResolver struct {
	resolver connectorruntime.SecretResolver
}

func (r orgSourceTokenResolver) ResolveToken(ctx context.Context, credentialRef string) (string, error) {
	if r.resolver == nil {
		return "", nil
	}
	return r.resolver.ResolveSecret(ctx, credentialRef)
}

func previewMembershipCount(snapshot orgsource.Snapshot) int {
	seen := map[string]struct{}{}
	for _, membership := range snapshot.Memberships {
		seen[membership.EmployeeID+":"+membership.DepartmentID] = struct{}{}
	}
	for _, employee := range snapshot.Employees {
		for _, departmentID := range employee.DepartmentIDs {
			if departmentID == "" {
				continue
			}
			seen[employee.ID+":"+departmentID] = struct{}{}
		}
	}
	return len(seen)
}
