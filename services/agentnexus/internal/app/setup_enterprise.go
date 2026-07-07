package app

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
)

type setupEnterpriseContext struct {
	EnterpriseID     string
	EnterpriseName   string
	AdminUserID      string
	EnvironmentLabel string
}

type setupEnterpriseStore interface {
	Save(setupEnterpriseContext)
	Get(string) (setupEnterpriseContext, bool)
	First() (setupEnterpriseContext, bool)
}

type memorySetupEnterpriseStore struct {
	mu      sync.Mutex
	entries map[string]setupEnterpriseContext
}

func newMemorySetupEnterpriseStore() *memorySetupEnterpriseStore {
	return &memorySetupEnterpriseStore{entries: map[string]setupEnterpriseContext{}}
}

func (s *memorySetupEnterpriseStore) Save(ctx setupEnterpriseContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[ctx.EnterpriseID] = ctx
}

func (s *memorySetupEnterpriseStore) Get(enterpriseID string) (setupEnterpriseContext, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, ok := s.entries[enterpriseID]
	return ctx, ok
}

func (s *memorySetupEnterpriseStore) First() (setupEnterpriseContext, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ctx := range s.entries {
		return ctx, true
	}
	return setupEnterpriseContext{}, false
}

type setupEnterpriseRequest struct {
	EnterpriseID     string `json:"enterprise_id"`
	EnterpriseName   string `json:"enterprise_name"`
	AdminUserID      string `json:"admin_user_id"`
	EnvironmentLabel string `json:"environment_label"`
}

type setupEnterpriseResponse struct {
	EnterpriseID   string `json:"enterprise_id"`
	EnterpriseName string `json:"enterprise_name"`
	State          string `json:"state"`
}

func HandleSetupEnterprise(store setupEnterpriseStore, iamService *iam.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req setupEnterpriseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		if req.EnterpriseID == "" || req.EnterpriseName == "" || req.AdminUserID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enterprise_id, enterprise_name, and admin_user_id are required"})
			return
		}
		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "setup store is required"})
			return
		}
		if iamService != nil {
			if _, err := iamService.CreateEnterprise(r.Context(), iam.CreateEnterpriseInput{ID: req.EnterpriseID, Name: req.EnterpriseName}); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create enterprise"})
				return
			}
		}
		store.Save(setupEnterpriseContext{
			EnterpriseID:     req.EnterpriseID,
			EnterpriseName:   req.EnterpriseName,
			AdminUserID:      req.AdminUserID,
			EnvironmentLabel: req.EnvironmentLabel,
		})
		writeJSON(w, http.StatusOK, setupEnterpriseResponse{
			EnterpriseID:   req.EnterpriseID,
			EnterpriseName: req.EnterpriseName,
			State:          "configured_without_org",
		})
	}
}
