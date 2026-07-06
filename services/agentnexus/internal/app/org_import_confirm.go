package app

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
)

type orgImportConfirmRequest struct {
	EnterpriseID        string             `json:"enterprise_id"`
	EnterpriseName      string             `json:"enterprise_name"`
	Provider            string             `json:"provider"`
	SnapshotHash        string             `json:"snapshot_hash"`
	HumanConfirmationID string             `json:"human_confirmation_id"`
	Snapshot            orgsource.Snapshot `json:"snapshot"`
}

type orgImportConfirmResponse struct {
	Provider             string `json:"provider"`
	OrgVersionID         string `json:"org_version_id"`
	VersionNumber        int64  `json:"version_number"`
	ImportedDepartments  int    `json:"imported_departments"`
	ImportedEmployees    int    `json:"imported_employees"`
	ImportedMemberships  int    `json:"imported_memberships"`
	RequiresConfirmation bool   `json:"requires_confirmation"`
}

func HandleOrgImportConfirm(service *iam.Service, auditSink audit.Sink) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req orgImportConfirmRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		if service == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "iam service is required"})
			return
		}
		if req.EnterpriseID == "" || req.EnterpriseName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enterprise_id and enterprise_name are required"})
			return
		}
		sourceHash := hashRuntimeValue(req.Snapshot)
		if req.SnapshotHash != "" && req.SnapshotHash != sourceHash {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "snapshot_hash does not match snapshot"})
			return
		}
		result, err := service.ConfirmOrgImport(r.Context(), iam.ConfirmOrgImportInput{
			EnterpriseID:        req.EnterpriseID,
			EnterpriseName:      req.EnterpriseName,
			Provider:            req.Provider,
			SourceHash:          sourceHash,
			HumanConfirmationID: req.HumanConfirmationID,
			Snapshot:            req.Snapshot,
		})
		if errors.Is(err, iam.ErrOrgImportConfirmationRequired) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "org import confirmation required"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to confirm org import"})
			return
		}
		appendOrgImportAudit(r, auditSink, audit.EventInput{
			EnterpriseID: req.EnterpriseID,
			Action:       "org_import_confirm",
			Decision:     "allow",
			InputHash:    sourceHash,
			OutputHash:   hashRuntimeValue(result),
		})
		writeJSON(w, http.StatusOK, orgImportConfirmResponse{
			Provider:             req.Provider,
			OrgVersionID:         result.OrgVersion.ID,
			VersionNumber:        result.OrgVersion.VersionNumber,
			ImportedDepartments:  result.ImportedDepartments,
			ImportedEmployees:    result.ImportedEmployees,
			ImportedMemberships:  result.ImportedMemberships,
			RequiresConfirmation: false,
		})
	}
}

func appendOrgImportAudit(r *http.Request, sink audit.Sink, input audit.EventInput) {
	if sink == nil {
		return
	}
	_, _ = sink.Append(r.Context(), input)
}

func HandleOrgGraph(service *iam.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enterpriseID := r.URL.Query().Get("enterprise_id")
		if enterpriseID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enterprise_id is required"})
			return
		}
		graph, err := service.GetOrgGraph(r.Context(), enterpriseID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load org graph"})
			return
		}
		writeJSON(w, http.StatusOK, graph)
	}
}
