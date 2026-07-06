package app

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/receipts"
)

const receiptRequestPrefix = "/api/receipts/requests/"

type receiptRequestCreateRequest struct {
	ID           string          `json:"id"`
	EnterpriseID string          `json:"enterprise_id"`
	CaseTicketID string          `json:"case_ticket_id"`
	StepGrantID  string          `json:"step_grant_id"`
	Target       receipts.Target `json:"target"`
}

type receiptRequestResponse struct {
	ID           string          `json:"id"`
	EnterpriseID string          `json:"enterprise_id"`
	CaseTicketID string          `json:"case_ticket_id"`
	StepGrantID  string          `json:"step_grant_id"`
	Target       receipts.Target `json:"target"`
	Status       string          `json:"status"`
}

type receiptCallbackRequest struct {
	EnterpriseID string                 `json:"enterprise_id"`
	ReceiptID    string                 `json:"receipt_id"`
	Result       receipts.ReceiptResult `json:"result"`
	Evidence     string                 `json:"evidence"`
}

type receiptCallbackResponse struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	Result    string `json:"result"`
}

func HandleReceiptRequestCreate(relay *receipts.Relay) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req receiptRequestCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		result, err := relay.CreateAndDeliver(receipts.RequestInput{
			ID:           req.ID,
			EnterpriseID: req.EnterpriseID,
			CaseTicketID: req.CaseTicketID,
			StepGrantID:  req.StepGrantID,
			Target:       req.Target,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, receiptRequestResponse{
			ID:           result.ID,
			EnterpriseID: result.EnterpriseID,
			CaseTicketID: result.CaseTicketID,
			StepGrantID:  result.StepGrantID,
			Target:       result.Target,
			Status:       string(result.Status),
		})
	}
}

func HandleReceiptRequestCallback(relay *receipts.Relay) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID, action, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, receiptRequestPrefix), ":")
		if !ok || requestID == "" || action != "callback" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "receipt request action not found"})
			return
		}
		var req receiptCallbackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		receipt, err := relay.ReceiveCallback(receipts.CallbackInput{
			EnterpriseID: req.EnterpriseID,
			RequestID:    requestID,
			ReceiptID:    req.ReceiptID,
			Result:       req.Result,
			Evidence:     req.Evidence,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, receiptCallbackResponse{
			ID:        receipt.ID,
			RequestID: receipt.RequestID,
			Result:    string(receipt.Result),
		})
	}
}
