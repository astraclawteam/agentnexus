package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

func ComputeHash(event Event) string {
	payload := struct {
		ID                  string `json:"id"`
		EnterpriseID        string `json:"enterprise_id"`
		CaseTicketID        string `json:"case_ticket_id,omitempty"`
		StepGrantID         string `json:"step_grant_id,omitempty"`
		ActorUserID         string `json:"actor_user_id,omitempty"`
		ConnectorInstanceID string `json:"connector_instance_id,omitempty"`
		ResourceType        string `json:"resource_type,omitempty"`
		ResourceID          string `json:"resource_id,omitempty"`
		Action              string `json:"action"`
		Decision            string `json:"decision"`
		InputHash           string `json:"input_hash,omitempty"`
		OutputHash          string `json:"output_hash,omitempty"`
		EvidencePointer     string `json:"evidence_pointer,omitempty"`
		PrevHash            string `json:"prev_hash,omitempty"`
	}{
		ID:                  event.ID,
		EnterpriseID:        event.EnterpriseID,
		CaseTicketID:        event.CaseTicketID,
		StepGrantID:         event.StepGrantID,
		ActorUserID:         event.ActorUserID,
		ConnectorInstanceID: event.ConnectorInstanceID,
		ResourceType:        event.ResourceType,
		ResourceID:          event.ResourceID,
		Action:              event.Action,
		Decision:            event.Decision,
		InputHash:           event.InputHash,
		OutputHash:          event.OutputHash,
		EvidencePointer:     event.EvidencePointer,
		PrevHash:            event.PrevHash,
	}
	bytes, _ := json.Marshal(payload)
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func VerifyHashChain(events []Event) error {
	var prev string
	for _, event := range events {
		if event.PrevHash != prev {
			return fmt.Errorf("audit event %s prev_hash mismatch", event.ID)
		}
		if ComputeHash(event) != event.EventHash {
			return fmt.Errorf("audit event %s hash mismatch", event.ID)
		}
		prev = event.EventHash
	}
	return nil
}

type Sink interface {
	Append(context.Context, EventInput) (Event, error)
}

type HashChainLog struct {
	mu     sync.Mutex
	events []Event
	newID  func() string
}

type LogOption func(*HashChainLog)

func NewHashChainLog(opts ...LogOption) *HashChainLog {
	log := &HashChainLog{
		newID: func() string { return "audit_generated" },
	}
	for _, opt := range opts {
		opt(log)
	}
	return log
}

func WithIDGenerator(newID func() string) LogOption {
	return func(log *HashChainLog) {
		log.newID = newID
	}
}

func (log *HashChainLog) Append(_ context.Context, input EventInput) (Event, error) {
	log.mu.Lock()
	defer log.mu.Unlock()

	if input.ID == "" {
		input.ID = log.newID()
	}
	prevHash := ""
	if len(log.events) > 0 {
		prevHash = log.events[len(log.events)-1].EventHash
	}
	event := NewEvent(input, prevHash)
	log.events = append(log.events, event)
	return event, nil
}

func (log *HashChainLog) Events() []Event {
	log.mu.Lock()
	defer log.mu.Unlock()

	return append([]Event(nil), log.events...)
}
