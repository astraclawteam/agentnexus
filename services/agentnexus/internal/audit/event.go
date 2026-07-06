package audit

import "time"

type EventInput struct {
	ID                  string
	EnterpriseID        string
	CaseTicketID        string
	StepGrantID         string
	ActorUserID         string
	ConnectorInstanceID string
	ResourceType        string
	ResourceID          string
	Action              string
	Decision            string
	InputHash           string
	OutputHash          string
	EvidencePointer     string
}

type Event struct {
	ID                  string
	EnterpriseID        string
	CaseTicketID        string
	StepGrantID         string
	ActorUserID         string
	ConnectorInstanceID string
	ResourceType        string
	ResourceID          string
	Action              string
	Decision            string
	InputHash           string
	OutputHash          string
	EvidencePointer     string
	PrevHash            string
	EventHash           string
	CreatedAt           time.Time
}

func NewEvent(input EventInput, prevHash string) Event {
	event := Event{
		ID:                  input.ID,
		EnterpriseID:        input.EnterpriseID,
		CaseTicketID:        input.CaseTicketID,
		StepGrantID:         input.StepGrantID,
		ActorUserID:         input.ActorUserID,
		ConnectorInstanceID: input.ConnectorInstanceID,
		ResourceType:        input.ResourceType,
		ResourceID:          input.ResourceID,
		Action:              input.Action,
		Decision:            input.Decision,
		InputHash:           input.InputHash,
		OutputHash:          input.OutputHash,
		EvidencePointer:     input.EvidencePointer,
		PrevHash:            prevHash,
	}
	event.EventHash = ComputeHash(event)
	return event
}
