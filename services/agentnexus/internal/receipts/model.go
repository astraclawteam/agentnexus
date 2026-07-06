package receipts

import "time"

type TargetSource string

const (
	TargetSourceExternalSource  TargetSource = "external_source"
	TargetSourceConnectorConfig TargetSource = "connector_config"
	TargetSourcePolicyOrgRule   TargetSource = "policy_org_rule"
	TargetSourceUserSelection   TargetSource = "user_selection"
)

type Channel string

const (
	ChannelClaw Channel = "claw"
	ChannelIM   Channel = "im"
)

type RequestStatus string

const (
	RequestStatusPending    RequestStatus = "pending"
	RequestStatusDelivered  RequestStatus = "delivered"
	RequestStatusReceived   RequestStatus = "received"
	RequestStatusApproved   RequestStatus = "approved"
	RequestStatusDenied     RequestStatus = "denied"
	RequestStatusNarrowed   RequestStatus = "narrowed"
	RequestStatusInstructed RequestStatus = "instructed"
	RequestStatusExpired    RequestStatus = "expired"
	RequestStatusRevoked    RequestStatus = "revoked"
)

type ReceiptResult string

const (
	ReceiptApproved   ReceiptResult = "approved"
	ReceiptDenied     ReceiptResult = "denied"
	ReceiptNarrowed   ReceiptResult = "narrowed"
	ReceiptInstructed ReceiptResult = "instructed"
)

type Target struct {
	ID      string
	Source  TargetSource
	Channel Channel
	Address string
}

type RequestInput struct {
	ID           string
	EnterpriseID string
	CaseTicketID string
	StepGrantID  string
	Target       Target
}

type ReceiptRequest struct {
	ID           string
	EnterpriseID string
	CaseTicketID string
	StepGrantID  string
	Target       Target
	Status       RequestStatus
	CreatedAt    time.Time
}

type Receipt struct {
	ID        string
	RequestID string
	Result    ReceiptResult
	Evidence  string
	CreatedAt time.Time
}

type CallbackInput struct {
	EnterpriseID string
	RequestID    string
	ReceiptID    string
	Result       ReceiptResult
	Evidence     string
}
