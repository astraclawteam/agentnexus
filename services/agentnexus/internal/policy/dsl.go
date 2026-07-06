package policy

type Decision string

const (
	DecisionAllow               Decision = "allow"
	DecisionDeny                Decision = "deny"
	DecisionNeedExternalReceipt Decision = "need_external_receipt"
	DecisionAllowWithMasking    Decision = "allow_with_masking"
)

const (
	RiskLow = iota + 1
	RiskMedium
	RiskHigh
)

type Policy struct {
	Rules []Rule
}

type Rule struct {
	ResourceType string
	Action       string
	Decision     Decision
	DataScope    []string
	MaskFields   []string
	RiskLevel    int
}

type Request struct {
	ResourceType string
	ResourceID   string
	Action       string
	Fields       []string
}

type Result struct {
	Decision   Decision
	DataScope  []string
	MaskFields []string
	RiskLevel  int
}
