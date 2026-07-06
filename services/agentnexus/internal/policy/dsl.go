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
	// EnforceAdmins controls whether administrator actors still need an
	// explicit matching rule. The zero value is false so local/admin operators
	// can recover access unless a deployment opts into strict enforcement.
	EnforceAdmins bool
	Rules         []Rule
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
	ActorRoles   []string
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
