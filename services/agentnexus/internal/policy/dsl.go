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
	EnforceAdmins bool   `json:"enforce_admins" yaml:"enforce_admins"`
	Rules         []Rule `json:"rules" yaml:"rules"`
}

type Rule struct {
	ResourceType string   `json:"resource_type" yaml:"resource_type"`
	Action       string   `json:"action" yaml:"action"`
	Decision     Decision `json:"decision" yaml:"decision"`
	DataScope    []string `json:"data_scope" yaml:"data_scope"`
	MaskFields   []string `json:"mask_fields" yaml:"mask_fields"`
	RiskLevel    int      `json:"risk_level" yaml:"risk_level"`
}

type Request struct {
	ActorRoles   []string `json:"actor_roles" yaml:"actor_roles"`
	ResourceType string   `json:"resource_type" yaml:"resource_type"`
	ResourceID   string   `json:"resource_id" yaml:"resource_id"`
	Action       string   `json:"action" yaml:"action"`
	Fields       []string `json:"fields" yaml:"fields"`
}

type Result struct {
	Decision   Decision `json:"decision" yaml:"decision"`
	DataScope  []string `json:"data_scope" yaml:"data_scope"`
	MaskFields []string `json:"mask_fields" yaml:"mask_fields"`
	RiskLevel  int      `json:"risk_level" yaml:"risk_level"`
}
