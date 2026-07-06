package connector

const (
	ResourceTypeHTTP    = "http"
	ResourceTypeDB      = "database"
	ResourceTypeFile    = "file_storage"
	DefaultReadOnlyMode = true
)

type Manifest struct {
	SchemaVersion string       `json:"schema_version" yaml:"schema_version"`
	Name          string       `json:"name" yaml:"name"`
	Version       string       `json:"version" yaml:"version"`
	Resources     []Resource   `json:"resources" yaml:"resources"`
	Credentials   []Credential `json:"credentials,omitempty" yaml:"credentials,omitempty"`
}

type Resource struct {
	Name         string            `json:"name" yaml:"name"`
	Type         string            `json:"type" yaml:"type"`
	ReadOnly     *bool             `json:"read_only,omitempty" yaml:"read_only,omitempty"`
	Fields       []Field           `json:"fields,omitempty" yaml:"fields,omitempty"`
	Operations   []Operation       `json:"operations,omitempty" yaml:"operations,omitempty"`
	Scopes       []string          `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	InputSchema  map[string]any    `json:"input_schema,omitempty" yaml:"input_schema,omitempty"`
	OutputSchema map[string]any    `json:"output_schema,omitempty" yaml:"output_schema,omitempty"`
	SmokeTests   []SmokeTest       `json:"smoke_tests,omitempty" yaml:"smoke_tests,omitempty"`
	Risk         RiskMetadata      `json:"risk,omitempty" yaml:"risk,omitempty"`
	Executable   *ExecutableConfig `json:"executable,omitempty" yaml:"executable,omitempty"`
	HTTP         *HTTPConfig       `json:"http,omitempty" yaml:"http,omitempty"`
	Database     *DBConfig         `json:"database,omitempty" yaml:"database,omitempty"`
	File         *FileConfig       `json:"file,omitempty" yaml:"file,omitempty"`
}

type Field struct {
	Name string `json:"name" yaml:"name"`
	Type string `json:"type" yaml:"type"`
	Mask bool   `json:"mask,omitempty" yaml:"mask,omitempty"`
}

type Operation struct {
	Name   string `json:"name" yaml:"name"`
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
	Path   string `json:"path,omitempty" yaml:"path,omitempty"`
}

type SmokeTest struct {
	Name      string   `json:"name" yaml:"name"`
	Operation string   `json:"operation" yaml:"operation"`
	Fields    []string `json:"fields,omitempty" yaml:"fields,omitempty"`
}

const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

type RiskMetadata struct {
	Level         string `json:"level,omitempty" yaml:"level,omitempty"`
	RequiresAudit bool   `json:"requires_audit,omitempty" yaml:"requires_audit,omitempty"`
}

type ExecutableConfig struct {
	Upload bool `json:"upload,omitempty" yaml:"upload,omitempty"`
}

type Credential struct {
	Name          string `json:"name" yaml:"name"`
	CredentialRef string `json:"credential_ref" yaml:"credential_ref"`
}

type HTTPConfig struct {
	BaseURL string `json:"base_url,omitempty" yaml:"base_url,omitempty"`
}

type DBConfig struct {
	Driver string `json:"driver,omitempty" yaml:"driver,omitempty"`
}

type FileConfig struct {
	Bucket string `json:"bucket,omitempty" yaml:"bucket,omitempty"`
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
}

func (r Resource) IsReadOnly() bool {
	if r.ReadOnly == nil {
		return DefaultReadOnlyMode
	}
	return *r.ReadOnly
}
