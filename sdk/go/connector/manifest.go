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
	Name       string      `json:"name" yaml:"name"`
	Type       string      `json:"type" yaml:"type"`
	ReadOnly   *bool       `json:"read_only,omitempty" yaml:"read_only,omitempty"`
	Fields     []Field     `json:"fields,omitempty" yaml:"fields,omitempty"`
	Operations []Operation `json:"operations,omitempty" yaml:"operations,omitempty"`
	HTTP       *HTTPConfig `json:"http,omitempty" yaml:"http,omitempty"`
	Database   *DBConfig   `json:"database,omitempty" yaml:"database,omitempty"`
	File       *FileConfig `json:"file,omitempty" yaml:"file,omitempty"`
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
