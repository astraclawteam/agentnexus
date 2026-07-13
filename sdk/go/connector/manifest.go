package connector

const (
	ResourceTypeHTTP    = "http"
	ResourceTypeDB      = "database"
	ResourceTypeFile    = "file_storage"
	DefaultReadOnlyMode = true
)

// Manifest is the generic connector resource/config manifest: a declarative
// description of the resources, fields and operations a connector exposes. It
// is the pre-Product-Pack form. DevelopmentPackFromManifest (package.go)
// migrates a generic Manifest into an unsigned, development-only ProductPack;
// a production Product Pack is authored and signed directly and can never be
// imported from a generic manifest.
type Manifest struct {
	SchemaVersion string       `json:"schema_version"`
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Resources     []Resource   `json:"resources"`
	Credentials   []Credential `json:"credentials,omitempty"`
}

type Resource struct {
	Name       string      `json:"name"`
	Type       string      `json:"type"`
	ReadOnly   *bool       `json:"read_only,omitempty"`
	Fields     []Field     `json:"fields,omitempty"`
	Operations []Operation `json:"operations,omitempty"`
	HTTP       *HTTPConfig `json:"http,omitempty"`
	Database   *DBConfig   `json:"database,omitempty"`
	File       *FileConfig `json:"file,omitempty"`
}

type Field struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Mask bool   `json:"mask,omitempty"`
}

type Operation struct {
	Name   string `json:"name"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

type Credential struct {
	Name          string `json:"name"`
	CredentialRef string `json:"credential_ref"`
}

type HTTPConfig struct {
	BaseURL string `json:"base_url,omitempty"`
}

type DBConfig struct {
	Driver string `json:"driver,omitempty"`
}

type FileConfig struct {
	Bucket string `json:"bucket,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

func (r Resource) IsReadOnly() bool {
	if r.ReadOnly == nil {
		return DefaultReadOnlyMode
	}
	return *r.ReadOnly
}
