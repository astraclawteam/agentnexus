package config

import "os"

const DefaultVersion = "0.1.0-dev"

type Config struct {
	ServiceName string
	Version     string
	Environment string
	HTTPAddr    string
	// EnterpriseID is the owning enterprise (tenant) of this deployment. It
	// is part of every service's mTLS identity.
	EnterpriseID string
	// AgentID is the registered installation of an installed agent (the
	// Connector Agent binds it into its certificate identity).
	AgentID string
	TLS     TLSSettings
}

// TLSSettings locates the file-based mTLS material of the single AgentNexus
// TLS profile. The material is all-or-nothing: a partially configured set is
// a deployment error, never a silent downgrade to plaintext, and production
// refuses to start without a complete set (enforced by
// internal/transportsecurity.ResolveStartupMode).
type TLSSettings struct {
	// CertFile and KeyFile hold this service's identity certificate and key.
	CertFile string
	KeyFile  string
	// TrustBundleFile holds the signed trust bundle (sequence-protected).
	TrustBundleFile string
	// TrustAuthorityFile holds the pinned bundle-authority public key that
	// signs trust bundles. It is provisioned once and never hot-reloaded.
	TrustAuthorityFile string
	// CRLFile holds the signed certificate revocation list.
	CRLFile string
}

// Configured reports whether any TLS material path is set.
func (t TLSSettings) Configured() bool {
	return t.CertFile != "" || t.KeyFile != "" || t.TrustBundleFile != "" || t.TrustAuthorityFile != "" || t.CRLFile != ""
}

// Complete reports whether every TLS material path is set.
func (t TLSSettings) Complete() bool {
	return t.CertFile != "" && t.KeyFile != "" && t.TrustBundleFile != "" && t.TrustAuthorityFile != "" && t.CRLFile != ""
}

// Missing lists the unset TLS environment variables, for error messages.
func (t TLSSettings) Missing() []string {
	var missing []string
	for _, entry := range []struct {
		name  string
		value string
	}{
		{"AGENTNEXUS_TLS_CERT_FILE", t.CertFile},
		{"AGENTNEXUS_TLS_KEY_FILE", t.KeyFile},
		{"AGENTNEXUS_TLS_TRUST_BUNDLE_FILE", t.TrustBundleFile},
		{"AGENTNEXUS_TLS_TRUST_AUTHORITY_FILE", t.TrustAuthorityFile},
		{"AGENTNEXUS_TLS_CRL_FILE", t.CRLFile},
	} {
		if entry.value == "" {
			missing = append(missing, entry.name)
		}
	}
	return missing
}

func Load(serviceName string) Config {
	version := os.Getenv("AGENTNEXUS_VERSION")
	if version == "" {
		version = DefaultVersion
	}

	environment := os.Getenv("AGENTNEXUS_ENV")
	if environment == "" {
		environment = "dev"
	}

	httpAddr := os.Getenv("AGENTNEXUS_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	return Config{
		ServiceName:  serviceName,
		Version:      version,
		Environment:  environment,
		HTTPAddr:     httpAddr,
		EnterpriseID: os.Getenv("AGENTNEXUS_ENTERPRISE_ID"),
		AgentID:      os.Getenv("AGENTNEXUS_AGENT_ID"),
		TLS: TLSSettings{
			CertFile:           os.Getenv("AGENTNEXUS_TLS_CERT_FILE"),
			KeyFile:            os.Getenv("AGENTNEXUS_TLS_KEY_FILE"),
			TrustBundleFile:    os.Getenv("AGENTNEXUS_TLS_TRUST_BUNDLE_FILE"),
			TrustAuthorityFile: os.Getenv("AGENTNEXUS_TLS_TRUST_AUTHORITY_FILE"),
			CRLFile:            os.Getenv("AGENTNEXUS_TLS_CRL_FILE"),
		},
	}
}
