package config

import (
	"fmt"
	"os"
	"strings"
)

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
	// LLMRouter locates the llmrouter gateway. It is the ONLY outbound path
	// to a model; there is no direct-provider alternative to fall back to.
	LLMRouter LLMRouterSettings
	// HealthProbeTargets is the raw, unparsed target list a service probes to
	// report deployment readiness. It stays raw here because Load cannot
	// report an error; callers parse it with ParseProbeTargets and decide
	// what a malformed value means for them.
	HealthProbeTargets string
}

// LLMRouterSettings locates the llmrouter gateway.
//
// Like TLSSettings this is all-or-nothing: a half-configured router is a
// deployment error, never a silent fallback to some other model source. The GA
// manifest pins model access as llmrouter-only with an empty direct-provider
// list, so an incomplete set means the assistant does not exist, not that it
// finds a model elsewhere.
type LLMRouterSettings struct {
	// BaseURL is the llmrouter gateway root, without a trailing path.
	BaseURL string
	// APIKey authenticates this service to the router. It is a secret: it
	// must arrive from a secret store, never from a chart value, and it must
	// never appear in a log line, a readiness reason, or an error message.
	APIKey string
	// Model is the default model identifier requested from the router.
	Model string
}

// Configured reports whether any llmrouter value is set.
func (l LLMRouterSettings) Configured() bool {
	return l.BaseURL != "" || l.APIKey != "" || l.Model != ""
}

// Complete reports whether every llmrouter value is set.
func (l LLMRouterSettings) Complete() bool {
	return l.BaseURL != "" && l.APIKey != "" && l.Model != ""
}

// Missing lists the unset llmrouter environment variables, for error messages.
//
// It returns variable NAMES and never values, so the result is safe to put in
// a log line or a readiness reason even though one of the values is a secret.
func (l LLMRouterSettings) Missing() []string {
	var missing []string
	for _, entry := range []struct {
		name  string
		value string
	}{
		{"AGENTNEXUS_LLMROUTER_BASE_URL", l.BaseURL},
		{"AGENTNEXUS_LLMROUTER_API_KEY", l.APIKey},
		{"AGENTNEXUS_LLMROUTER_MODEL", l.Model},
	} {
		if entry.value == "" {
			missing = append(missing, entry.name)
		}
	}
	return missing
}

// ProbeTarget is one service whose readiness endpoint another service polls.
type ProbeTarget struct {
	Name string
	URL  string
}

// ParseProbeTargets parses a "name=url,name=url" list.
//
// It is strict: a malformed entry is an error rather than a skipped one.
// Silently dropping an entry would produce a readiness report that is missing a
// service without saying so, and a report an operator reads as complete when it
// is not is worse than a startup failure.
func ParseProbeTargets(raw string) ([]ProbeTarget, error) {
	var targets []ProbeTarget
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, url, found := strings.Cut(entry, "=")
		name, url = strings.TrimSpace(name), strings.TrimSpace(url)
		if !found || name == "" || url == "" {
			return nil, fmt.Errorf("probe target %q is not in name=url form", entry)
		}
		targets = append(targets, ProbeTarget{Name: name, URL: url})
	}
	return targets, nil
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
		LLMRouter: LLMRouterSettings{
			BaseURL: os.Getenv("AGENTNEXUS_LLMROUTER_BASE_URL"),
			APIKey:  os.Getenv("AGENTNEXUS_LLMROUTER_API_KEY"),
			Model:   os.Getenv("AGENTNEXUS_LLMROUTER_MODEL"),
		},
		HealthProbeTargets: os.Getenv("AGENTNEXUS_HEALTH_PROBE_TARGETS"),
	}
}
