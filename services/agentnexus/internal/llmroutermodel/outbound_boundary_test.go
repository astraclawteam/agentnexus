package llmroutermodel

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bannedProviderClients are constructors that would open a model connection to
// a provider directly. The GA manifest pins model access as llmrouter-only with
// an empty direct_providers list, and ELC-LLMROUTER-1 requires that local/cloud
// selection happens INSIDE llmrouter with no provider credentials exposed to
// AgentNexus. A direct provider client here would quietly break both.
var bannedProviderClients = []string{
	"genai.NewClient",
	"openai.NewClient",
	"anthropic.NewClient",
	"vertexai.NewClient",
	"ollama.New",
}

// bannedProviderImports are modules that only exist to talk to a provider.
// google.golang.org/genai is deliberately NOT here: ADK uses its types as the
// content vocabulary (Content, Part, Tool, Schema, FinishReason), and importing
// it for types is not egress. The constructor scan above is what catches misuse.
var bannedProviderImports = []string{
	"github.com/sashabaranov/go-openai",
	"github.com/anthropics/anthropic-sdk-go",
	"github.com/ollama/ollama",
}

// TestOnlyLLMRouterOutbound is named by GA Task 13's verification command. It
// asserts the structural half of the boundary: every model call this service
// makes leaves through the llmrouter client and nothing else.
func TestOnlyLLMRouterOutbound(t *testing.T) {
	for _, pkg := range []string{".", filepath.Join("..", "gatewayagent")} {
		files, err := filepath.Glob(filepath.Join(pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			// Production code only. A _test.go file naming a provider
			// constructor is a fixture or, as here, this scan's own banned
			// list; neither ships, and neither is egress.
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			source := string(raw)
			for _, banned := range bannedProviderClients {
				if strings.Contains(source, banned) {
					t.Errorf("%s constructs a direct provider client %q; model access is llmrouter-only", file, banned)
				}
			}
			for _, banned := range bannedProviderImports {
				if strings.Contains(source, `"`+banned) {
					t.Errorf("%s imports provider SDK %q; model access is llmrouter-only", file, banned)
				}
			}
		}
	}
}

// TestOutboundBaseURLIsAlwaysConfigured asserts the other half: the single
// outbound path is built from configuration, never from a hardcoded host. A
// literal provider endpoint compiled into the binary would be egress that no
// deployment could redirect or audit.
func TestOutboundBaseURLIsAlwaysConfigured(t *testing.T) {
	raw, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	// Any absolute URL literal in the client is suspicious: the base URL must
	// come from Config, and paths are appended to it.
	literalURL := regexp.MustCompile(`"https?://[^"]+"`)
	if found := literalURL.FindAllString(source, -1); len(found) > 0 {
		t.Fatalf("client.go contains hardcoded endpoint literal(s) %v; the base URL must come from configuration", found)
	}
	if !strings.Contains(source, "c.baseURL+") {
		t.Fatal("client.go no longer builds its request URL from the configured base URL")
	}
	if !strings.Contains(source, `errors.New("llmrouter base URL is required")`) {
		t.Fatal("client.go no longer refuses to construct without a configured base URL")
	}
}
