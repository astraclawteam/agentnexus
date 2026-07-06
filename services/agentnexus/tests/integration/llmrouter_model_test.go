package integration

import (
	"context"
	"os"
	"testing"
	"time"

	adkmodel "google.golang.org/adk/v2/model"
	"google.golang.org/genai"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/llmroutermodel"
)

func TestLLMRouterModelIntegration(t *testing.T) {
	baseURL := os.Getenv("LLMROUTER_BASE_URL")
	apiKey := os.Getenv("LLMROUTER_API_KEY")
	if baseURL == "" || apiKey == "" {
		t.Skip("LLMROUTER_BASE_URL and LLMROUTER_API_KEY are required")
	}

	modelName := os.Getenv("LLMROUTER_MODEL")
	if modelName == "" {
		modelName = "agentnexus-test"
	}

	llm, err := llmroutermodel.New(llmroutermodel.Config{
		BaseURL:      baseURL,
		APIKey:       apiKey,
		DefaultModel: modelName,
		Timeout:      15 * time.Second,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &adkmodel.LLMRequest{
		Model: modelName,
		Contents: []*genai.Content{
			genai.NewContentFromText("Reply with exactly: ok", genai.RoleUser),
		},
	}

	var gotResponse bool
	for resp, err := range llm.GenerateContent(ctx, req, false) {
		if err != nil {
			t.Fatalf("GenerateContent returned error: %v", err)
		}
		if resp.ErrorCode != "" {
			t.Fatalf("GenerateContent returned LLM error %s: %s", resp.ErrorCode, resp.ErrorMessage)
		}
		if resp.Content == nil {
			t.Fatal("GenerateContent response content is nil")
		}
		gotResponse = true
		break
	}
	if !gotResponse {
		t.Fatal("GenerateContent produced no responses")
	}
}
