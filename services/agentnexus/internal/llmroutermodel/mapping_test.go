package llmroutermodel

import (
	"testing"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

func TestMapADKRequestToLLMRouterMessages(t *testing.T) {
	req := &model.LLMRequest{
		Model: "agentnexus-test-model",
		Contents: []*genai.Content{
			genai.NewContentFromText("Find my tasks", genai.RoleUser),
			genai.NewContentFromParts([]*genai.Part{
				genai.NewPartFromFunctionResponse("lookup_tasks", map[string]any{"count": float64(2)}),
			}, genai.RoleUser),
		},
	}

	mapped, err := MapADKRequest(req, nil, "fallback-model", false)
	if err != nil {
		t.Fatalf("MapADKRequest returned error: %v", err)
	}

	if mapped.Model != "agentnexus-test-model" {
		t.Fatalf("Model = %q, want %q", mapped.Model, "agentnexus-test-model")
	}
	if len(mapped.Messages) != 2 {
		t.Fatalf("len(Messages) = %d, want 2", len(mapped.Messages))
	}
	if mapped.Messages[0].Role != "user" || mapped.Messages[0].Content != "Find my tasks" {
		t.Fatalf("first message = %+v, want user text", mapped.Messages[0])
	}
	if mapped.Messages[1].Role != "tool" || mapped.Messages[1].Name != "lookup_tasks" {
		t.Fatalf("second message = %+v, want tool result", mapped.Messages[1])
	}
}

func TestMapADKToolsToLLMRouterTools(t *testing.T) {
	tools := []*genai.Tool{{
		FunctionDeclarations: []*genai.FunctionDeclaration{{
			Name:        "lookup_tasks",
			Description: "Lookup visible tasks",
			Parameters: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"user_id": {Type: genai.TypeString},
				},
				Required: []string{"user_id"},
			},
		}},
	}}

	mapped, err := MapADKTools(tools)
	if err != nil {
		t.Fatalf("MapADKTools returned error: %v", err)
	}

	if len(mapped) != 1 {
		t.Fatalf("len(mapped) = %d, want 1", len(mapped))
	}
	if mapped[0].Type != "function" {
		t.Fatalf("tool type = %q, want function", mapped[0].Type)
	}
	if mapped[0].Function.Name != "lookup_tasks" {
		t.Fatalf("function name = %q, want lookup_tasks", mapped[0].Function.Name)
	}
	if mapped[0].Function.Parameters["type"] != "object" {
		t.Fatalf("parameters type = %v, want object", mapped[0].Function.Parameters["type"])
	}
}

func TestMapLLMRouterToolCallToADKResponse(t *testing.T) {
	resp := LLMRouterChatResponse{
		ID:    "chatcmpl_test",
		Model: "agentnexus-test-model",
		Choices: []LLMRouterChoice{{
			Message: LLMRouterMessage{
				Role: "assistant",
				ToolCalls: []LLMRouterToolCall{{
					ID:   "call_123",
					Type: "function",
					Function: LLMRouterToolCallFunction{
						Name:      "lookup_tasks",
						Arguments: `{"user_id":"user_1"}`,
					},
				}},
			},
			FinishReason: "tool_calls",
		}},
	}

	mapped, err := MapLLMRouterResponse(resp, false)
	if err != nil {
		t.Fatalf("MapLLMRouterResponse returned error: %v", err)
	}

	if mapped.Content == nil || len(mapped.Content.Parts) != 1 {
		t.Fatalf("mapped content = %+v, want one part", mapped.Content)
	}
	call := mapped.Content.Parts[0].FunctionCall
	if call == nil {
		t.Fatal("FunctionCall is nil")
	}
	if call.ID != "call_123" || call.Name != "lookup_tasks" || call.Args["user_id"] != "user_1" {
		t.Fatalf("FunctionCall = %+v, want lookup_tasks with user_id", call)
	}
}

func TestMapLLMRouterUsageToAuditContext(t *testing.T) {
	resp := LLMRouterChatResponse{
		ID:       "chatcmpl_test",
		Model:    "agentnexus-test-model",
		Provider: "local",
		Usage: &LLMRouterUsage{
			PromptTokens:     10,
			CompletionTokens: 7,
			TotalTokens:      17,
		},
		Choices: []LLMRouterChoice{{
			Message: LLMRouterMessage{Role: "assistant", Content: "done"},
		}},
	}

	mapped, err := MapLLMRouterResponse(resp, false)
	if err != nil {
		t.Fatalf("MapLLMRouterResponse returned error: %v", err)
	}

	if mapped.UsageMetadata == nil {
		t.Fatal("UsageMetadata is nil")
	}
	if mapped.UsageMetadata.PromptTokenCount != 10 || mapped.UsageMetadata.CandidatesTokenCount != 7 || mapped.UsageMetadata.TotalTokenCount != 17 {
		t.Fatalf("UsageMetadata = %+v, want 10/7/17", mapped.UsageMetadata)
	}
	if mapped.CustomMetadata["provider"] != "local" || mapped.CustomMetadata["model"] != "agentnexus-test-model" {
		t.Fatalf("CustomMetadata = %+v, want provider/model", mapped.CustomMetadata)
	}
}

func TestMapLLMRouterErrorToADKRecoverableError(t *testing.T) {
	resp := LLMRouterErrorResponse{
		Error: LLMRouterError{
			Code:    "rate_limit_exceeded",
			Message: "quota exceeded",
			Type:    "rate_limit_error",
		},
	}

	mapped := MapLLMRouterError(resp)

	if mapped.ErrorCode != "rate_limit_exceeded" {
		t.Fatalf("ErrorCode = %q, want rate_limit_exceeded", mapped.ErrorCode)
	}
	if mapped.ErrorMessage != "quota exceeded" {
		t.Fatalf("ErrorMessage = %q, want quota exceeded", mapped.ErrorMessage)
	}
	if mapped.CustomMetadata["error_type"] != "rate_limit_error" {
		t.Fatalf("CustomMetadata = %+v, want error_type", mapped.CustomMetadata)
	}
}

func TestMapStreamChunkMarksPartialResponses(t *testing.T) {
	chunk := LLMRouterStreamChunk{
		ID:    "chunk_1",
		Model: "agentnexus-test-model",
		Choices: []LLMRouterStreamChoice{{
			Delta: LLMRouterMessageDelta{
				Role:    "assistant",
				Content: "hel",
			},
		}},
	}

	mapped, err := MapLLMRouterStreamChunk(chunk)
	if err != nil {
		t.Fatalf("MapLLMRouterStreamChunk returned error: %v", err)
	}

	if !mapped.Partial {
		t.Fatal("Partial = false, want true")
	}
	if mapped.Content.Parts[0].Text != "hel" {
		t.Fatalf("text = %q, want hel", mapped.Content.Parts[0].Text)
	}
}
