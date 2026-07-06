package llmroutermodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	adkmodel "google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

type LLMRouterChatRequest struct {
	Model    string             `json:"model"`
	Messages []LLMRouterMessage `json:"messages"`
	Tools    []LLMRouterTool    `json:"tools,omitempty"`
	Stream   bool               `json:"stream,omitempty"`
}

type LLMRouterChatResponse struct {
	ID       string            `json:"id"`
	Model    string            `json:"model"`
	Provider string            `json:"provider,omitempty"`
	Choices  []LLMRouterChoice `json:"choices"`
	Usage    *LLMRouterUsage   `json:"usage,omitempty"`
}

type LLMRouterChoice struct {
	Message      LLMRouterMessage `json:"message"`
	FinishReason string           `json:"finish_reason,omitempty"`
}

type LLMRouterMessage struct {
	Role       string              `json:"role"`
	Content    string              `json:"content,omitempty"`
	Name       string              `json:"name,omitempty"`
	ToolCallID string              `json:"tool_call_id,omitempty"`
	ToolCalls  []LLMRouterToolCall `json:"tool_calls,omitempty"`
}

type LLMRouterToolCall struct {
	ID       string                    `json:"id,omitempty"`
	Type     string                    `json:"type"`
	Function LLMRouterToolCallFunction `json:"function"`
}

type LLMRouterToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type LLMRouterTool struct {
	Type     string            `json:"type"`
	Function LLMRouterFunction `json:"function"`
}

type LLMRouterFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type LLMRouterUsage struct {
	PromptTokens     int32 `json:"prompt_tokens,omitempty"`
	CompletionTokens int32 `json:"completion_tokens,omitempty"`
	TotalTokens      int32 `json:"total_tokens,omitempty"`
}

type LLMRouterErrorResponse struct {
	Error LLMRouterError `json:"error"`
}

type LLMRouterError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Type    string `json:"type,omitempty"`
}

type LLMRouterStreamChunk struct {
	ID      string                  `json:"id"`
	Model   string                  `json:"model"`
	Choices []LLMRouterStreamChoice `json:"choices"`
	Usage   *LLMRouterUsage         `json:"usage,omitempty"`
}

type LLMRouterStreamChoice struct {
	Delta        LLMRouterMessageDelta `json:"delta"`
	FinishReason string                `json:"finish_reason,omitempty"`
}

type LLMRouterMessageDelta struct {
	Role      string              `json:"role,omitempty"`
	Content   string              `json:"content,omitempty"`
	ToolCalls []LLMRouterToolCall `json:"tool_calls,omitempty"`
}

func MapADKRequest(req *adkmodel.LLMRequest, tools []*genai.Tool, fallbackModel string, stream bool) (LLMRouterChatRequest, error) {
	if req == nil {
		return LLMRouterChatRequest{}, errors.New("adk request is nil")
	}

	modelName := strings.TrimSpace(req.Model)
	if modelName == "" {
		modelName = strings.TrimSpace(fallbackModel)
	}
	if modelName == "" {
		return LLMRouterChatRequest{}, errors.New("model is required")
	}

	messages := make([]LLMRouterMessage, 0, len(req.Contents))
	for _, content := range req.Contents {
		mapped, err := mapContent(content)
		if err != nil {
			return LLMRouterChatRequest{}, err
		}
		messages = append(messages, mapped...)
	}

	mappedTools, err := MapADKTools(tools)
	if err != nil {
		return LLMRouterChatRequest{}, err
	}

	return LLMRouterChatRequest{
		Model:    modelName,
		Messages: messages,
		Tools:    mappedTools,
		Stream:   stream,
	}, nil
}

func MapADKTools(tools []*genai.Tool) ([]LLMRouterTool, error) {
	var mapped []LLMRouterTool
	for _, tool := range tools {
		if tool == nil {
			continue
		}
		for _, declaration := range tool.FunctionDeclarations {
			if declaration == nil {
				continue
			}
			parameters, err := mapFunctionParameters(declaration)
			if err != nil {
				return nil, fmt.Errorf("map tool %q parameters: %w", declaration.Name, err)
			}
			mapped = append(mapped, LLMRouterTool{
				Type: "function",
				Function: LLMRouterFunction{
					Name:        declaration.Name,
					Description: declaration.Description,
					Parameters:  parameters,
				},
			})
		}
	}
	return mapped, nil
}

func MapLLMRouterResponse(resp LLMRouterChatResponse, partial bool) (*adkmodel.LLMResponse, error) {
	if len(resp.Choices) == 0 {
		return nil, errors.New("llmrouter response has no choices")
	}

	choice := resp.Choices[0]
	mapped := &adkmodel.LLMResponse{
		Content:        mapRouterMessageToContent(choice.Message),
		UsageMetadata:  mapUsage(resp.Usage),
		CustomMetadata: mapMetadata(resp.ID, resp.Model, resp.Provider),
		ModelVersion:   resp.Model,
		FinishReason:   mapFinishReason(choice.FinishReason),
		Partial:        partial,
		TurnComplete:   !partial,
	}
	return mapped, nil
}

func MapLLMRouterError(resp LLMRouterErrorResponse) *adkmodel.LLMResponse {
	return &adkmodel.LLMResponse{
		ErrorCode:    resp.Error.Code,
		ErrorMessage: resp.Error.Message,
		CustomMetadata: map[string]any{
			"error_type": resp.Error.Type,
		},
		TurnComplete: true,
	}
}

func MapLLMRouterStreamChunk(chunk LLMRouterStreamChunk) (*adkmodel.LLMResponse, error) {
	if len(chunk.Choices) == 0 {
		return nil, errors.New("llmrouter stream chunk has no choices")
	}

	choice := chunk.Choices[0]
	message := LLMRouterMessage{
		Role:      choice.Delta.Role,
		Content:   choice.Delta.Content,
		ToolCalls: choice.Delta.ToolCalls,
	}
	turnComplete := choice.FinishReason != ""

	return &adkmodel.LLMResponse{
		Content:        mapRouterMessageToContent(message),
		UsageMetadata:  mapUsage(chunk.Usage),
		CustomMetadata: mapMetadata(chunk.ID, chunk.Model, ""),
		ModelVersion:   chunk.Model,
		FinishReason:   mapFinishReason(choice.FinishReason),
		Partial:        !turnComplete,
		TurnComplete:   turnComplete,
	}, nil
}

func mapContent(content *genai.Content) ([]LLMRouterMessage, error) {
	if content == nil {
		return nil, nil
	}

	toolResults := make([]LLMRouterMessage, 0)
	assistantToolCalls := make([]LLMRouterToolCall, 0)
	textParts := make([]string, 0)

	for _, part := range content.Parts {
		if part == nil {
			continue
		}
		if part.Text != "" {
			textParts = append(textParts, part.Text)
		}
		if part.FunctionResponse != nil {
			payload, err := json.Marshal(part.FunctionResponse.Response)
			if err != nil {
				return nil, fmt.Errorf("marshal function response %q: %w", part.FunctionResponse.Name, err)
			}
			toolResults = append(toolResults, LLMRouterMessage{
				Role:       "tool",
				Name:       part.FunctionResponse.Name,
				ToolCallID: part.FunctionResponse.ID,
				Content:    string(payload),
			})
		}
		if part.FunctionCall != nil {
			args, err := json.Marshal(part.FunctionCall.Args)
			if err != nil {
				return nil, fmt.Errorf("marshal function call %q args: %w", part.FunctionCall.Name, err)
			}
			assistantToolCalls = append(assistantToolCalls, LLMRouterToolCall{
				ID:   part.FunctionCall.ID,
				Type: "function",
				Function: LLMRouterToolCallFunction{
					Name:      part.FunctionCall.Name,
					Arguments: string(args),
				},
			})
		}
	}

	messages := make([]LLMRouterMessage, 0, 1+len(toolResults))
	if len(textParts) > 0 || len(assistantToolCalls) > 0 {
		messages = append(messages, LLMRouterMessage{
			Role:      mapADKRole(content.Role),
			Content:   strings.Join(textParts, "\n"),
			ToolCalls: assistantToolCalls,
		})
	}
	messages = append(messages, toolResults...)
	return messages, nil
}

func mapADKRole(role string) string {
	switch role {
	case string(genai.RoleModel):
		return "assistant"
	case string(genai.RoleUser), "":
		return "user"
	default:
		return role
	}
}

func mapRouterMessageToContent(message LLMRouterMessage) *genai.Content {
	parts := make([]*genai.Part, 0, 1+len(message.ToolCalls))
	if message.Content != "" {
		parts = append(parts, genai.NewPartFromText(message.Content))
	}
	for _, toolCall := range message.ToolCalls {
		args := map[string]any{}
		if strings.TrimSpace(toolCall.Function.Arguments) != "" {
			_ = json.Unmarshal([]byte(toolCall.Function.Arguments), &args)
		}
		part := genai.NewPartFromFunctionCall(toolCall.Function.Name, args)
		part.FunctionCall.ID = toolCall.ID
		parts = append(parts, part)
	}
	return genai.NewContentFromParts(parts, genai.RoleModel)
}

func mapFunctionParameters(declaration *genai.FunctionDeclaration) (map[string]any, error) {
	if declaration.ParametersJsonSchema != nil {
		return normalizeJSONSchema(declaration.ParametersJsonSchema)
	}
	if declaration.Parameters == nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}, nil
	}
	return mapSchema(declaration.Parameters), nil
}

func normalizeJSONSchema(schema any) (map[string]any, error) {
	switch typed := schema.(type) {
	case map[string]any:
		return typed, nil
	default:
		payload, err := json.Marshal(typed)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(payload, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func mapSchema(schema *genai.Schema) map[string]any {
	if schema == nil {
		return nil
	}

	out := map[string]any{}
	if schema.Type != "" {
		out["type"] = mapSchemaType(schema.Type)
	}
	if schema.Description != "" {
		out["description"] = schema.Description
	}
	if schema.Format != "" {
		out["format"] = schema.Format
	}
	if len(schema.Enum) > 0 {
		out["enum"] = schema.Enum
	}
	if len(schema.Required) > 0 {
		out["required"] = schema.Required
	}
	if schema.Items != nil {
		out["items"] = mapSchema(schema.Items)
	}
	if len(schema.Properties) > 0 {
		properties := make(map[string]any, len(schema.Properties))
		for name, property := range schema.Properties {
			properties[name] = mapSchema(property)
		}
		out["properties"] = properties
	}
	if len(schema.AnyOf) > 0 {
		anyOf := make([]map[string]any, 0, len(schema.AnyOf))
		for _, option := range schema.AnyOf {
			anyOf = append(anyOf, mapSchema(option))
		}
		out["anyOf"] = anyOf
	}
	return out
}

func mapSchemaType(schemaType genai.Type) string {
	switch schemaType {
	case genai.TypeObject:
		return "object"
	case genai.TypeArray:
		return "array"
	case genai.TypeString:
		return "string"
	case genai.TypeInteger:
		return "integer"
	case genai.TypeNumber:
		return "number"
	case genai.TypeBoolean:
		return "boolean"
	default:
		return strings.ToLower(string(schemaType))
	}
}

func mapUsage(usage *LLMRouterUsage) *genai.GenerateContentResponseUsageMetadata {
	if usage == nil {
		return nil
	}
	return &genai.GenerateContentResponseUsageMetadata{
		PromptTokenCount:     usage.PromptTokens,
		CandidatesTokenCount: usage.CompletionTokens,
		TotalTokenCount:      usage.TotalTokens,
	}
}

func mapMetadata(id, model, provider string) map[string]any {
	metadata := map[string]any{}
	if id != "" {
		metadata["llmrouter_id"] = id
	}
	if model != "" {
		metadata["model"] = model
	}
	if provider != "" {
		metadata["provider"] = provider
	}
	return metadata
}

func mapFinishReason(reason string) genai.FinishReason {
	switch reason {
	case "":
		return genai.FinishReasonUnspecified
	case "stop":
		return genai.FinishReasonStop
	case "length":
		return genai.FinishReasonMaxTokens
	case "tool_calls":
		return genai.FinishReasonStop
	default:
		return genai.FinishReason(strings.ToUpper(reason))
	}
}
