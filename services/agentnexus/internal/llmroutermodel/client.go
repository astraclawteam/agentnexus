package llmroutermodel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultTimeout = 30 * time.Second

type Config struct {
	BaseURL      string
	APIKey       string
	DefaultModel string
	Timeout      time.Duration
	HTTPClient   *http.Client
}

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func NewClient(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("llmrouter base URL is required")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("llmrouter API key is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = defaultTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}

	return &Client{
		baseURL: baseURL,
		apiKey:  cfg.APIKey,
		http:    httpClient,
	}, nil
}

func (c *Client) Chat(ctx context.Context, req LLMRouterChatRequest) (LLMRouterChatResponse, *LLMRouterErrorResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return LLMRouterChatResponse{}, nil, fmt.Errorf("marshal llmrouter request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return LLMRouterChatResponse{}, nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return LLMRouterChatResponse{}, nil, err
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return LLMRouterChatResponse{}, nil, err
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		routerErr := LLMRouterErrorResponse{}
		if err := json.Unmarshal(body, &routerErr); err != nil || routerErr.Error.Message == "" {
			routerErr.Error = LLMRouterError{
				Code:    httpResp.Status,
				Message: string(body),
				Type:    "llmrouter_http_error",
			}
		}
		return LLMRouterChatResponse{}, &routerErr, nil
	}

	var chatResp LLMRouterChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return LLMRouterChatResponse{}, nil, fmt.Errorf("decode llmrouter response: %w", err)
	}
	return chatResp, nil, nil
}
