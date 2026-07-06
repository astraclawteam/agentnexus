package llmroutermodel

import (
	"context"
	"iter"
	"strings"

	adkmodel "google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

type Model struct {
	client       *Client
	defaultModel string
	tools        []*genai.Tool
}

func New(cfg Config, tools ...*genai.Tool) (*Model, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &Model{
		client:       client,
		defaultModel: strings.TrimSpace(cfg.DefaultModel),
		tools:        tools,
	}, nil
}

func (m *Model) Name() string {
	if m.defaultModel != "" {
		return m.defaultModel
	}
	return "llmrouter"
}

func (m *Model) GenerateContent(ctx context.Context, req *adkmodel.LLMRequest, stream bool) iter.Seq2[*adkmodel.LLMResponse, error] {
	return func(yield func(*adkmodel.LLMResponse, error) bool) {
		routerReq, err := MapADKRequest(req, m.tools, m.defaultModel, stream)
		if err != nil {
			yield(nil, err)
			return
		}

		resp, routerErr, err := m.client.Chat(ctx, routerReq)
		if err != nil {
			yield(nil, err)
			return
		}
		if routerErr != nil {
			yield(MapLLMRouterError(*routerErr), nil)
			return
		}

		mapped, err := MapLLMRouterResponse(resp, false)
		yield(mapped, err)
	}
}

var _ adkmodel.LLM = (*Model)(nil)
