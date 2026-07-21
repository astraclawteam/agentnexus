package gatewayagent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/adk/v2/agent"
	adkrunner "google.golang.org/adk/v2/runner"
	adksession "google.golang.org/adk/v2/session"
	"google.golang.org/genai"

	"google.golang.org/adk/v2/model"
)

// Assistant runs one bounded turn of the operations assistant.
type Assistant struct {
	runner   *adkrunner.Runner
	sessions *TenantScopedSessionService
	policy   Policy
}

// Turn is the result of one assistant turn.
type Turn struct {
	// Text is the assistant's operator-facing answer.
	Text string
	// ToolCalls counts tool invocations, so a caller can see when a turn was
	// cut short by the cap rather than by the assistant finishing.
	ToolCalls int
	// Truncated reports that a bound stopped the turn.
	Truncated bool
}

// NewAssistant composes the agent, the tenant-scoped session service and the
// ADK runner.
//
// AppName is fixed at Runner construction and Run addresses a session by
// (userID, sessionID) - none of which is a tenant. Tenant isolation therefore
// lives in the session service, not in this constructor, and every session
// operation funnels through it.
func NewAssistant(llm model.LLM, policy Policy, diagnostics DiagnosticsService, sessions adksession.Service) (*Assistant, error) {
	if sessions == nil {
		return nil, errors.New("gateway agent: a session service is required")
	}
	built, err := NewAgent(llm, policy, diagnostics)
	if err != nil {
		return nil, err
	}
	scoped := NewTenantScopedSessionService(sessions, AppName)
	run, err := adkrunner.New(adkrunner.Config{
		AppName:        AppName,
		Agent:          built,
		SessionService: scoped,
		// The assistant opens a session on first contact; an operator should
		// not have to provision one before asking a question.
		AutoCreateSession: true,
	})
	if err != nil {
		return nil, fmt.Errorf("build assistant runner: %w", err)
	}
	return &Assistant{runner: run, sessions: scoped, policy: policy}, nil
}

// Ask runs one turn. The tenant must already be bound to ctx from the verified
// browser session; Ask does not accept a tenant argument, so a caller cannot
// pass one that the credential did not prove.
func (a *Assistant) Ask(ctx context.Context, operatorRef, sessionRef, question string) (Turn, error) {
	if a == nil || a.runner == nil {
		return Turn{}, errors.New("gateway agent: assistant unavailable")
	}
	if _, err := TenantFrom(ctx); err != nil {
		return Turn{}, err
	}
	if strings.TrimSpace(operatorRef) == "" || strings.TrimSpace(sessionRef) == "" {
		return Turn{}, errors.New("gateway agent: operator and session references are required")
	}
	if strings.TrimSpace(question) == "" {
		return Turn{}, errors.New("gateway agent: empty question")
	}

	// Every bound is enforced here rather than trusted to the model. A turn
	// that runs long, calls tools in a loop or floods output is a failure mode
	// hostile connector metadata can drive, so each one ends the turn.
	ctx, cancel := context.WithTimeout(ctx, a.policy.Timeout())
	defer cancel()

	var (
		answer    strings.Builder
		toolCalls int
		truncated bool
	)
	for event, err := range a.runner.Run(ctx, operatorRef, sessionRef, genai.NewContentFromText(question, genai.RoleUser), agent.RunConfig{}) {
		if err != nil {
			return Turn{Text: answer.String(), ToolCalls: toolCalls, Truncated: truncated}, err
		}
		if event == nil || event.Content == nil {
			continue
		}
		for _, part := range event.Content.Parts {
			if part == nil {
				continue
			}
			if part.FunctionCall != nil {
				toolCalls++
				if toolCalls > a.policy.MaxToolCalls() {
					truncated = true
					return Turn{Text: answer.String(), ToolCalls: toolCalls, Truncated: true},
						fmt.Errorf("gateway agent: tool-call cap of %d exceeded", a.policy.MaxToolCalls())
				}
			}
			if part.Text == "" {
				continue
			}
			if answer.Len()+len(part.Text) > a.policy.MaxOutputBytes() {
				answer.WriteString(part.Text[:max(0, a.policy.MaxOutputBytes()-answer.Len())])
				truncated = true
				return Turn{Text: answer.String(), ToolCalls: toolCalls, Truncated: true}, nil
			}
			answer.WriteString(part.Text)
		}
	}
	return Turn{Text: answer.String(), ToolCalls: toolCalls, Truncated: truncated}, nil
}
