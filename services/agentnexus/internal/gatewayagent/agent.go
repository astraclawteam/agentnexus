package gatewayagent

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/tool"
)

// AppName is the ADK app name. It is fixed at Runner construction and is the
// base the tenant-scoped session service namespaces per tenant.
const AppName = "agentnexus-gateway-agent"

// AgentName is the ADK agent name. ADK reserves "user", and the name must be
// unique within the agent tree.
const AgentName = "nexus-ops-assistant"

// instructionPreamble is the fixed half of the operator-facing brief.
//
// It states the boundary in plain language for the operator's benefit, but it
// is NOT what enforces the boundary: the policy allow-list decides which tools
// exist, the tools ground every fact in a deterministic service, and the
// session service scopes by tenant. Those hold even if this text is ignored,
// contradicted, or overridden by hostile content arriving through connector
// metadata - which is exactly what an instruction alone cannot survive.
//
// Note what this text does NOT contain: a list of what the assistant can do.
// That list is generated in buildInstruction from the tools that were actually
// built, because a hand-written one drifts. It previously advertised five
// capabilities while two tools existed, so the model was told to call three
// tools that were never registered - the assistant's first move on those
// questions was a call that could only fail.
const instructionPreamble = `You are the AgentNexus operations assistant.

You help an operator understand and prepare.

You do not decide business risk, choose approvers, issue grants, execute
actions, read business data, change policy, install packages, or reveal secret
values. If asked to do any of those, say plainly that it is outside what you
can do and point to the person or screen that owns it.

State only facts your tools returned. If a tool did not tell you something, say
you do not know and say which check would answer it. Never guess a health
state, an error cause, or a configuration value.

Write for an operator who may not be technical: short sentences, concrete next
steps, no jargon that the tool output did not already use.`

// buildInstruction composes the brief from the tools that were actually built.
//
// Deriving the capability list rather than writing it is what keeps the two in
// step. The allow-list may name a capability whose tool has not been written
// yet; when it does, the model is simply never told about it, instead of being
// promised a tool that does not exist.
func buildInstruction(tools []tool.Tool) string {
	var brief strings.Builder
	brief.WriteString(instructionPreamble)
	brief.WriteString("\n\nThese are the only tools you have:\n")
	for _, built := range tools {
		fmt.Fprintf(&brief, "\n- %s: %s", built.Name(), built.Description())
	}
	brief.WriteString("\n\nIf answering would need something no tool above covers, say so plainly and\nname the person or screen that owns it. Do not describe it as something you\ncan do.")
	return brief.String()
}

// NewAgent builds the bounded operations assistant.
//
// The model is supplied as a model.LLM implementation. That is the single seam
// through which this service reaches a model at all, and it is why the
// llmrouter adapter is the only outbound path: nothing here can construct a
// provider client, and TestOnlyLLMRouterOutbound fails the build if anything
// tries.
func NewAgent(llm model.LLM, policy Policy, diagnostics DiagnosticsService) (agent.Agent, error) {
	if llm == nil {
		return nil, errors.New("gateway agent: a model is required")
	}
	tools, err := NewTools(policy, diagnostics)
	if err != nil {
		return nil, err
	}
	built, err := llmagent.New(llmagent.Config{
		Name:        AgentName,
		Description: "Bounded AgentNexus operations assistant: health, error explanation, connector onboarding preparation and draft validation.",
		Model:       llm,
		Instruction: buildInstruction(tools),
		Tools:       tools,
	})
	if err != nil {
		return nil, fmt.Errorf("build operations assistant: %w", err)
	}
	return built, nil
}
