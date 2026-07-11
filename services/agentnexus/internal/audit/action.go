package audit

type Action string

const (
	ActionWorkflowDraftCreated       Action = "workflow_draft_created"
	ActionWorkflowVersionPublished   Action = "workflow_version_published"
	ActionDreamPolicyCreated         Action = "dream_policy_created"
	ActionDreamPolicyCreateRequested Action = "dream_policy_create_requested"
	ActionDreamJobRun                Action = "dream_job_run"
	ActionRetrievalPlanCreated       Action = "retrieval_plan_created"
	ActionEvidenceLocated            Action = "evidence_located"
	ActionEvidenceRead               Action = "evidence_read"
	ActionAnswerTraceCreated         Action = "answer_trace_created"
	ActionSensitiveArtifactParsed    Action = "sensitive_artifact_parsed"
	ActionVisibilityRuleChanged      Action = "visibility_rule_changed"
)

func ValidAction(action Action) bool {
	switch action {
	case ActionWorkflowDraftCreated, ActionWorkflowVersionPublished,
		ActionDreamPolicyCreated, ActionDreamPolicyCreateRequested,
		ActionDreamJobRun, ActionRetrievalPlanCreated, ActionEvidenceLocated,
		ActionEvidenceRead, ActionAnswerTraceCreated, ActionSensitiveArtifactParsed,
		ActionVisibilityRuleChanged:
		return true
	default:
		return false
	}
}
