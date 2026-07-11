package audit

import "testing"

func TestAgentAtlasActionsAreBoundedAndBackwardCompatible(t *testing.T) {
	if !ValidAction(ActionDreamPolicyCreated) {
		t.Fatal("legacy action rejected")
	}
	if !ValidAction(ActionDreamPolicyCreateRequested) {
		t.Fatal("requested action rejected")
	}
	if ValidAction("unknown") {
		t.Fatal("unknown action accepted")
	}
}
