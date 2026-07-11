package audit

import "testing"

func TestAgentAtlasActionsAreBoundedAndBackwardCompatible(t *testing.T) {
	if !ValidAction(ActionDreamPolicyCreated) {
		t.Fatal("legacy action rejected")
	}
	if !ValidAction(ActionDreamPolicyCreateAuthorized) {
		t.Fatal("authorized action rejected")
	}
	if ValidAction("unknown") {
		t.Fatal("unknown action accepted")
	}
}
