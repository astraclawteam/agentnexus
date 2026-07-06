package integration

import (
	"os"
	"testing"
)

func TestConnectorAgentIntegration(t *testing.T) {
	if os.Getenv("AGENTNEXUS_TEST_NATS_URL") == "" {
		t.Skip("AGENTNEXUS_TEST_NATS_URL is not set")
	}
	t.Skip("connector-agent NATS integration requires a published connector instance fixture")
}
