package config_test

import (
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
)

func TestLoadApprovalDefaultsToUnregistered(t *testing.T) {
	t.Setenv("AGENTNEXUS_APPROVAL_CHANNEL", "")
	cfg, err := config.LoadApproval()
	if err != nil {
		t.Fatalf("unset must not be an error: %v", err)
	}
	if cfg.Registered() {
		t.Error("an unset channel must leave the transmission surface unregistered")
	}
}

func TestLoadApprovalPendingOnlyRegistersTheSurface(t *testing.T) {
	t.Setenv("AGENTNEXUS_APPROVAL_CHANNEL", config.ApprovalChannelPending)
	cfg, err := config.LoadApproval()
	if err != nil {
		t.Fatalf("pending-only: %v", err)
	}
	if !cfg.Registered() {
		t.Error("pending-only must register the surface so callers get a truthful pending status, not a 404")
	}
}

// An operator who asks for a delivery mode this build cannot perform must be
// told at startup. Silently falling back would give them a surface that accepts
// approval plans and delivers none of them, which is the failure mode most
// likely to be discovered by a missed approval.
func TestLoadApprovalRejectsAnUnimplementedMode(t *testing.T) {
	t.Setenv("AGENTNEXUS_APPROVAL_CHANNEL", "http")
	cfg, err := config.LoadApproval()
	if err == nil {
		t.Fatalf("an unimplemented mode must fail closed, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), "http") {
		t.Errorf("error must name the rejected value, got %q", err)
	}
}
