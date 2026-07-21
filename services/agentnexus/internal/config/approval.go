package config

import (
	"fmt"
	"os"
	"strings"
)

// Approval delivery modes.
const (
	// ApprovalChannelNone leaves the transmission surface unregistered. This is
	// the default and preserves the historical behaviour.
	ApprovalChannelNone = "none"
	// ApprovalChannelPending registers the surface with a channel that
	// correlates plans durably but never delivers them, so every transmission
	// stays honestly pending until a real outbound integration exists (B7).
	ApprovalChannelPending = "pending-only"
)

// ApprovalConfig selects this deployment's outbound approval delivery channel.
type ApprovalConfig struct {
	Mode string
}

// Registered reports whether the approval transmission endpoints should be
// served at all.
func (c ApprovalConfig) Registered() bool { return c.Mode == ApprovalChannelPending }

// LoadApproval reads AGENTNEXUS_APPROVAL_CHANNEL. An unrecognised value is an
// error rather than a silent fallback: an operator who sets a mode this build
// does not implement -- "http" against a customer OA, say -- must be told at
// startup, not left with a surface that accepts plans and quietly delivers
// none.
func LoadApproval() (ApprovalConfig, error) {
	mode := strings.TrimSpace(os.Getenv("AGENTNEXUS_APPROVAL_CHANNEL"))
	switch mode {
	case "":
		return ApprovalConfig{Mode: ApprovalChannelNone}, nil
	case ApprovalChannelNone, ApprovalChannelPending:
		return ApprovalConfig{Mode: mode}, nil
	default:
		return ApprovalConfig{}, fmt.Errorf(
			"AGENTNEXUS_APPROVAL_CHANNEL must be %q or %q (got %q); no outbound delivery channel is implemented yet",
			ApprovalChannelNone, ApprovalChannelPending, mode)
	}
}
