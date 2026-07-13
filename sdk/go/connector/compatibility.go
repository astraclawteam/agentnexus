package connector

import (
	"regexp"
	"strings"
)

// semverRe is the strict major.minor.patch form used by compatibility windows.
// A version range is compared numerically (never lexically), so "1.10.0" > "1.9.0".
var semverRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// VersionRange is an inclusive, semver compatibility window. Min is required;
// Max is optional (open-ended forward compatibility). When both are present Min
// must not exceed Max under numeric semver ordering.
type VersionRange struct {
	Min string `json:"min"`
	Max string `json:"max,omitempty"`
}

// Compatibility declares which Agent runtime contract and connector runtime a
// Product Pack supports, plus the prior product versions it supersedes. A pack
// with no declared compatibility is rejected: the release gate must know the
// contract window a resellable pack targets.
type Compatibility struct {
	RuntimeContract    VersionRange `json:"runtime_contract"`
	ConnectorRuntime   VersionRange `json:"connector_runtime"`
	SupersedesVersions []string     `json:"supersedes_versions,omitempty"`
}

// MigrationInfo records how this pack version migrates from earlier ones. The
// object is always present (even if empty) so upgrade tooling has a declared,
// auditable migration surface.
type MigrationInfo struct {
	FromVersions []string `json:"from_versions"`
	Notes        string   `json:"notes,omitempty"`
	Irreversible bool     `json:"irreversible,omitempty"`
}

func validateVersionRange(field string, r VersionRange) error {
	if r.Min == "" {
		return fieldErrorf(field, "min version is required")
	}
	if !semverRe.MatchString(r.Min) {
		return fieldErrorf(field, "min version %q is not semver (major.minor.patch)", r.Min)
	}
	if r.Max != "" {
		if !semverRe.MatchString(r.Max) {
			return fieldErrorf(field, "max version %q is not semver (major.minor.patch)", r.Max)
		}
		if compareSemver(r.Min, r.Max) > 0 {
			return fieldErrorf(field, "min version %q must not exceed max version %q", r.Min, r.Max)
		}
	}
	return nil
}

func validateCompatibility(c Compatibility) error {
	// A pack with no declared compatibility window is rejected: the range
	// validators surface "compatibility.<field>: min version is required" for a
	// zero-valued Compatibility, which is exactly the missing-compatibility case.
	if err := validateVersionRange("compatibility.runtime_contract", c.RuntimeContract); err != nil {
		return err
	}
	if err := validateVersionRange("compatibility.connector_runtime", c.ConnectorRuntime); err != nil {
		return err
	}
	return nil
}

// compareSemver compares two strict semver strings numerically. It assumes both
// have already matched semverRe; malformed segments compare as 0.
func compareSemver(a, b string) int {
	pa, pb := parseSemver(a), parseSemver(b)
	for i := 0; i < 3; i++ {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}

func parseSemver(s string) [3]int {
	var out [3]int
	for i, part := range strings.SplitN(s, ".", 3) {
		if i > 2 {
			break
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}
