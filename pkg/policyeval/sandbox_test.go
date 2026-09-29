package policyeval

import (
	"slices"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
)

// nondeterministicAllowed are the non-deterministic builtins the sandbox keeps: they read
// the clock or a random source, but reach nothing outside the process.
var nondeterministicAllowed = []string{
	"io.jwt.decode_verify",
	"io.jwt.encode_sign",
	"io.jwt.encode_sign_raw",
	"rand.intn",
	"time.now_ns",
	"uuid.rfc4122",
}

func TestSandboxCapabilitiesRemovesDeniedBuiltins(t *testing.T) {
	caps := SandboxCapabilities()
	for _, builtin := range caps.Builtins {
		assert.NotContains(t, DeniedBuiltins, builtin.Name)
	}
	assert.Less(t, len(caps.Builtins), len(ast.CapabilitiesForThisVersion().Builtins))
}

// TestSandboxBuiltinAudit fails when an OPA upgrade adds a non-deterministic builtin, which
// is how OPA marks builtins with side effects such as I/O. Decide whether the new builtin is
// safe, then add it to DeniedBuiltins or nondeterministicAllowed.
func TestSandboxBuiltinAudit(t *testing.T) {
	for _, builtin := range ast.CapabilitiesForThisVersion().Builtins {
		if !builtin.Nondeterministic {
			continue
		}
		if slices.Contains(DeniedBuiltins, builtin.Name) || slices.Contains(nondeterministicAllowed, builtin.Name) {
			continue
		}
		t.Errorf("builtin %q is non-deterministic and not reviewed for the playback sandbox", builtin.Name)
	}
}
