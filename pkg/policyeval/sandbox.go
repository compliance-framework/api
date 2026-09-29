package policyeval

import (
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// DeniedBuiltins are the builtins that reach outside the evaluator: the network or the
// host process. Policies that call one fail to compile under SandboxCapabilities.
var DeniedBuiltins = []string{
	"http.send",
	"net.lookup_ip_addr",
	"opa.runtime",
}

// SandboxCapabilities returns this OPA version's capabilities with DeniedBuiltins removed.
// Each call returns a fresh copy that the caller may modify.
func SandboxCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	builtins := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, builtin := range caps.Builtins {
		if slices.Contains(DeniedBuiltins, builtin.Name) {
			continue
		}
		builtins = append(builtins, builtin)
	}
	caps.Builtins = builtins
	return caps
}
