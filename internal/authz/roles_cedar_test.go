package authz

import (
	"bytes"
	"strings"
	"testing"
)

// The bundled policies are generated from the manifest roles; they must always be valid
// Cedar (a parse failure here is a CCF bug, not operator error).
func TestCompileRolePoliciesParses(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	ps, err := CompileRolePolicies(m)
	if err != nil {
		t.Fatalf("CompileRolePolicies() error = %v", err)
	}
	n := 0
	for range ps.All() {
		n++
	}
	if n == 0 {
		t.Fatal("CompileRolePolicies() produced no policies")
	}
}

// Output must be deterministic so it is stable for review and golden comparison.
func TestRenderRolePoliciesDeterministic(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	a := renderRolePolicies(m)
	b := renderRolePolicies(m)
	if !bytes.Equal(a, b) {
		t.Fatal("renderRolePolicies() is not deterministic")
	}
}

// Spot-check the shape of the generated policies: the wildcard role drops both scope
// constraints, a read-only role constrains the action only, and a per-resource grant
// constrains by entity type using the same names as the exported schema.
func TestRenderRolePoliciesShape(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	src := string(renderRolePolicies(m))

	for _, want := range []string{
		`principal in CCF::Role::"admin"`,
		`principal in CCF::Role::"viewer"`,
		`action in [CCF::Action::"read"]`,
		`resource is CCF::Evidence`,
		`resource is CCF::PoamItem`, // poam_item -> PoamItem (matches export.go cedarEntityName)
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated policies missing %q\n---\n%s", want, src)
		}
	}

	// admin is "*": ["*"] — an unconstrained permit (bare action + bare resource), so the
	// admin policy line must not pin a resource type.
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, `CCF::Role::"admin"`) && strings.Contains(line, "resource is") {
			t.Errorf("admin grant unexpectedly type-constrained: %q", line)
		}
	}
}
