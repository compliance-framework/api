package authz

import (
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// cedarNamespace is the Cedar namespace every CCF entity type lives under. It matches the
// schema emitted by `ccf authz export --format=cedar` (export.go), so the bundled policies,
// the exported schema and an operator's own .cedar files all speak the same entity names.
const cedarNamespace = "CCF"

// cedarRoleEntityType is the Cedar entity type for the OSS roles. A subject is granted a
// role by being `in` the corresponding CCF::Role entity (RBAC as Cedar group membership);
// the role→permissions mapping is the bundled policy set compiled from the manifest.
const cedarRoleEntityType = cedarNamespace + "::Role"

// CompileRolePolicies translates the manifest's roles: block into the bundled OSS Cedar
// policy set — the C0 global-RBAC policies the embedded engine is designed to honor
// (BCH-1319 §11.1, §11.3). The manifest roles: block is the single source of truth: each
// role→resource→actions grant becomes one permit policy whose scope references only the
// subject's role membership, the action, and the resource type (C0 — no attribute
// conditions, so the C1/C2 resolvers never fire for these policies, BCH-1319 §11.4).
//
// Operators extend this set via their own .cedar files (the GitOps escape hatch, §11.2);
// because Cedar is deny-by-default with forbid overriding permit, an operator file can both
// add grants and carve exceptions out of the bundled roles without editing CCF.
func CompileRolePolicies(m *Manifest) (*cedar.PolicySet, error) {
	src := renderRolePolicies(m)
	ps, err := cedar.NewPolicySetFromBytes("ccf-roles.cedar", src)
	if err != nil {
		// A parse failure here is a CCF bug (the manifest roles produced invalid Cedar),
		// not operator error — surface the generated source so it is debuggable.
		return nil, fmt.Errorf("authz: compile bundled role policies: %w\n--- generated ---\n%s", err, src)
	}
	return ps, nil
}

// renderRolePolicies emits the bundled role policies as Cedar source text. Output is
// deterministic (roles and resources are walked in sorted order) so it is stable for golden
// tests and diff-friendly if ever exported. It is the policy counterpart to export.go's
// schema rendering and reuses the same entity-name mapping (cedarEntityName).
func renderRolePolicies(m *Manifest) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "// Generated from manifest roles: block (schemaVersion %d) — CCF OSS global-RBAC (C0).\n", m.SchemaVersion)
	b.WriteString("// Bundled policy set honored by the embedded Cedar engine (BCH-1316). Do not edit by hand;\n")
	b.WriteString("// it is regenerated from the manifest at startup. Operator policies live in separate .cedar files.\n")

	for _, role := range sortedKeys(m.Roles) {
		grants := m.Roles[role]
		for _, resourceKey := range sortedKeys(grants) {
			actions := grants[resourceKey]
			if len(actions) == 0 {
				continue
			}
			b.WriteString("\n")
			writeRolePolicy(&b, role, resourceKey, actions)
		}
	}
	return []byte(b.String())
}

// writeRolePolicy emits a single permit policy granting role the given actions on the given
// resource. The wildcard "*" (resource or action) drops the corresponding scope constraint
// so the grant applies to any resource / any action, matching the manifest's "*" semantics.
func writeRolePolicy(b *strings.Builder, role, resourceKey string, actions []string) {
	fmt.Fprintf(b, "// role %q may %s on %s\n", role, strings.Join(actions, ", "), resourceKey)
	b.WriteString("permit (\n")
	fmt.Fprintf(b, "  principal in %s::%q,\n", cedarRoleEntityType, role)
	fmt.Fprintf(b, "  %s,\n", cedarActionClause(actions))
	fmt.Fprintf(b, "  %s\n", cedarResourceClause(resourceKey))
	b.WriteString(");\n")
}

// cedarActionClause renders the action scope. A lone "*" means "any action" → the bare
// `action` head with no constraint; otherwise the actions are listed as an explicit set
// (with no action hierarchy, `action in [..]` is exact membership).
func cedarActionClause(actions []string) string {
	if isWildcard(actions) {
		return "action"
	}
	quoted := make([]string, len(actions))
	for i, a := range actions {
		quoted[i] = fmt.Sprintf("%s::Action::%q", cedarNamespace, a)
	}
	return "action in [" + strings.Join(quoted, ", ") + "]"
}

// cedarResourceClause renders the resource scope. "*" means "any resource" → the bare
// `resource` head; a named resource constrains by entity type (`resource is CCF::Evidence`),
// which is exactly the C0 "subject.role × action × resource.type" decision (BCH-1316).
func cedarResourceClause(resourceKey string) string {
	if resourceKey == "*" {
		return "resource"
	}
	return fmt.Sprintf("resource is %s::%s", cedarNamespace, cedarEntityName(resourceKey))
}

// isWildcard reports whether an action list is the manifest "*" wildcard (all actions).
func isWildcard(actions []string) bool {
	return len(actions) == 1 && actions[0] == "*"
}
