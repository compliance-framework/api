package authz

import (
	"fmt"
	"os"
	"sort"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

// DefaultAgentRole is the role granted to every authenticated agent when the role-assignment
// file does not say otherwise. It is the manifest's service role (evidence:create,
// heartbeat:ingest, agent:register/ingest), so agents can ingest with zero configuration —
// matching the prior agent-ingest behavior the embedded engine replaces.
const DefaultAgentRole = "agent"

// RoleAssignments is the OSS static role-assignment configuration (BCH-1319 §11.3): a
// GitOps-friendly mapping of principals to one of the bundled roles, with no UI and no DB.
// A subject's effective roles are the union of its direct user grant and a grant for each
// group it belongs to (plus the agent default for agent subjects), so a subject can hold
// several roles even though each principal/group maps to a single role.
//
//   - Users  — by user: `alice@example.com → auditor`. Keyed by the subject's email
//     (subject.id), matched case-insensitively. Works for every user today.
//   - Groups — by group: `sec-team → admin`. Keyed by group name. Live only once the subject
//     carries a groups attribute (native CCF groups ∪ SSO groups), which is BCH-1328's
//     surface; until then this map is inert (no subject has groups), exactly the documented
//     "group-based assignment requires BCH-1328" dependency. Structurally ready so it goes
//     live additively when BCH-1328 lands — no change here.
//   - Agents — the role granted to authenticated agents (default DefaultAgentRole).
type RoleAssignments struct {
	Users  map[string]string `yaml:"users"`
	Groups map[string]string `yaml:"groups"`
	Agents string            `yaml:"agents"`
}

// LoadRoleAssignments reads and parses a role-assignment file. A missing file is returned as
// an os.IsNotExist error so the caller can treat the optional file as "no static assignments"
// (deny-by-default for users, agent default still applies); a malformed file is a hard error
// so a typo fails fast at startup rather than silently denying everyone.
func LoadRoleAssignments(path string) (*RoleAssignments, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: read role assignments %s: %w", path, err)
	}
	var ra RoleAssignments
	if err := yaml.UnmarshalStrict(data, &ra); err != nil {
		return nil, fmt.Errorf("authz: parse role assignments %s: %w", path, err)
	}
	return &ra, nil
}

// normalize lowercases the user/group keys and the agent role, and applies the agent
// default. Email and group matching are case-insensitive; doing it once at load keeps the
// per-request lookups allocation-free. It is idempotent.
func (ra *RoleAssignments) normalize() {
	ra.Users = lowerKeys(ra.Users)
	ra.Groups = lowerKeys(ra.Groups)
	ra.Agents = strings.TrimSpace(ra.Agents)
	if ra.Agents == "" {
		ra.Agents = DefaultAgentRole
	}
}

// lowerKeys returns a copy of m with its keys trimmed and lowercased. Later duplicates (keys
// that collide once lowercased) win, which is deterministic for a config the operator writes.
func lowerKeys(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

// validate checks that every role referenced by the assignments is one the manifest actually
// declares, so a typo (`audtor`) is caught at startup instead of silently granting nothing.
// Call after normalize.
func (ra *RoleAssignments) validate(m *Manifest) error {
	known := func(role string) bool {
		if role == "" {
			return false
		}
		_, ok := m.Roles[role]
		return ok
	}
	var unknown []string
	check := func(kind, principal, role string) {
		if !known(role) {
			unknown = append(unknown, fmt.Sprintf("%s %q → %q", kind, principal, role))
		}
	}
	for u, role := range ra.Users {
		check("user", u, role)
	}
	for g, role := range ra.Groups {
		check("group", g, role)
	}
	if ra.Agents != "" && !known(ra.Agents) {
		unknown = append(unknown, fmt.Sprintf("agents → %q", ra.Agents))
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("authz: role assignments reference unknown role(s): %s (declared roles: %s)",
			strings.Join(unknown, "; "), strings.Join(sortedKeys(m.Roles), ", "))
	}
	return nil
}

// rolesFor returns the effective roles for a subject: the direct user grant, one grant per
// group the subject belongs to, and the agent default for agent subjects. The result is
// sorted and deduplicated so the entity store and any logging are deterministic. An empty
// result means deny-by-default (the subject has no role, so no bundled permit can match).
func (ra *RoleAssignments) rolesFor(s Subject) []string {
	set := map[string]struct{}{}
	switch s.Type {
	case "user":
		if role, ok := ra.Users[strings.ToLower(strings.TrimSpace(s.ID))]; ok && role != "" {
			set[role] = struct{}{}
		}
		for _, g := range subjectGroups(s) {
			if role, ok := ra.Groups[g]; ok && role != "" {
				set[role] = struct{}{}
			}
		}
	case "agent":
		if ra.Agents != "" {
			set[ra.Agents] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	roles := make([]string, 0, len(set))
	for r := range set {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	return roles
}

// subjectGroups extracts the normalized (trimmed, lowercased) group names from a subject's
// groups attribute. The attribute is absent today — it is populated by the consistent native
// ∪ SSO groups surface in BCH-1328 — so this returns nil for current subjects, leaving
// group-based assignment inert until then. It accepts the []string and []any shapes a JSON/
// claims-derived prop may take.
func subjectGroups(s Subject) []string {
	raw, ok := s.Props["groups"]
	if !ok {
		return nil
	}
	var groups []string
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			groups = append(groups, v)
		}
	}
	switch vs := raw.(type) {
	case []string:
		for _, g := range vs {
			add(g)
		}
	case []any:
		for _, g := range vs {
			if str, ok := g.(string); ok {
				add(str)
			}
		}
	}
	return groups
}
