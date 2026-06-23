package authz

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadRoleAssignments(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "roles.yaml")
	if err := os.WriteFile(valid, []byte(`
users:
  Alice@Example.com: auditor
  bob@example.com: admin
groups:
  Sec-Team: admin
agents: agent
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ra, err := LoadRoleAssignments(valid)
	if err != nil {
		t.Fatalf("LoadRoleAssignments() error = %v", err)
	}
	ra.normalize()
	// Keys are lowercased so lookups are case-insensitive.
	if got := ra.Users["alice@example.com"]; got != "auditor" {
		t.Errorf("users[alice] = %q, want auditor", got)
	}
	if got := ra.Groups["sec-team"]; got != "admin" {
		t.Errorf("groups[sec-team] = %q, want admin", got)
	}
	if ra.Agents != "agent" {
		t.Errorf("agents = %q, want agent", ra.Agents)
	}

	// Missing file surfaces as fs.ErrNotExist so the cedar factory can treat the optional
	// file as "no static assignments" rather than failing startup.
	if _, err := LoadRoleAssignments(filepath.Join(dir, "nope.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file error = %v, want fs.ErrNotExist", err)
	}

	// A malformed file is a hard error (a typo must not silently deny everyone).
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("users: [this, is, not, a, map]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoleAssignments(bad); err == nil {
		t.Error("LoadRoleAssignments(malformed) error = nil, want error")
	}

	// Unknown YAML keys are rejected (strict) so a misremembered field name is caught.
	unknown := filepath.Join(dir, "unknown.yaml")
	if err := os.WriteFile(unknown, []byte("user:\n  a@b.com: admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoleAssignments(unknown); err == nil {
		t.Error("LoadRoleAssignments(unknown key) error = nil, want error")
	}
}

func TestRoleAssignmentsNormalizeDefaultsAgent(t *testing.T) {
	ra := &RoleAssignments{}
	ra.normalize()
	if ra.Agents != DefaultAgentRole {
		t.Errorf("default agents = %q, want %q", ra.Agents, DefaultAgentRole)
	}
	// An explicit agent role is preserved.
	ra2 := &RoleAssignments{Agents: "viewer"}
	ra2.normalize()
	if ra2.Agents != "viewer" {
		t.Errorf("explicit agents = %q, want viewer", ra2.Agents)
	}
}

func TestRoleAssignmentsValidate(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}

	ok := &RoleAssignments{Users: map[string]string{"a@b.com": "auditor"}, Agents: "agent"}
	ok.normalize()
	if err := ok.validate(m); err != nil {
		t.Errorf("validate(known roles) error = %v, want nil", err)
	}

	for name, ra := range map[string]*RoleAssignments{
		"unknown user role":  {Users: map[string]string{"a@b.com": "audtor"}},
		"unknown group role": {Groups: map[string]string{"g": "supervisor"}},
		"unknown agent role": {Agents: "robot"},
	} {
		ra.normalize()
		if err := ra.validate(m); err == nil {
			t.Errorf("validate(%s) error = nil, want error", name)
		}
	}
}

func TestRolesFor(t *testing.T) {
	ra := &RoleAssignments{
		Users:  map[string]string{"alice@example.com": "viewer"},
		Groups: map[string]string{"sec-team": "auditor", "ops": "admin"},
		Agents: "agent",
	}
	ra.normalize()

	tests := []struct {
		name string
		subj Subject
		want []string
	}{
		{
			name: "direct user grant, case-insensitive",
			subj: Subject{Type: "user", ID: "Alice@Example.com"},
			want: []string{"viewer"},
		},
		{
			name: "unassigned user gets nothing (deny-by-default)",
			subj: Subject{Type: "user", ID: "nobody@example.com"},
			want: nil,
		},
		{
			name: "group grant via groups prop",
			subj: Subject{Type: "user", ID: "x@example.com", Props: map[string]any{"groups": []string{"sec-team"}}},
			want: []string{"auditor"},
		},
		{
			name: "union of direct + multiple groups, sorted+deduped",
			subj: Subject{Type: "user", ID: "alice@example.com", Props: map[string]any{"groups": []any{"sec-team", "ops"}}},
			want: []string{"admin", "auditor", "viewer"},
		},
		{
			name: "agent gets the default agent role",
			subj: Subject{Type: "agent", ID: "agent-1"},
			want: []string{"agent"},
		},
		{
			name: "anonymous gets nothing",
			subj: Subject{Type: "anonymous"},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ra.rolesFor(tt.subj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rolesFor() = %v, want %v", got, tt.want)
			}
		})
	}
}
