package authz

import "testing"

func TestDefaultManifestParses(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatalf("DefaultManifest() error = %v", err)
	}
	if m.SchemaVersion != supportedManifestSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", m.SchemaVersion, supportedManifestSchemaVersion)
	}

	// The migrated routes' resources must be present in the vocabulary. The enforced
	// umbrella admin action (ActionManage) and the granular admin.* actions both apply.
	if !m.HasAction(ResourceAdmin, ActionManage) {
		t.Errorf("manifest missing enforced admin action %q; resources=%v", ActionManage, m.Resources)
	}
	if !m.HasAction(ResourceAdmin, "users.manage") {
		t.Errorf("manifest missing admin action users.manage; resources=%v", m.Resources)
	}
	for _, action := range []string{ActionRead, ActionCreate, "update", "delete"} {
		if !m.HasAction(ResourceEvidence, action) {
			t.Errorf("manifest missing evidence action %q", action)
		}
	}

	// Subjects and roles are part of the vocabulary too.
	if _, ok := m.Subjects["user"]; !ok {
		t.Errorf("manifest missing user subject")
	}
	if _, ok := m.Roles["admin"]; !ok {
		t.Errorf("manifest missing admin role")
	}

	// DefaultManifest is cached; a second call returns the same pointer.
	if m2, _ := DefaultManifest(); m2 != m {
		t.Errorf("DefaultManifest() not cached: got distinct pointers")
	}
}

func TestParseManifestRejectsUnsupportedSchema(t *testing.T) {
	_, err := ParseManifest([]byte("schemaVersion: 99\nresources:\n  evidence:\n    actions: [read]\n"))
	if err == nil {
		t.Fatal("expected error for unsupported schemaVersion, got nil")
	}
}

func TestParseManifestRejectsNoResources(t *testing.T) {
	_, err := ParseManifest([]byte("schemaVersion: 1\n"))
	if err == nil {
		t.Fatal("expected error for manifest with no resources, got nil")
	}
}

func TestParseManifestRejectsInvalidYAML(t *testing.T) {
	if _, err := ParseManifest([]byte("schemaVersion: : :\n  - bad")); err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestParseManifestRejectsResourceWithoutActions(t *testing.T) {
	_, err := ParseManifest([]byte("schemaVersion: 1\nresources:\n  evidence:\n    attributes:\n      props: set<string>\n"))
	if err == nil {
		t.Fatal("expected error for resource with no actions, got nil")
	}
}

func TestParseManifestRejectsContextAttrWithoutType(t *testing.T) {
	doc := "schemaVersion: 1\nresources:\n  ssp:\n    actions: [read]\n    context:\n      oscal_roles:\n        status: reserved\n"
	if _, err := ParseManifest([]byte(doc)); err == nil {
		t.Fatal("expected error for context attribute without a type, got nil")
	}
}

// TestDefaultManifestCoversArchetypes asserts the full BCH-1314 surface declares one
// resource per route-group across the six archetypes (a representative sample).
func TestDefaultManifestCoversArchetypes(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatalf("DefaultManifest() error = %v", err)
	}
	want := []string{
		// A — OSCAL documents
		"catalog", "profile", "component-definition", "ssp", "assessment-plan",
		"assessment-results", "poam_oscal", "inventory", "party", "role", "activity",
		// B — register items (POAM is two resources)
		"risk", "poam_item",
		// C — telemetry
		"evidence", "heartbeat",
		// D — workflow engine
		"workflow-definition", "workflow-step-definition", "workflow-instance",
		"workflow-execution", "step-execution", "role-assignment", "control-relationship",
		// E — dashboard / config
		"filter", "dashboard-suggestion",
		// F — platform / admin (admin split into its constituents)
		"admin", "user", "agent", "notification", "risk-template", "subject-template",
		"digest", "ai-diagnostics", "import",
	}
	for _, r := range want {
		if _, ok := m.Resources[r]; !ok {
			t.Errorf("manifest missing resource %q", r)
		}
	}

	// Archetype attribute spot-checks (BCH-1319 §12).
	if got := m.Resources["risk"].Attributes["owned_by"]; got != "set<string>" {
		t.Errorf("risk.owned_by = %q, want set<string>", got)
	}
	if got := m.Resources["evidence"].Attributes["labels"]; got != "map<string,string>" {
		t.Errorf("evidence.labels = %q, want map<string,string>", got)
	}
	if got := m.Resources["inventory"].Attributes["ssp_id"]; got != "uuid" {
		t.Errorf("inventory.ssp_id = %q, want uuid", got)
	}
	if _, ok := m.Subjects["user"].Attributes["user_uuid"]; !ok {
		t.Error("user subject missing user_uuid attribute")
	}
}

// TestManifestContextRelationshipAttrs asserts oscal_roles / assigned_to are declared as
// reserved relationship attributes in the context section, not the static attribute map.
func TestManifestContextRelationshipAttrs(t *testing.T) {
	m, _ := DefaultManifest()

	roles, ok := m.Resources["ssp"].Context["oscal_roles"]
	if !ok {
		t.Fatal("ssp missing context.oscal_roles")
	}
	if roles.Status != "reserved" || roles.Relationship == "" || roles.Type == "" {
		t.Errorf("ssp.oscal_roles = %+v, want a reserved relationship attribute with a type", roles)
	}
	if _, leaked := m.Resources["ssp"].Attributes["oscal_roles"]; leaked {
		t.Error("oscal_roles must not appear in the static attribute map")
	}

	for _, r := range []string{"step-execution", "role-assignment"} {
		if _, ok := m.Resources[r].Context["assigned_to"]; !ok {
			t.Errorf("%s missing context.assigned_to", r)
		}
		if _, leaked := m.Resources[r].Attributes["assigned_to"]; leaked {
			t.Errorf("%s.assigned_to must not appear in the static attribute map", r)
		}
	}
}

// TestManifestRolesReferenceDeclaredVocabulary guards the public contract: every role
// grants only resources and actions the manifest actually declares (apart from the "*"
// wildcards), so a default role can never reference a typo'd or removed resource/action.
func TestManifestRolesReferenceDeclaredVocabulary(t *testing.T) {
	m, _ := DefaultManifest()
	for role, grants := range m.Roles {
		for resource, actions := range grants {
			if resource != "*" {
				if _, ok := m.Resources[resource]; !ok {
					t.Errorf("role %q grants unknown resource %q", role, resource)
					continue
				}
			}
			for _, action := range actions {
				if action == "*" || resource == "*" {
					continue
				}
				if !m.HasAction(resource, action) {
					t.Errorf("role %q grants %q:%q which the manifest does not declare", role, resource, action)
				}
			}
		}
	}
}
