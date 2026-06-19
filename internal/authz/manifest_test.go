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
