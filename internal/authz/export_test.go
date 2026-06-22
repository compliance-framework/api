package authz

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseExportFormat(t *testing.T) {
	for _, f := range SupportedExportFormats {
		got, err := ParseExportFormat(strings.ToUpper(string(f)))
		if err != nil {
			t.Errorf("ParseExportFormat(%q) error = %v", f, err)
		}
		if got != f {
			t.Errorf("ParseExportFormat(%q) = %q, want %q", f, got, f)
		}
	}
	if _, err := ParseExportFormat("toml"); err == nil {
		t.Error("expected error for unknown format, got nil")
	}
}

func TestExportAllFormatsNonEmptyAndDeterministic(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatalf("DefaultManifest() error = %v", err)
	}
	for _, f := range SupportedExportFormats {
		first, err := m.Export(f)
		if err != nil {
			t.Fatalf("Export(%q) error = %v", f, err)
		}
		if len(first) == 0 {
			t.Errorf("Export(%q) returned empty output", f)
		}
		second, err := m.Export(f)
		if err != nil {
			t.Fatalf("Export(%q) second error = %v", f, err)
		}
		if !bytes.Equal(first, second) {
			t.Errorf("Export(%q) is not deterministic across calls", f)
		}
	}
}

func TestExportJSONRoundTrips(t *testing.T) {
	m, _ := DefaultManifest()
	out, err := m.Export(ExportJSON)
	if err != nil {
		t.Fatalf("Export(json) error = %v", err)
	}
	var back Manifest
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("json.Unmarshal exported manifest: %v", err)
	}
	if back.SchemaVersion != m.SchemaVersion {
		t.Errorf("round-trip schemaVersion = %d, want %d", back.SchemaVersion, m.SchemaVersion)
	}
	if !back.HasAction(ResourceEvidence, ActionCreate) {
		t.Error("round-tripped JSON manifest missing evidence:create")
	}
}

func TestExportYAMLRoundTrips(t *testing.T) {
	m, _ := DefaultManifest()
	out, err := m.Export(ExportYAML)
	if err != nil {
		t.Fatalf("Export(yaml) error = %v", err)
	}
	back, err := ParseManifest(out)
	if err != nil {
		t.Fatalf("ParseManifest(exported yaml): %v", err)
	}
	if !back.HasAction("risk", "promote") {
		t.Error("round-tripped YAML manifest missing risk:promote")
	}
}

func TestExportCedarShape(t *testing.T) {
	m, _ := DefaultManifest()
	out, _ := m.Export(ExportCedar)
	s := string(out)
	for _, want := range []string{
		"namespace CCF {",
		"entity User",
		"entity Risk",
		"entity ComponentDefinition", // kebab -> PascalCase
		"action \"promote\" appliesTo",
		"action \"users.manage\" appliesTo", // dotted action kept as a quoted id
		"principal: [Agent, User]",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("cedar export missing %q\n---\n%s", want, s)
		}
	}
}

func TestExportOpenFGAShape(t *testing.T) {
	m, _ := DefaultManifest()
	out, _ := m.Export(ExportOpenFGA)
	s := string(out)
	for _, want := range []string{
		"schema 1.1",
		"type user",
		"type risk",
		"type component_definition", // kebab -> snake (valid OpenFGA type)
		"define promote: [agent, user]",
		"define users_manage:", // dotted action sanitized to a valid relation name
	} {
		if !strings.Contains(s, want) {
			t.Errorf("openfga export missing %q\n---\n%s", want, s)
		}
	}
}

// TestExportCedarEntitiesUnique guards the user/agent collision: those names are both a
// subject and a resource, and Cedar/OpenFGA reject a duplicate declaration.
func TestExportCedarEntitiesUnique(t *testing.T) {
	m, _ := DefaultManifest()
	out, _ := m.Export(ExportCedar)
	counts := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "entity ") {
			continue
		}
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(line, "entity "), ";"), "{"))
		counts[name]++
	}
	for name, n := range counts {
		if n > 1 {
			t.Errorf("cedar entity %q declared %d times; must be unique", name, n)
		}
	}
	if counts["User"] != 1 || counts["Agent"] != 1 {
		t.Errorf("User/Agent should each be declared once, got User=%d Agent=%d", counts["User"], counts["Agent"])
	}
}

func TestExportOpenFGATypesUnique(t *testing.T) {
	m, _ := DefaultManifest()
	out, _ := m.Export(ExportOpenFGA)
	counts := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "type ") {
			counts[strings.TrimSpace(strings.TrimPrefix(line, "type "))]++
		}
	}
	for name, n := range counts {
		if n > 1 {
			t.Errorf("openfga type %q declared %d times; must be unique", name, n)
		}
	}
	if counts["user"] != 1 || counts["agent"] != 1 {
		t.Errorf("user/agent should each be declared once, got user=%d agent=%d", counts["user"], counts["agent"])
	}
}

func TestExportUnknownFormat(t *testing.T) {
	m, _ := DefaultManifest()
	if _, err := m.Export(ExportFormat("toml")); err == nil {
		t.Error("expected error exporting unknown format, got nil")
	}
}
