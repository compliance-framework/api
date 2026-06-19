package authz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultManifest(t *testing.T) {
	m, err := DefaultManifest()
	require.NoError(t, err)
	require.Equal(t, 1, m.SchemaVersion)
	require.Contains(t, m.Resources, "evidence")
	require.Contains(t, m.Resources, "admin")
	require.True(t, m.HasAction("evidence", "create"))
	require.True(t, m.HasAction("admin", "manage"))
	require.False(t, m.HasAction("evidence", "delete"))
	require.False(t, m.HasAction("unknown", "create"))
}

func TestParseManifest_Valid(t *testing.T) {
	m, err := ParseManifest([]byte(`
schemaVersion: 1
resources:
  evidence:
    actions: [read, create]
`))
	require.NoError(t, err)
	require.True(t, m.HasAction("evidence", "read"))
}

func TestParseManifest_InvalidYAML(t *testing.T) {
	_, err := ParseManifest([]byte("schemaVersion: 1\nresources: [this is not a map"))
	require.Error(t, err)
}

func TestManifest_Validate(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"zero schema version", "schemaVersion: 0\nresources:\n  x:\n    actions: [a]\n"},
		{"no resources", "schemaVersion: 1\n"},
		{"resource without actions", "schemaVersion: 1\nresources:\n  x:\n    actions: []\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tc.yaml))
			require.Error(t, err)
		})
	}
}

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")
	require.NoError(t, os.WriteFile(path, []byte("schemaVersion: 1\nresources:\n  evidence:\n    actions: [read]\n"), 0o600))

	m, err := LoadManifest(path)
	require.NoError(t, err)
	require.True(t, m.HasAction("evidence", "read"))

	_, err = LoadManifest(filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)
}
