package authz

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// manifestYAML is the canonical authorization vocabulary, embedded so a valid
// manifest is always available regardless of deployment layout. Operators may
// override it with an external file (see LoadManifest / authz_manifest_path).
//
//go:embed manifest.yaml
var manifestYAML []byte

// Manifest is CCF's engine-neutral authorization vocabulary: the resources,
// actions and default roles operators can write policies against. It is treated
// as a public API surface — renaming an action or attribute is a breaking
// change for every customer policy set.
type Manifest struct {
	SchemaVersion int                    `yaml:"schemaVersion"`
	Subjects      map[string]SubjectDef  `yaml:"subjects"`
	Resources     map[string]ResourceDef `yaml:"resources"`
	// Roles are suggested defaults: role -> resource -> actions. Operators may
	// override or extend them in their PAP.
	Roles map[string]map[string][]string `yaml:"roles"`
}

// SubjectDef declares the attributes a subject type exports into the evaluation
// tuple.
type SubjectDef struct {
	Attributes map[string]string `yaml:"attributes"`
}

// ResourceDef declares a resource's allowed actions and the attributes it
// exports. Per BCH-1319 the attribute surface is intentionally minimal in this
// phase.
type ResourceDef struct {
	Actions    []string          `yaml:"actions"`
	Attributes map[string]string `yaml:"attributes"`
}

// ParseManifest parses and validates a manifest from YAML bytes.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("authz: parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadManifest reads and validates a manifest from a file path.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: read manifest %q: %w", path, err)
	}
	return ParseManifest(data)
}

// DefaultManifest returns the embedded canonical manifest.
func DefaultManifest() (*Manifest, error) {
	return ParseManifest(manifestYAML)
}

// Validate checks the manifest is structurally sound: a positive schema version
// and at least one resource, each with at least one action.
func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("authz: nil manifest")
	}
	if m.SchemaVersion <= 0 {
		return fmt.Errorf("authz: manifest schemaVersion must be > 0, got %d", m.SchemaVersion)
	}
	if len(m.Resources) == 0 {
		return fmt.Errorf("authz: manifest declares no resources")
	}
	for name, r := range m.Resources {
		if len(r.Actions) == 0 {
			return fmt.Errorf("authz: resource %q declares no actions", name)
		}
	}
	return nil
}

// HasAction reports whether the manifest declares action on resource. It is a
// helper for drivers that wish to validate requested (resource, action) pairs
// against the vocabulary; the builtin driver does not gate on it in Phase 1.
func (m *Manifest) HasAction(resource, action string) bool {
	if m == nil {
		return false
	}
	r, ok := m.Resources[resource]
	if !ok {
		return false
	}
	for _, a := range r.Actions {
		if a == action {
			return true
		}
	}
	return false
}
