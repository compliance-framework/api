package authz

import (
	_ "embed"
	"fmt"
	"os"
	"sync"

	yaml "gopkg.in/yaml.v2"
)

//go:embed manifest.yaml
var embeddedManifest []byte

// Manifest is CCF's engine-neutral authorization vocabulary: the subjects, resources,
// actions and suggested default roles that operator policies are written against. It is
// treated as a public contract — renaming an action or removing an attribute is a
// breaking change for every customer policy set.
type Manifest struct {
	SchemaVersion int                            `yaml:"schemaVersion"`
	Subjects      map[string]SubjectDef          `yaml:"subjects"`
	Resources     map[string]ResourceDef         `yaml:"resources"`
	Roles         map[string]map[string][]string `yaml:"roles"`
}

// SubjectDef declares the attributes a subject type exports into the evaluation tuple.
type SubjectDef struct {
	Attributes map[string]string `yaml:"attributes"`
}

// ResourceDef declares a resource's actions and the attributes it exports. The attribute
// set is provisional in Phase 1 (BCH-1319 designs the authoritative surface).
type ResourceDef struct {
	Actions    []string          `yaml:"actions"`
	Attributes map[string]string `yaml:"attributes"`
}

const supportedManifestSchemaVersion = 1

// ParseManifest unmarshals and validates a manifest document.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("authz: parse manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadManifest reads and parses a manifest from disk.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: read manifest %s: %w", path, err)
	}
	return ParseManifest(data)
}

// HasAction reports whether the manifest declares action for the named resource.
func (m *Manifest) HasAction(resource, action string) bool {
	def, ok := m.Resources[resource]
	if !ok {
		return false
	}
	for _, a := range def.Actions {
		if a == action {
			return true
		}
	}
	return false
}

func (m *Manifest) validate() error {
	if m.SchemaVersion != supportedManifestSchemaVersion {
		return fmt.Errorf("authz: unsupported manifest schemaVersion %d (want %d)", m.SchemaVersion, supportedManifestSchemaVersion)
	}
	if len(m.Resources) == 0 {
		return fmt.Errorf("authz: manifest declares no resources")
	}
	return nil
}

var (
	defaultManifestOnce sync.Once
	defaultManifest     *Manifest
	defaultManifestErr  error
)

// DefaultManifest returns the manifest embedded in the binary, parsed once and cached.
// The embedded copy is the source of truth for the builtin driver; operators targeting
// external engines export it via later-phase tooling (ccf authz export). It lives inside
// the package (rather than a repo-root authz/ path) because go:embed cannot reach outside
// the package directory and embedding removes any runtime working-directory dependency.
func DefaultManifest() (*Manifest, error) {
	defaultManifestOnce.Do(func() {
		defaultManifest, defaultManifestErr = ParseManifest(embeddedManifest)
	})
	return defaultManifest, defaultManifestErr
}
