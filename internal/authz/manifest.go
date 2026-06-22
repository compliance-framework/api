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
	SchemaVersion int                            `yaml:"schemaVersion" json:"schemaVersion"`
	Subjects      map[string]SubjectDef          `yaml:"subjects" json:"subjects,omitempty"`
	Resources     map[string]ResourceDef         `yaml:"resources" json:"resources"`
	Roles         map[string]map[string][]string `yaml:"roles" json:"roles,omitempty"`
}

// SubjectDef declares the attributes a subject type exports into the evaluation tuple.
type SubjectDef struct {
	Attributes map[string]string `yaml:"attributes" json:"attributes,omitempty"`
}

// ResourceDef declares a resource's actions and the attributes it exports. Attributes are
// the C0/C1/C2 static props the PEP supplies directly (a request param or one resource-row
// load); Context holds relationship attributes that don't fit a static prop and are
// resolved lazily by a PIP (BCH-1319 §7.1, §8).
type ResourceDef struct {
	Actions    []string               `yaml:"actions" json:"actions"`
	Attributes map[string]string      `yaml:"attributes,omitempty" json:"attributes,omitempty"`
	Context    map[string]ContextAttr `yaml:"context,omitempty" json:"context,omitempty"`
}

// ContextAttr declares a relationship attribute exposed in the evaluation tuple's context
// rather than as a static subject or resource prop. These are (subject × resource)
// relationship attributes (e.g. oscal_roles, assigned_to) the PEP cannot read from a single
// row; a PIP resolves them lazily when a policy references them (BCH-1319 §7.1, §8). They
// are declared in the public contract now but reserved — no resolver or policy consumes
// them yet — so they are kept out of the static Attributes map until then.
type ContextAttr struct {
	Type         string `yaml:"type" json:"type"`
	Relationship string `yaml:"relationship,omitempty" json:"relationship,omitempty"`
	Status       string `yaml:"status,omitempty" json:"status,omitempty"`
	Note         string `yaml:"note,omitempty" json:"note,omitempty"`
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
	for name, def := range m.Resources {
		if len(def.Actions) == 0 {
			return fmt.Errorf("authz: resource %q declares no actions", name)
		}
		for attr, c := range def.Context {
			if c.Type == "" {
				return fmt.Errorf("authz: resource %q context attribute %q has no type", name, attr)
			}
		}
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
