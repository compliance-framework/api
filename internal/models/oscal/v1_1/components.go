package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// Base64 A resource encoded using the Base64 alphabet defined by RFC 2045.
// ControlImplementation Describes how the containing component or capability implements an individual catalog.
type ComponentDefinitionControlImplementation struct {

	// A reference to a catalog with a corresponding id value. When referencing an externally defined catalog, the Control Identifier Reference must be used in the context of the external / imported OSCAL instance (e.g., uri-reference).
	ControlId string `json:"catalog-id"`

	// A suggestion from the supplier (e.g., component vendor or author) for how the specified catalog may be implemented if the containing component or capability is instantiated in a system security plan.
	Description      string                            `json:"description"`
	Links            []*Link                           `json:"links,omitempty"`
	Props            []*Property                       `json:"props,omitempty"`
	Remarks          string                            `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole                `json:"responsible-roles,omitempty"`
	SetParameters    []*SetParameterValue              `json:"set-parameters,omitempty"`
	Statements       []*ControlStatementImplementation `json:"statements,omitempty"`

	// Provides a globally unique means to identify a given catalog implementation by a component.
	Uuid string `json:"uuid"`
}

// ControlImplementationSet Defines how the component or capability supports a set of controls.
type ControlImplementationSet struct {

	// A description of how the specified set of controls are implemented for the containing component or capability.
	Description             string                                      `json:"description"`
	ImplementedRequirements []*ComponentDefinitionControlImplementation `json:"implemented-requirements"`
	Links                   []*Link                                     `json:"links,omitempty"`
	Props                   []*Property                                 `json:"props,omitempty"`
	SetParameters           []*SetParameterValue                        `json:"set-parameters,omitempty"`

	// A reference to an OSCAL catalog or profile providing the referenced catalog or subcontrol definition.
	Source string `json:"source"`

	// Provides a means to identify a set of catalog implementations that are supported by a given component or capability.
	Uuid string `json:"uuid"`
}

// ControlStatementImplementation Identifies which statements within a catalog are addressed.
type ControlStatementImplementation struct {

	// A summary of how the containing catalog statement is implemented by the component or capability.
	Description      string             `json:"description"`
	Links            []*Link            `json:"links,omitempty"`
	Props            []*Property        `json:"props,omitempty"`
	Remarks          string             `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// A human-oriented identifier reference to a catalog statement.
	StatementId string `json:"statement-id"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this catalog statement elsewhere in this or other OSCAL instances. The UUID of the catalog statement in the source OSCAL instance is sufficient to reference the data item locally or globally (e.g., in an imported OSCAL instance).
	Uuid string `json:"uuid"`
}

// ImportComponentDefinition Loads a component definition from another resource.
type ImportComponentDefinition struct {

	// A link to a resource that defines a set of components and/or capabilities to import into this collection.
	Href string `json:"href"`
}

// IncorporatesComponent The collection of components comprising this capability.
type IncorporatesComponent struct {

	// A machine-oriented identifier reference to a component.
	ComponentUuid string `json:"component-uuid"`

	// A description of the component, including information about its function.
	Description string `json:"description"`
}

// ComponentDefinitionCapability A grouping of other components and/or capabilities.
type ComponentDefinitionCapability struct {
	ControlImplementations []*ControlImplementationSet `json:"catalog-implementations,omitempty"`

	// A summary of the capability.
	Description            string                   `json:"description"`
	IncorporatesComponents []*IncorporatesComponent `json:"incorporates-components,omitempty"`
	Links                  []*Link                  `json:"links,omitempty"`

	// The capability's human-readable name.
	Name    string      `json:"name"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`

	// Provides a globally unique means to identify a given capability.
	Uuid string `json:"uuid"`
}

// DefinedComponent A defined component that can be part of an implemented system.
type DefinedComponent struct {
	ControlImplementations []*ControlImplementationSet `json:"catalog-implementations,omitempty"`

	// A description of the component, including information about its function.
	Description string                        `json:"description"`
	Links       []*Link                       `json:"links,omitempty"`
	Props       []*Property                   `json:"props,omitempty"`
	Protocols   []*ServiceProtocolInformation `json:"protocols,omitempty"`

	// A summary of the technological or business purpose of the component.
	Purpose          string             `json:"purpose,omitempty"`
	Remarks          string             `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// A human readable name for the component.
	Title string `json:"title"`

	// A category describing the purpose of the component.
	Type interface{} `json:"type"`

	// Provides a globally unique means to identify a given component.
	Uuid string `json:"uuid"`
}

// ComponentDefinition A collection of component descriptions, which may optionally be grouped by capability.
type ComponentDefinition struct {
	BackMatter                 *BackMatter                      `json:"back-matter,omitempty"`
	Capabilities               []*ComponentDefinitionCapability `json:"capabilities,omitempty"`
	Components                 []*DefinedComponent              `json:"components,omitempty"`
	ImportComponentDefinitions []*ImportComponentDefinition     `json:"import-component-definitions,omitempty"`
	Metadata                   map[string]interface{}           `json:"metadata"`

	// Provides a globally unique means to identify a given component definition instance.
	Uuid string `json:"uuid" query:"uuid"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *ComponentDefinition) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *ComponentDefinition) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *ComponentDefinition) DeepCopy() schema.BaseModel {
	d := &ComponentDefinition{}
	p, err := c.ToJSON()
	if err != nil {
		panic(err)
	}
	err = d.FromJSON(p)
	if err != nil {
		panic(err)
	}
	return d
}

func (c *ComponentDefinition) UUID() string {
	return c.Uuid
}

func (c *ComponentDefinition) Validate() error {
	//TODO Implement logic as defined in OSCAL
	return nil
}
func (c *ComponentDefinition) Type() string {
	return "components"
}

func init() {
	schema.MustRegister("components", &ComponentDefinition{})
}
