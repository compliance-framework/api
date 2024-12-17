package domain

type ComponentType int

const (
	InterconnectionComponentType ComponentType = iota
	SoftwareComponentType
	HardwareComponentType
	ServiceComponentType
	PolicyComponentType
	PhysicalComponentType
	ProcessProcedureComponentType
	PlanComponentType
	GuidanceComponentType
	StandardComponentType
	ValidationComponentType
)

// Component A defined component that can be part of an implemented system.
// Notes:
// - Implemented Protocols from OSCAL is not implemented. They can always be added as props.
type Component struct {
	Uuid        Uuid          `json:"uuid" query:"uuid" yaml:"uuid"`
	Type        ComponentType `json:"type" query:"type" yaml:"type"`
	Title       string        `json:"title" query:"title" yaml:"title"`
	Description string        `json:"description" query:"description" yaml:"description"`

	// A summary of the technological or business purpose of the component.
	Purpose          string     `json:"purpose" query:"purpose" yaml:"purpose"`
	Props            []Property `json:"props" query:"props" yaml:"props"`
	Links            []Link     `json:"links" query:"links" yaml:"links"`
	Implementations  []Uuid     `json:"control_implementations" query:"control_implementations" yaml:"control_implementations"`
	ResponsibleRoles []Uuid     `json:"responsible_roles" query:"responsible_roles" yaml:"responsible_roles"`
}

// Definition A collection of component descriptions, which may optionally be grouped by capability.
type Definition struct {
	Uuid     Uuid     `json:"uuid" query:"uuid" yaml:"uuid"`
	Metadata Metadata `yaml:"metadata"`

	// ImportedDefinitions Loads a component definition from another resource.
	// TODO: Does importing move all the definitions into the current definition or does it just reference them?
	ImportedDefinitions []Uuid `json:"imported_definitions" query:"imported_definitions" yaml:"imported_definitions"`

	Components   []Uuid     `json:"components" query:"components" yaml:"components"`
	Capabilities []Uuid     `json:"capabilities" query:"capabilities" yaml:"capabilities"`
	BackMatter   BackMatter `json:"backmatter" query:"backmatter" yaml:"backmatter"`
}

type Capability struct {
	Uuid Uuid   `json:"uuid" query:"uuid" yaml:"uuid"`
	Name string `json:"name" query:"name" yaml:"name"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`

	IncorporatesComponents []Uuid `json:"incorporated_components" query:"incorporated_components" yaml:"incorporated_components"`
	ControlImplementations []Uuid `json:"control_implementations" query:"control_implementations" yaml:"control_implementations"`

	Remarks string `json:"remarks" query:"remarks" yaml:"remarks"`
}

// ControlImplementation Control Implementation Set: Defines how the component or capability supports a set of controls.
type ControlImplementation struct {
	Uuid Uuid `json:"uuid" query:"uuid" yaml:"uuid"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// Source A reference to an OSCAL catalog or profile providing the referenced control or sub-control definition.
	// Should be in the format `catalog/{catalog_uuid}` or `profile/{profile_uuid}`.
	// TODO: Need to find a way to handle this in MongoDB. (Maybe add another field to store the source type?)
	Source                  string           `json:"source" query:"source" yaml:"source"`
	SetParameters           []ParameterValue `json:"set_parameters" query:"set_parameters" yaml:"set_parameters"`
	ImplementedRequirements []Uuid           `json:"implemented_requirements" query:"implemented_requirements" yaml:"implemented_requirements"`
	ResponsibleRoles        []Uuid           `json:"responsible_roles" query:"responsible_roles" yaml:"responsible_roles"`
}

// ImplementedRequirement Describes how the containing component or capability implements an individual control.
type ImplementedRequirement struct {
	Uuid Uuid `json:"uuid" query:"uuid" yaml:"uuid"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	ControlId        Uuid                         `json:"control_id" query:"control_id" yaml:"control_id"`
	SetParameters    []ParameterValue             `json:"set_parameters" query:"set_parameters" yaml:"set_parameters"`
	ResponsibleRoles []Uuid                       `json:"responsible_roles" query:"responsible_roles" yaml:"responsible_roles"`
	Statements       []ControlDefinitionStatement `json:"statements" query:"statements" yaml:"statements"`
}

type ControlDefinitionStatement struct {
	Uuid Uuid `json:"uuid" query:"uuid" yaml:"uuid"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`

	StatementId      string `json:"statement_id" query:"statement_id" yaml:"statement_id"`
	ResponsibleRoles []Uuid `json:"responsible_roles" query:"responsible_roles" yaml:"responsible_roles"`
	Remarks          string `json:"remarks" query:"remarks" yaml:"remarks"`
}

type ParameterValue struct {
	ParamId Uuid     `json:"parameter" query:"parameter" yaml:"parameter"`
	Values  []string `json:"values" query:"values" yaml:"values"`
	Remarks string   `json:"remarks" query:"remarks" yaml:"remarks"`
}
