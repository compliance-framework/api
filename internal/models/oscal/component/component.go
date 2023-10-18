package component

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Type int

const (
	Interconnection Type = iota
	Software
	Hardware
	Service
	Policy
	Physical
	ProcessProcedure
	Plan
	Guidance
	Standard
	Validation
)

// Component A defined component that can be part of an implemented system.
// Notes:
// - Implemented Protocols from OSCAL is not implemented. They can always be added as props.
type Component struct {
	Uuid        oscal.Uuid `json:"uuid" query:"uuid"`
	Type        Type       `json:"type" query:"type"`
	Title       string     `json:"title" query:"title"`
	Description string     `json:"description" query:"description"`

	// A summary of the technological or business purpose of the component.
	Purpose          string           `json:"purpose" query:"purpose"`
	Props            []oscal.Property `json:"props" query:"props"`
	Links            []metadata.Link  `json:"links" query:"links"`
	Implementations  []oscal.Uuid     `json:"control_implementations" query:"control_implementations"`
	ResponsibleRoles []oscal.Uuid     `json:"responsible_roles" query:"responsible_roles"`
}

// Definition A collection of component descriptions, which may optionally be grouped by capability.
type Definition struct {
	Uuid     oscal.Uuid `json:"uuid" query:"uuid"`
	Metadata oscal.Metadata

	// ImportedDefinitions Loads a component definition from another resource.
	// TODO: Does importing move all the definitions into the current definition or does it just reference them?
	ImportedDefinitions []oscal.Uuid `json:"imported_definitions" query:"imported_definitions"`

	Components   []oscal.Uuid     `json:"components" query:"components"`
	Capabilities []oscal.Uuid     `json:"capabilities" query:"capabilities"`
	BackMatter   oscal.BackMatter `json:"backmatter" query:"backmatter"`
}

type Capability struct {
	Uuid oscal.Uuid `json:"uuid" query:"uuid"`
	Name string     `json:"name" query:"name"`

	oscal.ComprehensiveDetails

	IncorporatesComponents []oscal.Uuid `json:"incorporated_components" query:"incorporated_components"`
	ControlImplementations []oscal.Uuid `json:"control_implementations" query:"control_implementations"`

	Remarks string `json:"remarks" query:"remarks"`
}

// ControlImplementation Control Implementation Set: Defines how the component or capability supports a set of controls.
type ControlImplementation struct {
	Uuid oscal.Uuid `json:"uuid" query:"uuid"`

	oscal.ComprehensiveDetails

	// Source A reference to an OSCAL catalog or profile providing the referenced control or sub-control definition.
	// Should be in the format `catalog/{catalog_uuid}` or `profile/{profile_uuid}`.
	// TODO: Need to find a way to handle this in MongoDB. (Maybe add another field to store the source type?)
	Source                  string           `json:"source" query:"source"`
	SetParameters           []ParameterValue `json:"set_parameters" query:"set_parameters"`
	ImplementedRequirements []oscal.Uuid     `json:"implemented_requirements" query:"implemented_requirements"`
	ResponsibleRoles        []oscal.Uuid     `json:"responsible_roles" query:"responsible_roles"`
}

// ImplementedRequirement Describes how the containing component or capability implements an individual control.
type ImplementedRequirement struct {
	Uuid oscal.Uuid `json:"uuid" query:"uuid"`

	oscal.ComprehensiveDetails

	ControlId        oscal.Uuid                   `json:"control_id" query:"control_id"`
	SetParameters    []ParameterValue             `json:"set_parameters" query:"set_parameters"`
	ResponsibleRoles []oscal.Uuid                 `json:"responsible_roles" query:"responsible_roles"`
	Statements       []ControlDefinitionStatement `json:"statements" query:"statements"`
}

type ControlDefinitionStatement struct {
	Uuid oscal.Uuid `json:"uuid" query:"uuid"`

	oscal.ComprehensiveDetails

	StatementId      string       `json:"statement_id" query:"statement_id"`
	ResponsibleRoles []oscal.Uuid `json:"responsible_roles" query:"responsible_roles"`
	Remarks          string       `json:"remarks" query:"remarks"`
}

type ParameterValue struct {
	ParamId oscal.Uuid `json:"parameter" query:"parameter"`
	Values  []string   `json:"values" query:"values"`
	Remarks string     `json:"remarks" query:"remarks"`
}
