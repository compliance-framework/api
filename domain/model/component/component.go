package component

import (
	"github.com/compliance-framework/configuration-service/domain/model"
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
	Uuid        model.Uuid `json:"uuid" query:"uuid"`
	Type        Type       `json:"type" query:"type"`
	Title       string     `json:"title" query:"title"`
	Description string     `json:"description" query:"description"`

	// A summary of the technological or business purpose of the component.
	Purpose          string           `json:"purpose" query:"purpose"`
	Props            []model.Property `json:"props" query:"props"`
	Links            []model.Link     `json:"links" query:"links"`
	Implementations  []model.Uuid     `json:"control_implementations" query:"control_implementations"`
	ResponsibleRoles []model.Uuid     `json:"responsible_roles" query:"responsible_roles"`
}

// Definition A collection of component descriptions, which may optionally be grouped by capability.
type Definition struct {
	Uuid     model.Uuid `json:"uuid" query:"uuid"`
	Metadata model.Metadata

	// ImportedDefinitions Loads a component definition from another resource.
	// TODO: Does importing move all the definitions into the current definition or does it just reference them?
	ImportedDefinitions []model.Uuid `json:"imported_definitions" query:"imported_definitions"`

	Components   []model.Uuid     `json:"components" query:"components"`
	Capabilities []model.Uuid     `json:"capabilities" query:"capabilities"`
	BackMatter   model.BackMatter `json:"backmatter" query:"backmatter"`
}

type Capability struct {
	Uuid model.Uuid `json:"uuid" query:"uuid"`
	Name string     `json:"name" query:"name"`

	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	model.Props
	model.Links

	IncorporatesComponents []model.Uuid `json:"incorporated_components" query:"incorporated_components"`
	ControlImplementations []model.Uuid `json:"control_implementations" query:"control_implementations"`

	Remarks string `json:"remarks" query:"remarks"`
}

// ControlImplementation Control Implementation Set: Defines how the component or capability supports a set of controls.
type ControlImplementation struct {
	Uuid model.Uuid `json:"uuid" query:"uuid"`

	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	model.Props
	model.Links
	model.Remarks

	// Source A reference to an OSCAL catalog or profile providing the referenced control or sub-control definition.
	// Should be in the format `catalog/{catalog_uuid}` or `profile/{profile_uuid}`.
	// TODO: Need to find a way to handle this in MongoDB. (Maybe add another field to store the source type?)
	Source                  string           `json:"source" query:"source"`
	SetParameters           []ParameterValue `json:"set_parameters" query:"set_parameters"`
	ImplementedRequirements []model.Uuid     `json:"implemented_requirements" query:"implemented_requirements"`
	ResponsibleRoles        []model.Uuid     `json:"responsible_roles" query:"responsible_roles"`
}

// ImplementedRequirement Describes how the containing component or capability implements an individual control.
type ImplementedRequirement struct {
	Uuid model.Uuid `json:"uuid" query:"uuid"`

	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	model.Props
	model.Links
	model.Remarks

	ControlId        model.Uuid                   `json:"control_id" query:"control_id"`
	SetParameters    []ParameterValue             `json:"set_parameters" query:"set_parameters"`
	ResponsibleRoles []model.Uuid                 `json:"responsible_roles" query:"responsible_roles"`
	Statements       []ControlDefinitionStatement `json:"statements" query:"statements"`
}

type ControlDefinitionStatement struct {
	Uuid model.Uuid `json:"uuid" query:"uuid"`

	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	model.Props
	model.Links

	StatementId      string       `json:"statement_id" query:"statement_id"`
	ResponsibleRoles []model.Uuid `json:"responsible_roles" query:"responsible_roles"`
	Remarks          string       `json:"remarks" query:"remarks"`
}

type ParameterValue struct {
	ParamId model.Uuid `json:"parameter" query:"parameter"`
	Values  []string   `json:"values" query:"values"`
	Remarks string     `json:"remarks" query:"remarks"`
}
