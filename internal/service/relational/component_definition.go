package relational

import (
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// ComponentDefinition represents a component definition in OSCAL.
// It includes metadata, back matter, imported component definitions, components, and capabilities.
type ComponentDefinition struct {
	UUIDModel             // required
	Metadata   Metadata   `json:"metadata" gorm:"polymorphic:Parent;"` // required
	BackMatter BackMatter `json:"back-matter" gorm:"polymorphic:Parent;"`

	ImportComponentDefinitions datatypes.JSONSlice[ImportComponentDefinition] `json:"import-component-definitions"`
	Components                 []DefinedComponent                             `json:"components"`
	Capabilities               []Capability                                   `json:"capabilities"`
}

// UnmarshalOscal converts an OSCAL ComponentDefinition into a relational ComponentDefinition.
// It includes metadata, import component definitions, components, and capabilities.
func (c *ComponentDefinition) UnmarshalOscal(ocd oscalTypes_1_1_3.ComponentDefinition) *ComponentDefinition {
	metadata := &Metadata{}
	metadata.UnmarshalOscal(ocd.Metadata)
	id := uuid.MustParse(ocd.UUID)

	importComponentDefs := ConvertList(ocd.ImportComponentDefinitions, func(oicd oscalTypes_1_1_3.ImportComponentDefinition) ImportComponentDefinition {
		compDef := ImportComponentDefinition{}
		compDef.UnmarshalOscal(oicd)
		return compDef
	})

	components := ConvertList(ocd.Components, func(odc oscalTypes_1_1_3.DefinedComponent) DefinedComponent {
		dc := &DefinedComponent{}
		dc.UnmarshalOscal(odc)
		return *dc
	})

	capabilities := ConvertList(ocd.Capabilities, func(oc oscalTypes_1_1_3.Capability) Capability {
		cap := Capability{}
		cap.UnmarshalOscal(oc)
		return cap
	})

	var backMatter BackMatter
	if ocd.BackMatter != nil {
		backMatter.UnmarshalOscal(*ocd.BackMatter)
	}

	*c = ComponentDefinition{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Metadata:                   *metadata,
		ImportComponentDefinitions: datatypes.NewJSONSlice(importComponentDefs),
		Components:                 components,
		Capabilities:               capabilities,
		BackMatter:                 backMatter,
	}
	return c
}

// MarshalOscal converts the relational ComponentDefinition back into an OSCAL ComponentDefinition structure.
func (c *ComponentDefinition) MarshalOscal() *oscalTypes_1_1_3.ComponentDefinition {
	ret := oscalTypes_1_1_3.ComponentDefinition{
		UUID: c.UUIDModel.ID.String(),
	}

	ret.Metadata = *c.Metadata.MarshalOscal()

	if len(c.ImportComponentDefinitions) > 0 {
		imports := make([]oscalTypes_1_1_3.ImportComponentDefinition, len(c.ImportComponentDefinitions))
		for i, icd := range c.ImportComponentDefinitions {
			imports[i] = *icd.MarshalOscal()
		}
		ret.ImportComponentDefinitions = &imports
	}

	if len(c.Components) > 0 {
		components := make([]oscalTypes_1_1_3.DefinedComponent, len(c.Components))
		for i, comp := range c.Components {
			components[i] = *comp.MarshalOscal()
		}
		ret.Components = &components
	}

	if len(c.Capabilities) > 0 {
		capabilities := make([]oscalTypes_1_1_3.Capability, len(c.Capabilities))
		for i, cap := range c.Capabilities {
			capabilities[i] = *cap.MarshalOscal()
		}
		ret.Capabilities = &capabilities
	}

	if len(c.BackMatter.Resources) > 0 {
		bm := c.BackMatter.MarshalOscal()
		ret.BackMatter = bm
	}

	return &ret
}

// DefinedComponent represents a defined component in OSCAL.
// It includes type, title, description, purpose, remarks, responsible roles, control implementations, properties, links, and protocols.
type DefinedComponent struct {
	UUIDModel          // required
	Type        string `json:"type"`        // required
	Title       string `json:"title"`       // required
	Description string `json:"description"` // required
	Purpose     string `json:"purpose"`
	Remarks     string `json:"remarks"`

	ResponsibleRoles       []ResponsibleRole          `json:"responsible-roles" gorm:"polymorphic:Parent"`
	ControlImplementations []ControlImplementationSet `json:"control-implementations" gorm:"many2many:defined_components_control_implementation_sets"`

	Props     datatypes.JSONSlice[Prop]     `json:"props"`
	Links     datatypes.JSONSlice[Link]     `json:"links"`
	Protocols datatypes.JSONSlice[Protocol] `json:"protocols"`

	ComponentDefinitionID uuid.UUID

	// oscalTypes113.DefinedComponent
}

// UnmarshalOscal converts an OSCAL DefinedComponent into a relational DefinedComponent.
// It includes protocols, control implementations, responsible roles, links, and props.
func (dc *DefinedComponent) UnmarshalOscal(odc oscalTypes_1_1_3.DefinedComponent) *DefinedComponent {
	id := uuid.MustParse(odc.UUID)

	protocols := ConvertList(odc.Protocols, func(op oscalTypes_1_1_3.Protocol) Protocol {
		protocol := Protocol{}
		protocol.UnmarshalOscal(op)
		return protocol
	})

	cis := ConvertList(odc.ControlImplementations, func(ci oscalTypes_1_1_3.ControlImplementationSet) ControlImplementationSet {
		impl := ControlImplementationSet{}
		impl.UnmarshalOscal(ci)
		return impl
	})

	roles := ConvertList(odc.ResponsibleRoles, func(rr oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
		r := ResponsibleRole{}
		r.UnmarshalOscal(rr)
		return r
	})

	links := ConvertOscalToLinks(odc.Links)
	props := ConvertOscalToProps(odc.Props)

	*dc = DefinedComponent{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Type:                   odc.Type,
		Title:                  odc.Title,
		Purpose:                odc.Purpose,
		Remarks:                odc.Remarks,
		Description:            odc.Description,
		Protocols:              protocols,
		Links:                  links,
		Props:                  props,
		ControlImplementations: cis,
		ResponsibleRoles:       roles,
	}
	return dc
}

// MarshalOscal converts the relational DefinedComponent back into an OSCAL DefinedComponent structure.
// It includes protocols, control implementations, responsible roles, links, and props.
func (dc *DefinedComponent) MarshalOscal() *oscalTypes_1_1_3.DefinedComponent {
	ret := oscalTypes_1_1_3.DefinedComponent{
		UUID:        dc.UUIDModel.ID.String(),
		Type:        dc.Type,
		Title:       dc.Title,
		Description: dc.Description,
	}

	if dc.Purpose != "" {
		ret.Purpose = dc.Purpose
	}
	if dc.Remarks != "" {
		ret.Remarks = dc.Remarks
	}

	if len(dc.Protocols) > 0 {
		protocols := make([]oscalTypes_1_1_3.Protocol, len(dc.Protocols))
		for i, protocol := range dc.Protocols {
			protocols[i] = *protocol.MarshalOscal()
		}
		ret.Protocols = &protocols
	}

	if len(dc.Links) > 0 {
		ret.Links = ConvertLinksToOscal(dc.Links)
	}

	if len(dc.Props) > 0 {
		ret.Props = ConvertPropsToOscal(dc.Props)
	}

	if len(dc.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(dc.ResponsibleRoles))
		for i, role := range dc.ResponsibleRoles {
			roles[i] = *role.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}

	if len(dc.ControlImplementations) > 0 {
		impls := make([]oscalTypes_1_1_3.ControlImplementationSet, len(dc.ControlImplementations))
		for i, impl := range dc.ControlImplementations {
			impls[i] = *impl.MarshalOscal()
		}
		ret.ControlImplementations = &impls
	}

	return &ret
}

// ControlImplementationSet represents a set of control implementations in OSCAL.
// It includes source, description, set parameters, implemented requirements, properties, and links.
type ControlImplementationSet struct {
	UUIDModel                                       // required
	Source        string                            `json:"source"`      // required
	Description   string                            `json:"description"` // required
	SetParameters datatypes.JSONSlice[SetParameter] `json:"set-parameters"`

	ImplementedRequirements []ImplementedRequirementControlImplementation `json:"implemented-requirements"` // required

	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`

	DefinedComponentID uuid.UUID
}

// UnmarshalOscal converts an OSCAL ControlImplementationSet into a relational ControlImplementationSet.
// It includes set parameters, implemented requirements, props, and links.
func (ci *ControlImplementationSet) UnmarshalOscal(oci oscalTypes_1_1_3.ControlImplementationSet) *ControlImplementationSet {
	id := uuid.MustParse(oci.UUID)

	setParms := ConvertList(oci.SetParameters, func(osp oscalTypes_1_1_3.SetParameter) SetParameter {
		sp := SetParameter{}
		sp.UnmarshalOscal(osp)
		return sp
	})

	links := ConvertOscalToLinks(oci.Links)
	props := ConvertOscalToProps(oci.Props)

	implReqs := ConvertList(&oci.ImplementedRequirements, func(oirci oscalTypes_1_1_3.ImplementedRequirementControlImplementation) ImplementedRequirementControlImplementation {
		irci := ImplementedRequirementControlImplementation{}
		irci.UnmarshalOscal(oirci)
		return irci
	})

	*ci = ControlImplementationSet{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Source:                  oci.Source,
		Description:             oci.Description,
		SetParameters:           setParms,
		Links:                   links,
		Props:                   props,
		ImplementedRequirements: implReqs,
	}
	return ci
}

// MarshalOscal converts the relational ControlImplementationSet back into an OSCAL ControlImplementationSet structure.
func (ci *ControlImplementationSet) MarshalOscal() *oscalTypes_1_1_3.ControlImplementationSet {
	ret := oscalTypes_1_1_3.ControlImplementationSet{
		UUID:        ci.UUIDModel.ID.String(),
		Source:      ci.Source,
		Description: ci.Description,
	}

	reqs := make([]oscalTypes_1_1_3.ImplementedRequirementControlImplementation, len(ci.ImplementedRequirements))
	for i, req := range ci.ImplementedRequirements {
		reqs[i] = *req.MarshalOscal()
	}
	ret.ImplementedRequirements = reqs

	if len(ci.Links) > 0 {
		ret.Links = ConvertLinksToOscal(ci.Links)
	}

	if len(ci.Props) > 0 {
		ret.Props = ConvertPropsToOscal(ci.Props)
	}

	if len(ci.SetParameters) > 0 {
		setParms := make([]oscalTypes_1_1_3.SetParameter, len(ci.SetParameters))
		for i, sp := range ci.SetParameters {
			setParms[i] = oscalTypes_1_1_3.SetParameter(sp)
		}
		ret.SetParameters = &setParms
	}

	return &ret
}

// ImplementedRequirementControlImplementation represents an implemented requirement in OSCAL.
// It includes control ID, description, set parameters, properties, links, remarks, responsible roles, and statements.
type ImplementedRequirementControlImplementation struct {
	UUIDModel                                          //required
	ControlId        string                            `json:"control-id"`  //required
	Description      string                            `json:"description"` //required
	SetParameters    datatypes.JSONSlice[SetParameter] `json:"set-parameters"`
	Props            datatypes.JSONSlice[Prop]         `json:"props"`
	Links            datatypes.JSONSlice[Link]         `json:"links"`
	Remarks          string                            `json:"remarks"`
	ResponsibleRoles []ResponsibleRole                 `json:"responsible-roles" gorm:"polymorphic:Parent;"` // required
	Statements       []ControlStatementImplementation  `json:"statements"`

	ControlImplementationSetID uuid.UUID
}

// UnmarshalOscal converts an OSCAL ImplementedRequirementControlImplementation into a relational ImplementedRequirementControlImplementation.
// It includes set parameters, props, links, responsible roles, and statements.
func (irci *ImplementedRequirementControlImplementation) UnmarshalOscal(oirci oscalTypes_1_1_3.ImplementedRequirementControlImplementation) *ImplementedRequirementControlImplementation {
	id := uuid.MustParse(oirci.UUID)

	links := ConvertOscalToLinks(oirci.Links)
	props := ConvertOscalToProps(oirci.Props)

	setParms := ConvertList(oirci.SetParameters, func(osp oscalTypes_1_1_3.SetParameter) SetParameter {
		sp := SetParameter{}
		sp.UnmarshalOscal(osp)
		return sp
	})

	roles := ConvertList(oirci.ResponsibleRoles, func(rr oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
		r := ResponsibleRole{}
		r.UnmarshalOscal(rr)
		return r
	})

	statements := ConvertList(oirci.Statements, func(s oscalTypes_1_1_3.ControlStatementImplementation) ControlStatementImplementation {
		stmt := ControlStatementImplementation{}
		stmt.UnmarshalOscal(s)
		return stmt
	})

	*irci = ImplementedRequirementControlImplementation{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ControlId:        oirci.ControlId,
		Description:      oirci.Description,
		Links:            links,
		Props:            props,
		Remarks:          oirci.Remarks,
		SetParameters:    setParms,
		ResponsibleRoles: roles,
		Statements:       statements,
	}
	return irci
}

// MarshalOscal converts the relational ImplementedRequirementControlImplementation back into an OSCAL ImplementedRequirementControlImplementation structure.
func (irci *ImplementedRequirementControlImplementation) MarshalOscal() *oscalTypes_1_1_3.ImplementedRequirementControlImplementation {
	ret := oscalTypes_1_1_3.ImplementedRequirementControlImplementation{
		UUID:        irci.UUIDModel.ID.String(),
		ControlId:   irci.ControlId,
		Description: irci.Description,
	}

	if len(irci.Links) > 0 {
		ret.Links = ConvertLinksToOscal(irci.Links)
	}

	if len(irci.Props) > 0 {
		ret.Props = ConvertPropsToOscal(irci.Props)
	}

	if len(irci.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(irci.ResponsibleRoles))
		for i, role := range irci.ResponsibleRoles {
			roles[i] = *role.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}

	if len(irci.Statements) > 0 {
		statements := make([]oscalTypes_1_1_3.ControlStatementImplementation, len(irci.Statements))
		for i, stmt := range irci.Statements {
			statements[i] = *stmt.MarshalOscal()
		}
		ret.Statements = &statements
	}

	if len(irci.SetParameters) > 0 {
		setParms := make([]oscalTypes_1_1_3.SetParameter, len(irci.SetParameters))
		for i, sp := range irci.SetParameters {
			setParms[i] = oscalTypes_1_1_3.SetParameter(sp)
		}
		ret.SetParameters = &setParms
	}

	if irci.Remarks != "" {
		ret.Remarks = irci.Remarks
	}

	return &ret
}

// ControlStatementImplementation represents a control statement implementation in OSCAL.
// It includes statement ID, description, properties, links, responsible roles, and remarks.
type ControlStatementImplementation struct {
	UUIDModel                                  // required
	StatementId      string                    `json:"statement-id"` // required
	Description      string                    `json:"description"`  // required
	Props            datatypes.JSONSlice[Prop] `json:"props"`
	Links            datatypes.JSONSlice[Link] `json:"links"`
	ResponsibleRoles []ResponsibleRole         `json:"responsible-roles" gorm:"polymorphic:Parent;"`
	Remarks          string                    `json:"remarks"`

	ImplementedRequirementControlImplementationId uuid.UUID
}

// UnmarshalOscal converts an OSCAL ControlStatementImplementation into a relational ControlStatementImplementation.
// It includes props, links, and responsible roles.
func (s *ControlStatementImplementation) UnmarshalOscal(oci oscalTypes_1_1_3.ControlStatementImplementation) *ControlStatementImplementation {
	id := uuid.MustParse(oci.UUID)
	links := ConvertOscalToLinks(oci.Links)
	props := ConvertOscalToProps(oci.Props)
	roles := ConvertList(oci.ResponsibleRoles, func(rr oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
		r := ResponsibleRole{}
		r.UnmarshalOscal(rr)
		return r
	})

	*s = ControlStatementImplementation{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		StatementId:      oci.StatementId,
		Description:      oci.Description,
		Links:            links,
		Props:            props,
		Remarks:          oci.Remarks,
		ResponsibleRoles: roles,
	}

	return s
}

// MarshalOscal converts the relational ControlStatementImplementation back into an OSCAL ControlStatementImplementation structure.
func (s *ControlStatementImplementation) MarshalOscal() *oscalTypes_1_1_3.ControlStatementImplementation {
	ret := oscalTypes_1_1_3.ControlStatementImplementation{
		UUID:        s.UUIDModel.ID.String(),
		StatementId: s.StatementId,
		Description: s.Description,
	}

	if s.Remarks != "" {
		ret.Remarks = s.Remarks
	}

	if len(s.Props) > 0 {
		ret.Props = ConvertPropsToOscal(s.Props)
	}

	if len(s.Links) > 0 {
		ret.Links = ConvertLinksToOscal(s.Links)
	}

	if len(s.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(s.ResponsibleRoles))
		for i, role := range s.ResponsibleRoles {
			roles[i] = *role.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}

	return &ret
}

// ImportComponentDefinition represents an imported component definition in OSCAL.
// It includes href for the imported component definition.
type ImportComponentDefinition oscalTypes_1_1_3.ImportComponentDefinition

// UnmarshalOscal converts an OSCAL ImportComponentDefinition into a relational ImportComponentDefinition.
func (icd *ImportComponentDefinition) UnmarshalOscal(oicd oscalTypes_1_1_3.ImportComponentDefinition) *ImportComponentDefinition {
	*icd = ImportComponentDefinition(oicd)
	return icd
}

// MarshalOscal converts the relational ImportComponentDefinition back into an OSCAL ImportComponentDefinition structure.
func (icd *ImportComponentDefinition) MarshalOscal() *oscalTypes_1_1_3.ImportComponentDefinition {
	osc := oscalTypes_1_1_3.ImportComponentDefinition(*icd)
	return &osc
}

// Capability represents a capability in OSCAL.
// It includes description, name, remarks, links, properties, incorporates components, and control implementations.
type Capability struct {
	UUIDModel          // required
	Description string `json:"description"` // required
	Name        string `json:"name"`        // required
	Remarks     string `json:"remarks"`

	Links                  datatypes.JSONSlice[Link]                   `json:"links"`
	Props                  datatypes.JSONSlice[Prop]                   `json:"props"`
	IncorporatesComponents datatypes.JSONSlice[IncorporatesComponents] `json:"incorporates-components"`
	ControlImplementations []ControlImplementationSet                  `json:"control-implementations" gorm:"many2many:capability_control_implementation_sets"`

	ComponentDefinitionId uuid.UUID
}

// UnmarshalOscal converts an OSCAL Capability into a relational Capability.
// It includes links, props, incorporates components, and control implementations.
func (c *Capability) UnmarshalOscal(oc oscalTypes_1_1_3.Capability) *Capability {
	id := uuid.MustParse(oc.UUID)
	links := ConvertOscalToLinks(oc.Links)
	props := ConvertOscalToProps(oc.Props)

	components := ConvertList(oc.IncorporatesComponents, func(oic oscalTypes_1_1_3.IncorporatesComponent) IncorporatesComponents {
		component := IncorporatesComponents{}
		component.UnmarshalOscal(oic)
		return component
	})

	controls := ConvertList(oc.ControlImplementations, func(oci oscalTypes_1_1_3.ControlImplementationSet) ControlImplementationSet {
		control := ControlImplementationSet{}
		control.UnmarshalOscal(oci)
		return control
	})

	*c = Capability{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Description:            oc.Description,
		Name:                   oc.Name,
		Remarks:                oc.Remarks,
		Links:                  links,
		Props:                  props,
		IncorporatesComponents: datatypes.JSONSlice[IncorporatesComponents](components),
		ControlImplementations: controls,
	}

	return c
}

// MarshalOscal converts the relational Capability back into an OSCAL Capability structure.
func (c *Capability) MarshalOscal() *oscalTypes_1_1_3.Capability {
	ret := oscalTypes_1_1_3.Capability{
		UUID:        c.UUIDModel.ID.String(),
		Description: c.Description,
		Name:        c.Name,
	}

	if c.Remarks != "" {
		ret.Remarks = c.Remarks
	}

	if len(c.Links) > 0 {
		ret.Links = ConvertLinksToOscal(c.Links)
	}

	if len(c.Props) > 0 {
		ret.Props = ConvertPropsToOscal(c.Props)
	}

	if len(c.IncorporatesComponents) > 0 {
		components := make([]oscalTypes_1_1_3.IncorporatesComponent, len(c.IncorporatesComponents))
		for i, component := range c.IncorporatesComponents {
			components[i] = oscalTypes_1_1_3.IncorporatesComponent(component)
		}

		ret.IncorporatesComponents = &components
	}

	if len(c.ControlImplementations) > 0 {
		controls := make([]oscalTypes_1_1_3.ControlImplementationSet, len(c.ControlImplementations))
		for i, control := range c.ControlImplementations {
			controls[i] = *control.MarshalOscal()
		}
		ret.ControlImplementations = &controls
	}

	return &ret
}

// IncorporatesComponents represents incorporated components in OSCAL.
// It includes component UUID and description.
type IncorporatesComponents oscalTypes_1_1_3.IncorporatesComponent

// UnmarshalOscal converts an OSCAL IncorporatesComponent into a relational IncorporatesComponents.
func (ic *IncorporatesComponents) UnmarshalOscal(iic oscalTypes_1_1_3.IncorporatesComponent) *IncorporatesComponents {
	*ic = IncorporatesComponents(iic)
	return ic
}

// MarshalOscal converts the relational IncorporatesComponents back into an OSCAL IncorporatesComponent structure.
func (ic *IncorporatesComponents) MarshalOscal() *oscalTypes_1_1_3.IncorporatesComponent {
	osc := oscalTypes_1_1_3.IncorporatesComponent(*ic)
	return &osc
}
