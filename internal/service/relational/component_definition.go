package relational

import (
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type ComponentDefinition struct {
	UUIDModel
	Metadata   Metadata   `json:"metadata" gorm:"polymorphic:Parent;"`
	BackMatter BackMatter `json:"back-matter" gorm:"polymorphic:Parent;"`

	ImportComponentDefinitions datatypes.JSONSlice[ImportComponentDefinition] `json:"import-component-definitions"`
	Components                 []DefinedComponent                             `json:"components"`
	Capabilities               []Capability                                   `json:"capabilities"`

	//oscaltypes113.ComponentDefinition
}

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

	backMatter := &BackMatter{}
	backMatter.UnmarshalOscal(*ocd.BackMatter)

	*c = ComponentDefinition{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Metadata:                   *metadata,
		ImportComponentDefinitions: datatypes.NewJSONSlice[ImportComponentDefinition](importComponentDefs),
		Components:                 components,
		Capabilities:               capabilities,
		BackMatter:                 *backMatter,
	}
	return c
}

type DefinedComponent struct {
	UUIDModel
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Purpose     string `json:"purpose"`
	Remarks     string `json:"remarks"`

	// TODO: Convert to a linker table that maps between roles that exist on UUID in the metadata
	ResponsibleRoles       datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`
	ControlImplementations []ControlImplementationSet           `json:"control-implementations" gorm:"many2many:defined_components_control_implementation_sets"`

	Props     datatypes.JSONSlice[Prop]     `json:"props"`
	Links     datatypes.JSONSlice[Link]     `json:"links"`
	Protocols datatypes.JSONSlice[Protocol] `json:"protocols"`

	ComponentDefinitionID uuid.UUID

	// oscalTypes113.DefinedComponent
}

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
		ResponsibleRoles:       datatypes.NewJSONSlice[ResponsibleRole](roles),
	}
	return dc
}

type Protocol oscalTypes_1_1_3.Protocol

func (p *Protocol) UnmarshalOscal(op oscalTypes_1_1_3.Protocol) *Protocol {
	*p = Protocol(op)
	return p
}

type SetParameter oscalTypes_1_1_3.SetParameter

func (sp *SetParameter) UnmarshalOscal(osp oscalTypes_1_1_3.SetParameter) *SetParameter {
	*sp = SetParameter(osp)
	return sp
}

type ControlImplementationSet struct {
	UUIDModel                                       // required
	Source        string                            `json:"source"`      // required
	Description   string                            `json:"description"` // required
	SetParameters datatypes.JSONSlice[SetParameter] `json:"set-parameters"`

	ImplementedRequirements []ImplementedRequirementControlImplementation `json:"implemented-requirements"` // required

	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`

	DefinedComponentID uuid.UUID

	/** required: [
		"uuid:,
		"source",
		"description",
		"implemented-requirements"
	]
	*/

	// oscalType_1_1_3.ControlImplementationSet
}

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

type ImplementedRequirementControlImplementation struct {
	UUIDModel                                             //required
	ControlId        string                               `json:"control-id"`  //required
	Description      string                               `json:"description"` //required
	SetParameters    datatypes.JSONSlice[SetParameter]    `json:"set-parameters"`
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	Remarks          string                               `json:"remarks"`
	ResponsibleRoles datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`
	Statements       []ControlStatementImplementation     `json:"statements"`

	ControlImplementationSetID uuid.UUID
}

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
		ResponsibleRoles: datatypes.NewJSONSlice[ResponsibleRole](roles),
		Statements:       statements,
	}
	return irci
}

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
			roles[i] = oscalTypes_1_1_3.ResponsibleRole(role)
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

type ControlStatementImplementation struct {
	UUIDModel                                             // required
	StatementId      string                               `json:"statement-id"` // required
	Description      string                               `json:"description"`  // required
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	ResponsibleRoles datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`
	Remarks          string                               `json:"remarks"`

	ImplementedRequirementControlImplementationId uuid.UUID
}

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
		ResponsibleRoles: datatypes.NewJSONSlice[ResponsibleRole](roles),
	}

	return s
}

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
			roles[i] = oscalTypes_1_1_3.ResponsibleRole(role)
		}
		ret.ResponsibleRoles = &roles
	}

	return &ret
}

type ResponsibleRole oscalTypes_1_1_3.ResponsibleRole

func (rr *ResponsibleRole) UnmarshalOscal(osc oscalTypes_1_1_3.ResponsibleRole) *ResponsibleRole {
	*rr = ResponsibleRole(osc)
	return rr
}

type ImportComponentDefinition oscalTypes_1_1_3.ImportComponentDefinition

func (icd *ImportComponentDefinition) UnmarshalOscal(oicd oscalTypes_1_1_3.ImportComponentDefinition) *ImportComponentDefinition {
	*icd = ImportComponentDefinition(oicd)
	return icd
}

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
	// oscalTypes_1_1_3.Capability
}

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

func (c *Capability) MarshalOscal() *oscalTypes_1_1_3.Capability {
	ret := oscalTypes_1_1_3.Capability{
		UUID:        c.UUIDModel.ID.String(),
		Description: c.Description,
		Name:        c.Name,
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

type IncorporatesComponents oscalTypes_1_1_3.IncorporatesComponent

func (ic *IncorporatesComponents) UnmarshalOscal(iic oscalTypes_1_1_3.IncorporatesComponent) *IncorporatesComponents {
	*ic = IncorporatesComponents(iic)
	return ic
}
