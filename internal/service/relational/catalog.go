package relational

import (
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Catalog struct {
	UUIDModel
	Metadata   Metadata                       `json:"metadata" gorm:"polymorphic:Parent;"`
	Params     datatypes.JSONSlice[Parameter] `json:"params"`
	Groups     []Group                        `json:"groups" gorm:"polymorphic:Parent;"`
	Controls   []Control                      `json:"controls" gorm:"polymorphic:Parent;"`
	BackMatter *BackMatter                    `json:"back-matter,omitempty" gorm:"polymorphic:Parent;"`
	/**
	"required": [
		"uuid",
		"metadata"
	],
	*/
}

func (c *Catalog) UnmarshalOscal(ocatalog oscalTypes_1_1_3.Catalog) *Catalog {
	metadata := &Metadata{}
	metadata.UnmarshalOscal(ocatalog.Metadata)

	id := uuid.MustParse(ocatalog.UUID)
	*c = Catalog{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Metadata: *metadata,
	}

	if ocatalog.BackMatter != nil {
		backmatter := &BackMatter{}
		backmatter.UnmarshalOscal(*ocatalog.BackMatter)
		c.BackMatter = backmatter
	}

	if ocatalog.Params != nil {
		c.Params = ConvertList(ocatalog.Params, func(data oscalTypes_1_1_3.Parameter) Parameter {
			output := Parameter{}
			output.UnmarshalOscal(data)
			return output
		})
	}

	if ocatalog.Controls != nil {
		c.Controls = ConvertList(ocatalog.Controls, func(data oscalTypes_1_1_3.Control) Control {
			output := Control{}
			output.UnmarshalOscal(data, id)
			return output
		})
	}

	if ocatalog.Groups != nil {
		c.Groups = ConvertList(ocatalog.Groups, func(data oscalTypes_1_1_3.Group) Group {
			output := Group{}
			output.UnmarshalOscal(data, id)
			return output
		})
	}

	return c
}

// MarshalOscal converts the Catalog back to an OSCAL Catalog
func (c *Catalog) MarshalOscal() *oscalTypes_1_1_3.Catalog {
	cat := &oscalTypes_1_1_3.Catalog{
		UUID:     c.UUIDModel.ID.String(),
		Metadata: *c.Metadata.MarshalOscal(),
	}
	if len(c.Params) > 0 {
		params := make([]oscalTypes_1_1_3.Parameter, len(c.Params))
		for i, p := range c.Params {
			params[i] = *p.MarshalOscal()
		}
		cat.Params = &params
	}
	if len(c.Groups) > 0 {
		groups := make([]oscalTypes_1_1_3.Group, len(c.Groups))
		for i, g := range c.Groups {
			groups[i] = *g.MarshalOscal()
		}
		cat.Groups = &groups
	}
	if len(c.Controls) > 0 {
		controls := make([]oscalTypes_1_1_3.Control, len(c.Controls))
		for i, ctl := range c.Controls {
			controls[i] = *ctl.MarshalOscal()
		}
		cat.Controls = &controls
	}
	if c.BackMatter != nil {
		cat.BackMatter = c.BackMatter.MarshalOscal()
	}
	return cat
}

type Group struct {
	ID     string                         `json:"id" gorm:"primary_key"` // required
	Class  string                         `json:"class"`
	Title  string                         `json:"title"` // required
	Params datatypes.JSONSlice[Parameter] `json:"params"`
	Parts  datatypes.JSONSlice[Part]      `json:"parts"`
	Props  datatypes.JSONSlice[Prop]      `json:"props,omitempty"`
	Links  datatypes.JSONSlice[Link]      `json:"links,omitempty"`

	CatalogID  uuid.UUID `gorm:"primaryKey"`
	ParentID   *string
	ParentType *string

	Groups   []Group   `json:"groups" gorm:"polymorphic:Parent;"`
	Controls []Control `json:"controls" gorm:"polymorphic:Parent;"`
}

func (c *Group) UnmarshalOscal(data oscalTypes_1_1_3.Group, catalogId uuid.UUID) *Group {
	*c = Group{
		ID:        data.ID,
		Title:     data.Title,
		Class:     data.Class,
		Props:     ConvertOscalToProps(data.Props),
		Links:     ConvertOscalToLinks(data.Links),
		CatalogID: catalogId,
	}
	if data.Params != nil {
		params := ConvertList(data.Params, func(data oscalTypes_1_1_3.Parameter) Parameter {
			output := Parameter{}
			output.UnmarshalOscal(data)
			return output
		})
		c.Params = params
	}
	if data.Parts != nil {
		parts := ConvertList(data.Parts, func(data oscalTypes_1_1_3.Part) Part {
			output := Part{}
			output.UnmarshalOscal(data)
			return output
		})
		c.Parts = parts
	}
	if data.Groups != nil {
		groups := ConvertList(data.Groups, func(data oscalTypes_1_1_3.Group) Group {
			output := Group{}
			output.UnmarshalOscal(data, c.CatalogID)
			return output
		})
		c.Groups = groups
	}
	if data.Controls != nil {
		controls := ConvertList(data.Controls, func(data oscalTypes_1_1_3.Control) Control {
			output := Control{}
			output.UnmarshalOscal(data, c.CatalogID)
			return output
		})
		c.Controls = controls
	}
	return c
}

// MarshalOscal converts the Group back to an OSCAL Group
func (c *Group) MarshalOscal() *oscalTypes_1_1_3.Group {
	og := &oscalTypes_1_1_3.Group{
		ID:    c.ID,
		Title: c.Title,
		Class: c.Class,
		//Props: ConvertPropsToOscal(c.Props),
		//Links: ConvertLinksToOscal(c.Links),
	}
	if len(c.Links) > 0 {
		og.Links = ConvertLinksToOscal(c.Links)
	}
	if len(c.Props) > 0 {
		og.Props = ConvertPropsToOscal(c.Props)
	}
	if len(c.Params) > 0 {
		params := make([]oscalTypes_1_1_3.Parameter, len(c.Params))
		for i, p := range c.Params {
			params[i] = *p.MarshalOscal()
		}
		og.Params = &params
	}
	if len(c.Parts) > 0 {
		parts := make([]oscalTypes_1_1_3.Part, len(c.Parts))
		for i, p := range c.Parts {
			parts[i] = *p.MarshalOscal()
		}
		og.Parts = &parts
	}
	if len(c.Groups) > 0 {
		groups := make([]oscalTypes_1_1_3.Group, len(c.Groups))
		for i, g := range c.Groups {
			groups[i] = *g.MarshalOscal()
		}
		og.Groups = &groups
	}
	if len(c.Controls) > 0 {
		controls := make([]oscalTypes_1_1_3.Control, len(c.Controls))
		for i, ctl := range c.Controls {
			controls[i] = *ctl.MarshalOscal()
		}
		og.Controls = &controls
	}
	return og
}

type Control struct {
	ID     string                         `json:"id" gorm:"primary_key"` // required
	Title  string                         `json:"title"`                 // required
	Class  *string                        `json:"class"`
	Params datatypes.JSONSlice[Parameter] `json:"params"`
	Parts  datatypes.JSONSlice[Part]      `json:"parts"`
	Props  datatypes.JSONSlice[Prop]      `json:"props,omitempty"`
	Links  datatypes.JSONSlice[Link]      `json:"links,omitempty"`

	CatalogID  uuid.UUID `gorm:"primaryKey"`
	ParentID   *string
	ParentType *string

	Controls []Control `json:"controls" gorm:"polymorphic:Parent;"`
}

func (c *Control) UnmarshalOscal(data oscalTypes_1_1_3.Control, catalogId uuid.UUID) *Control {
	*c = Control{
		ID:        data.ID,
		Title:     data.Title,
		Class:     &data.Class,
		Props:     ConvertOscalToProps(data.Props),
		Links:     ConvertOscalToLinks(data.Links),
		CatalogID: catalogId,
	}
	if data.Params != nil {
		params := ConvertList(data.Params, func(data oscalTypes_1_1_3.Parameter) Parameter {
			output := Parameter{}
			output.UnmarshalOscal(data)
			return output
		})
		c.Params = params
	}
	if data.Parts != nil {
		parts := ConvertList(data.Parts, func(data oscalTypes_1_1_3.Part) Part {
			output := Part{}
			output.UnmarshalOscal(data)
			return output
		})
		c.Parts = parts
	}
	if data.Controls != nil {
		controls := ConvertList(data.Controls, func(data oscalTypes_1_1_3.Control) Control {
			output := Control{}
			output.UnmarshalOscal(data, c.CatalogID)
			return output
		})
		c.Controls = controls
	}
	return c
}

// MarshalOscal converts the Control back to an OSCAL Control
func (c *Control) MarshalOscal() *oscalTypes_1_1_3.Control {
	oc := &oscalTypes_1_1_3.Control{
		ID:    c.ID,
		Title: c.Title,
		Class: "",
		//Props: ConvertPropsToOscal(c.Props),
		//Links: ConvertLinksToOscal(c.Links),
	}
	if len(c.Links) > 0 {
		oc.Links = ConvertLinksToOscal(c.Links)
	}
	if len(c.Props) > 0 {
		oc.Props = ConvertPropsToOscal(c.Props)
	}
	if c.Class != nil {
		oc.Class = *c.Class
	}
	if len(c.Params) > 0 {
		params := make([]oscalTypes_1_1_3.Parameter, len(c.Params))
		for i, p := range c.Params {
			params[i] = *p.MarshalOscal()
		}
		oc.Params = &params
	}
	if len(c.Parts) > 0 {
		parts := make([]oscalTypes_1_1_3.Part, len(c.Parts))
		for i, p := range c.Parts {
			parts[i] = *p.MarshalOscal()
		}
		oc.Parts = &parts
	}
	if len(c.Controls) > 0 {
		controls := make([]oscalTypes_1_1_3.Control, len(c.Controls))
		for i, ctl := range c.Controls {
			controls[i] = *ctl.MarshalOscal()
		}
		oc.Controls = &controls
	}
	return oc
}

type Parameter struct {
	ID          string                                   `json:"id"`
	Class       *string                                  `json:"class"`
	Label       *string                                  `json:"label"`
	Usage       *string                                  `json:"usage"`
	Remarks     *string                                  `json:"remarks"`
	Constraints datatypes.JSONSlice[ParameterConstraint] `json:"constraints"`
	Guidelines  datatypes.JSONSlice[ParameterGuideline]  `json:"guidelines"`
	Select      *datatypes.JSONType[ParameterSelection]  `json:"select"`
	Values      datatypes.JSONSlice[string]              `json:"values"`
	Props       datatypes.JSONSlice[Prop]                `json:"props,omitempty"`
	Links       datatypes.JSONSlice[Link]                `json:"links,omitempty"`

	/**
	"required": [
		"id"
	],
	*/
}

func (l *Parameter) UnmarshalOscal(data oscalTypes_1_1_3.Parameter) *Parameter {
	*l = Parameter{
		ID:      data.ID,
		Class:   &data.Class,
		Props:   ConvertOscalToProps(data.Props),
		Links:   ConvertOscalToLinks(data.Links),
		Label:   &data.Label,
		Usage:   &data.Usage,
		Remarks: &data.Remarks,
	}
	if data.Select != nil {
		selection := ParameterSelection{}
		selection.UnmarshalOscal(*data.Select)
		selectionJson := datatypes.NewJSONType(selection)
		l.Select = &selectionJson
	}
	if data.Constraints != nil {
		l.Constraints = ConvertList(data.Constraints, func(pc oscalTypes_1_1_3.ParameterConstraint) ParameterConstraint {
			constraint := ParameterConstraint{}
			constraint.UnmarshalOscal(pc)
			return constraint
		})
	}
	if data.Guidelines != nil {
		l.Guidelines = ConvertList(data.Guidelines, func(data oscalTypes_1_1_3.ParameterGuideline) ParameterGuideline {
			output := ParameterGuideline{}
			output.UnmarshalOscal(data)
			return output
		})
	}
	if data.Values != nil {
		l.Values = *data.Values
	}
	return l
}

// MarshalOscal converts the Parameter back to an OSCAL Parameter
func (l *Parameter) MarshalOscal() *oscalTypes_1_1_3.Parameter {
	op := &oscalTypes_1_1_3.Parameter{
		ID: l.ID,
		//Props: ConvertPropsToOscal(l.Props),
		//Links: ConvertLinksToOscal(l.Links),
	}
	if len(l.Links) > 0 {
		op.Links = ConvertLinksToOscal(l.Links)
	}
	if len(l.Props) > 0 {
		op.Props = ConvertPropsToOscal(l.Props)
	}
	if l.Class != nil {
		op.Class = *l.Class
	}
	if l.Label != nil {
		op.Label = *l.Label
	}
	if l.Usage != nil {
		op.Usage = *l.Usage
	}
	if l.Remarks != nil {
		op.Remarks = *l.Remarks
	}
	if l.Select != nil {
		data := l.Select.Data()
		op.Select = data.MarshalOscal()
	}
	if len(l.Constraints) > 0 {
		cs := make([]oscalTypes_1_1_3.ParameterConstraint, len(l.Constraints))
		for i, c := range l.Constraints {
			cs[i] = *c.MarshalOscal()
		}
		op.Constraints = &cs
	}
	if len(l.Guidelines) > 0 {
		gs := make([]oscalTypes_1_1_3.ParameterGuideline, len(l.Guidelines))
		for i, g := range l.Guidelines {
			gs[i] = *g.MarshalOscal()
		}
		op.Guidelines = &gs
	}
	if len(l.Values) > 0 {
		vals := make([]string, len(l.Values))
		copy(vals, l.Values)
		op.Values = &vals
	}
	return op
}

type ParameterSelectionCount string

const (
	ParameterSelectionCountOne       ParameterSelectionCount = "one"
	ParameterSelectionCountOneOrMore ParameterSelectionCount = "one-or-more"
)

type ParameterSelection struct {
	HowMany ParameterSelectionCount `json:"how-many"`
	Choice  []string                `json:"choice"`
}

func (l *ParameterSelection) UnmarshalOscal(data oscalTypes_1_1_3.ParameterSelection) *ParameterSelection {
	*l = ParameterSelection{
		HowMany: ParameterSelectionCount(data.HowMany),
	}
	if data.Choice != nil {
		l.Choice = *data.Choice
	}
	return l
}

// MarshalOscal converts the ParameterSelection back to an OSCAL ParameterSelection
func (l *ParameterSelection) MarshalOscal() *oscalTypes_1_1_3.ParameterSelection {
	ps := &oscalTypes_1_1_3.ParameterSelection{
		HowMany: string(l.HowMany),
	}
	if len(l.Choice) > 0 {
		choice := make([]string, len(l.Choice))
		copy(choice, l.Choice)
		ps.Choice = &choice
	}
	return ps
}

type ParameterGuideline struct {
	Prose string `json:"prose"`

	/**
	"required": [
		"prose"
	],
	*/
}

func (l *ParameterGuideline) UnmarshalOscal(data oscalTypes_1_1_3.ParameterGuideline) *ParameterGuideline {
	*l = ParameterGuideline(data)
	return l
}

func (l *ParameterGuideline) MarshalOscal() *oscalTypes_1_1_3.ParameterGuideline {
	return &oscalTypes_1_1_3.ParameterGuideline{
		Prose: l.Prose,
	}
}

type ParameterConstraint struct {
	Description string                    `json:"description"`
	Tests       []ParameterConstraintTest `json:"tests"`
}

func (l *ParameterConstraint) UnmarshalOscal(data oscalTypes_1_1_3.ParameterConstraint) *ParameterConstraint {
	*l = ParameterConstraint{
		Description: data.Description,
	}
	if data.Tests != nil {
		l.Tests = ConvertList(data.Tests, func(t oscalTypes_1_1_3.ConstraintTest) ParameterConstraintTest {
			test := ParameterConstraintTest{}
			test.UnmarshalOscal(t)
			return test
		})
	}
	return l
}

func (l *ParameterConstraint) MarshalOscal() *oscalTypes_1_1_3.ParameterConstraint {
	op := &oscalTypes_1_1_3.ParameterConstraint{
		Description: l.Description,
	}
	if len(l.Tests) > 0 {
		tests := make([]oscalTypes_1_1_3.ConstraintTest, len(l.Tests))
		for i, t := range l.Tests {
			tests[i] = *t.MarshalOscal()
		}
		op.Tests = &tests
	}
	return op
}

type ParameterConstraintTest struct {
	Expression string `json:"expression"`
	Remarks    string `json:"remarks"`
}

func (l *ParameterConstraintTest) UnmarshalOscal(data oscalTypes_1_1_3.ConstraintTest) *ParameterConstraintTest {
	*l = ParameterConstraintTest(data)
	return l
}

func (l *ParameterConstraintTest) MarshalOscal() *oscalTypes_1_1_3.ConstraintTest {
	return &oscalTypes_1_1_3.ConstraintTest{
		Expression: l.Expression,
		Remarks:    l.Remarks,
	}
}

type Part struct {
	ID     string                    `json:"id"`
	Name   string                    `json:"name"`
	NS     string                    `json:"ns"`
	Class  string                    `json:"class"`
	Title  string                    `json:"title"`
	Prose  string                    `json:"prose"`
	Props  datatypes.JSONSlice[Prop] `json:"props,omitempty"`
	Links  datatypes.JSONSlice[Link] `json:"links,omitempty"`
	PartID string                    `json:"part_id"`
	Parts  []Part                    `json:"parts"` // -> Part

	/**
	"required": [
		"name"
	],
	*/
}

func (p *Part) UnmarshalOscal(data oscalTypes_1_1_3.Part) *Part {
	*p = Part{
		ID:    data.ID,
		Name:  data.Name,
		NS:    data.Ns,
		Class: data.Class,
		Title: data.Title,
		Prose: data.Prose,
		Props: ConvertOscalToProps(data.Props),
		Links: ConvertOscalToLinks(data.Links),
		Parts: ConvertList(data.Parts, func(data oscalTypes_1_1_3.Part) Part {
			output := Part{}
			output.UnmarshalOscal(data)
			return output
		}),
	}
	return p
}

func (p *Part) MarshalOscal() *oscalTypes_1_1_3.Part {
	op := &oscalTypes_1_1_3.Part{
		ID:    p.ID,
		Name:  p.Name,
		Ns:    p.NS,
		Class: p.Class,
		Title: p.Title,
		Prose: p.Prose,
		//Props: ConvertPropsToOscal(p.Props),
		//Links: ConvertLinksToOscal(p.Links),
	}
	if len(p.Links) > 0 {
		op.Links = ConvertLinksToOscal(p.Links)
	}
	if len(p.Props) > 0 {
		op.Props = ConvertPropsToOscal(p.Props)
	}
	if len(p.Parts) > 0 {
		sub := make([]oscalTypes_1_1_3.Part, len(p.Parts))
		for i, sp := range p.Parts {
			sub[i] = *sp.MarshalOscal()
		}
		op.Parts = &sub
	}
	return op
}
