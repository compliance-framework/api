package relational

import (
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Profile struct {
	UUIDModel
	Metadata   Metadata    `json:"metadata" gorm:"Polymorphic:Parent"`
	BackMatter *BackMatter `json:"back-matter" gorm:"Polymorphic:Parent"`
	Imports    []Import    `json:"imports"`
	Merge      Merge       `json:"merge"`
}

// UnmarshalOscal take type of oscalTypes_1_1_3.Profile from go-oscal and converts it into a relational model within the struct
// while returning a pointer to itself
func (p *Profile) UnmarshalOscal(op oscalTypes_1_1_3.Profile) *Profile {
	id := uuid.MustParse(op.UUID)

	metadata := Metadata{}
	metadata.UnmarshalOscal(op.Metadata)

	backMatter := &BackMatter{}
	backMatter.UnmarshalOscal(*op.BackMatter)

	merge := Merge{}
	merge.UnmarshalOscal(*op.Merge)

	*p = Profile{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Metadata:   metadata,
		BackMatter: backMatter,
		Imports: ConvertList(&op.Imports, func(oi oscalTypes_1_1_3.Import) Import {
			imp := Import{}
			imp.UnmarshalOscal(oi)
			return imp
		}),
		Merge: merge,
	}
	return p
}

// MarshalOscal returns the type of oscalTypes_1_1_3.Profile from the underlying struct, omitting internal properties
// and ensuring that it is Oscal compliant
func (p *Profile) MarshalOscal() oscalTypes_1_1_3.Profile {
	ret := oscalTypes_1_1_3.Profile{
		UUID:     p.ID.String(),
		Metadata: *p.Metadata.MarshalOscal(),
		Merge:    p.Merge.MarshalOscal(),
	}

	if p.BackMatter != nil {
		backMatter := p.BackMatter.MarshalOscal()
		ret.BackMatter = backMatter
	}

	imports := make([]oscalTypes_1_1_3.Import, len(p.Imports))
	for i, imp := range p.Imports {
		imports[i] = imp.MarshalOscal()
	}
	ret.Imports = imports

	return ret
}

type IncludeAll = map[string]interface{}
type FlatWithoutGrouping = map[string]interface{}

type Import struct {
	UUIDModel
	// Href as per the OSCAL docs can be an absolute network path (potentially remote), relative or a URI fragment
	// for the moment to make the system's life easier, it should be a URI fragment to back-matter and try and resolve
	// back to an ingested catalog.
	Href            string                          `json:"href"`
	IncludeAll      datatypes.JSONType[*IncludeAll] `json:"include-all"`
	IncludeControls []SelectControlById             `json:"include-controls" gorm:"Polymorphic:Parent"`
	ExcludeControls []SelectControlById             `json:"exclude-controls" gorm:"Polymorphic:Parent"`

	ProfileID uuid.UUID
}

func (i *Import) UnmarshalOscal(oi oscalTypes_1_1_3.Import) *Import {
	*i = Import{
		UUIDModel:  UUIDModel{},
		Href:       oi.Href,
		IncludeAll: datatypes.NewJSONType[*IncludeAll](oi.IncludeAll),
		IncludeControls: ConvertList(oi.IncludeControls, func(oc oscalTypes_1_1_3.SelectControlById) SelectControlById {
			control := SelectControlById{}
			control.UnmarshalOscal(oc)
			return control
		}),
		ExcludeControls: ConvertList(oi.ExcludeControls, func(oc oscalTypes_1_1_3.SelectControlById) SelectControlById {
			control := SelectControlById{}
			control.UnmarshalOscal(oc)
			return control
		}),
	}
	return i
}

func (i *Import) MarshalOscal() oscalTypes_1_1_3.Import {
	ret := oscalTypes_1_1_3.Import{
		Href: i.Href,
	}

	if i.IncludeAll.Data() != nil {
		ret.IncludeAll = &oscalTypes_1_1_3.IncludeAll{}
	} else {
		// Default back to Include/ExcludeControls if include all is not set
		// IncludeControls must be set if includeall is not set, exclude is still optional
		includes := make([]oscalTypes_1_1_3.SelectControlById, len(i.IncludeControls))
		for i, control := range i.IncludeControls {
			includes[i] = control.MarshalOscal()
		}
		ret.IncludeControls = &includes

		if i.ExcludeControls != nil {
			excludes := make([]oscalTypes_1_1_3.SelectControlById, len(i.ExcludeControls))
			for i, control := range i.ExcludeControls {
				excludes[i] = control.MarshalOscal()
			}
			ret.ExcludeControls = &excludes
		}
	}

	return ret
}

type Matching oscalTypes_1_1_3.Matching

func (m *Matching) UnmarshalOscal(om oscalTypes_1_1_3.Matching) *Matching {
	*m = Matching(om)
	return m
}

func (m *Matching) MarshalOscal() *oscalTypes_1_1_3.Matching {
	matching := oscalTypes_1_1_3.Matching(*m)
	return &matching
}

type SelectControlById struct {
	UUIDModel
	WithChildControls string                        `json:"with-child-controls"`
	WithIds           datatypes.JSONSlice[string]   `json:"with-ids"`
	Matching          datatypes.JSONSlice[Matching] `json:"matching"`

	ParentID   uuid.UUID
	ParentType string
}

func (s *SelectControlById) UnmarshalOscal(o oscalTypes_1_1_3.SelectControlById) *SelectControlById {
	*s = SelectControlById{
		UUIDModel:         UUIDModel{},
		WithChildControls: o.WithChildControls,
		WithIds:           datatypes.NewJSONSlice[string](*o.WithIds),
		Matching: ConvertList(o.Matching, func(om oscalTypes_1_1_3.Matching) Matching {
			m := Matching{}
			m.UnmarshalOscal(om)
			return m
		}),
	}

	return s
}

func (s *SelectControlById) MarshalOscal() oscalTypes_1_1_3.SelectControlById {
	controls := oscalTypes_1_1_3.SelectControlById{}
	if s.WithChildControls != "" {
		controls.WithChildControls = s.WithChildControls
	}

	if s.WithIds != nil {
		withIds := make([]string, len(s.WithIds))
		for i, id := range s.WithIds {
			withIds[i] = string(id)
		}
		controls.WithIds = &withIds
	}

	if s.Matching != nil {
		matching := make([]oscalTypes_1_1_3.Matching, len(s.Matching))
		for i, m := range s.Matching {
			matching[i] = *m.MarshalOscal()
		}
		controls.Matching = &matching
	}
	return controls
}

type CombinationRule oscalTypes_1_1_3.CombinationRule

func (cr *CombinationRule) UnmarshalOscal(o oscalTypes_1_1_3.CombinationRule) *CombinationRule {
	*cr = CombinationRule(o)
	return cr
}

func (cr *CombinationRule) MarshalOscal() *oscalTypes_1_1_3.CombinationRule {
	combine := oscalTypes_1_1_3.CombinationRule(*cr)
	return &combine
}

type Merge struct {
	UUIDModel
	Combine datatypes.JSONType[*CombinationRule]     `json:"combine"`
	AsIs    bool                                     `json:"as-is"`
	Flat    datatypes.JSONType[*FlatWithoutGrouping] `json:"flat"`
	// Custom not implemented

	ProfileID uuid.UUID
}

func (m *Merge) UnmarshalOscal(o oscalTypes_1_1_3.Merge) *Merge {
	*m = Merge{
		UUIDModel: UUIDModel{},
		AsIs:      o.AsIs,
	}

	if o.Combine != nil {
		combinationRule := CombinationRule{}
		combinationRule.UnmarshalOscal(*o.Combine)
		m.Combine = datatypes.NewJSONType[*CombinationRule](&combinationRule)
	}
	if !m.AsIs {
		if o.Flat != nil {
			m.Flat = datatypes.NewJSONType[*FlatWithoutGrouping](o.Flat)
		}
		// Custom Merge is not implemented at this time to save complexity
	}

	return m
}

func (m *Merge) MarshalOscal() *oscalTypes_1_1_3.Merge {
	ret := oscalTypes_1_1_3.Merge{
		AsIs: m.AsIs,
	}

	if m.Combine.Data() != nil {
		ret.Combine = m.Combine.Data().MarshalOscal()
	}

	if !m.AsIs {
		if m.Flat.Data() != nil {
			ret.Flat = &oscalTypes_1_1_3.FlatWithoutGrouping{}
		}
		// Custom Merge is not implemented at this time to save complexity
	}

	return &ret
}
