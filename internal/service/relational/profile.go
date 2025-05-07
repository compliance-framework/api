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
}

// UnmarshalOscal take type of oscalTypes_1_1_3.Profile from go-oscal and converts it into a relational model within the struct
// while returning a pointer to itself
func (p *Profile) UnmarshalOscal(op oscalTypes_1_1_3.Profile) *Profile {
	id := uuid.MustParse(op.UUID)

	metadata := Metadata{}
	metadata.UnmarshalOscal(op.Metadata)

	backMatter := &BackMatter{}
	backMatter.UnmarshalOscal(*op.BackMatter)

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
	}
	return p
}

// MarshalOscal returns the type of oscalTypes_1_1_3.Profile from the underlying struct, omitting internal properties
// and ensuring that it is Oscal compliant
func (p *Profile) MarshalOscal() oscalTypes_1_1_3.Profile {
	ret := oscalTypes_1_1_3.Profile{
		UUID:     p.ID.String(),
		Metadata: *p.Metadata.MarshalOscal(),
	}

	if p.BackMatter != nil {
		backMatter := p.BackMatter.MarshalOscal()
		ret.BackMatter = backMatter
	}

	return ret
}

type IncludeAll = map[string]interface{}

type Import struct {
	UUIDModel
	Href       string                          `json:"href"`
	IncludeAll datatypes.JSONType[*IncludeAll] `json:"include-all"`

	ProfileID uuid.UUID
}

func (i *Import) UnmarshalOscal(oi oscalTypes_1_1_3.Import) *Import {
	*i = Import{
		UUIDModel:  UUIDModel{},
		Href:       oi.Href,
		IncludeAll: datatypes.NewJSONType[*IncludeAll](oi.IncludeAll),
	}
	return i
}

func (i *Import) MarshalOscal() oscalTypes_1_1_3.Import {
	ret := oscalTypes_1_1_3.Import{
		Href: i.Href,
	}

	if i.IncludeAll.Data() != nil {
		ret.IncludeAll = &oscalTypes_1_1_3.IncludeAll{}
	}

	return ret
}
