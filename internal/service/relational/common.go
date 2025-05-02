package relational

import (
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Prop oscaltypes113.Property

func (p *Prop) UnmarshalOscal(data oscaltypes113.Property) *Prop {
	*p = Prop(data)
	return p
}

func ConvertOscalToProps(data *[]oscaltypes113.Property) datatypes.JSONSlice[Prop] {
	props := ConvertList(data, func(op oscaltypes113.Property) Prop {
		prop := Prop{}
		prop.UnmarshalOscal(op)
		return prop
	})
	return datatypes.NewJSONSlice[Prop](props)
}

func ConvertPropsToOscal(data datatypes.JSONSlice[Prop]) *[]oscaltypes113.Property {
	out := make([]oscaltypes113.Property, 0)
	for _, v := range data {
		out = append(out, oscaltypes113.Property(v))
	}
	return &out
}

type Link oscaltypes113.Link

func (l *Link) UnmarshalOscal(data oscaltypes113.Link) *Link {
	*l = Link(data)
	return l
}

func ConvertOscalToLinks(data *[]oscaltypes113.Link) datatypes.JSONSlice[Link] {
	links := ConvertList(data, func(ol oscaltypes113.Link) Link {
		link := Link{}
		link.UnmarshalOscal(ol)
		return link
	})
	return datatypes.NewJSONSlice[Link](links)
}

func ConvertLinksToOscal(data datatypes.JSONSlice[Link]) *[]oscaltypes113.Link {
	out := make([]oscaltypes113.Link, 0)
	for _, v := range data {
		out = append(out, oscaltypes113.Link(v))
	}
	return &out
}

type DocumentIDScheme string

const (
	DocumentIDSchemeDoi DocumentIDScheme = "http://www.doi.org/"
)

type DocumentID struct {
	Scheme     DocumentIDScheme `json:"scheme"`
	Identifier string           `json:"identifier"`
}

func (d *DocumentID) UnmarshalOscal(id oscaltypes113.DocumentId) *DocumentID {
	*d = DocumentID{
		Scheme:     DocumentIDScheme(id.Scheme),
		Identifier: id.Identifier,
	}
	return d
}

// MarshalOscal converts the DocumentID back to an OSCAL DocumentId
func (d *DocumentID) MarshalOscal() *oscaltypes113.DocumentId {
	return &oscaltypes113.DocumentId{
		Scheme:     string(d.Scheme),
		Identifier: d.Identifier,
	}
}

type AddressType string

const (
	AddressTypeWork AddressType = "work"
	AddressTypeHome AddressType = "home"
)

type Address struct {
	Type       AddressType `json:"type"`
	AddrLines  []string    `json:"lines"`
	City       string      `json:"city"`
	State      string      `json:"state"`
	PostalCode string      `json:"postal-code"`
	Country    string      `json:"country"`
}

func (a *Address) UnmarshalOscal(oaddress oscaltypes113.Address) *Address {
	*a = Address{
		Type:       AddressType(oaddress.Type),
		AddrLines:  *oaddress.AddrLines,
		City:       oaddress.City,
		State:      oaddress.State,
		PostalCode: oaddress.PostalCode,
		Country:    oaddress.Country,
	}
	return a
}

// MarshalOscal converts the Address back to an OSCAL Address
func (a *Address) MarshalOscal() *oscaltypes113.Address {
	addr := &oscaltypes113.Address{
		Type:       string(a.Type),
		AddrLines:  &a.AddrLines,
		City:       a.City,
		State:      a.State,
		PostalCode: a.PostalCode,
		Country:    a.Country,
	}
	return addr
}

type TelephoneNumberType string

const (
	TelephoneNumberTypeHome   TelephoneNumberType = "home"
	TelephoneNumberTypeOffice TelephoneNumberType = "office"
	TelephoneNumberTypeMobile TelephoneNumberType = "mobile"
)

type TelephoneNumber struct {
	Type   *TelephoneNumberType `json:"type"`
	Number string               `json:"number"`

	/**
	"required": [
		"number"
	],
	*/
}

func (t *TelephoneNumber) UnmarshalOscal(number oscaltypes113.TelephoneNumber) *TelephoneNumber {
	ntype := TelephoneNumberType(number.Type)
	*t = TelephoneNumber{
		Type:   &ntype,
		Number: number.Number,
	}
	return t
}

// MarshalOscal converts the TelephoneNumber back to an OSCAL TelephoneNumber
func (t *TelephoneNumber) MarshalOscal() *oscaltypes113.TelephoneNumber {
	tn := &oscaltypes113.TelephoneNumber{
		Number: t.Number,
	}
	if t.Type != nil {
		tn.Type = string(*t.Type)
	}
	return tn
}

type ResponsibleParty struct {
	UUIDModel
	Props   datatypes.JSONSlice[Prop] `json:"props"`
	Links   datatypes.JSONSlice[Link] `json:"links"`
	Remarks string                    `json:"remarks"`

	RoleID  string `json:"role-id"` // required
	Role    Role
	Parties []Party `gorm:"many2many:responsible_party_parties;"`
}

func (r *ResponsibleParty) UnmarshalOscal(or oscaltypes113.ResponsibleParty) *ResponsibleParty {
	*r = ResponsibleParty{
		Props: ConvertList(or.Props, func(property oscaltypes113.Property) Prop {
			prop := Prop{}
			prop.UnmarshalOscal(property)
			return prop
		}),
		Links: ConvertList(or.Links, func(olink oscaltypes113.Link) Link {
			link := Link{}
			link.UnmarshalOscal(olink)
			return link
		}),
		Remarks: or.Remarks,
		RoleID:  or.RoleId,
		Parties: ConvertList(&or.PartyUuids, func(olink string) Party {
			id := uuid.MustParse(olink)
			return Party{
				UUIDModel: UUIDModel{
					ID: &id,
				},
			}
		}),
	}

	return r
}

// MarshalOscal converts the ResponsibleParty back to an OSCAL ResponsibleParty
func (r *ResponsibleParty) MarshalOscal() *oscaltypes113.ResponsibleParty {
	rp := &oscaltypes113.ResponsibleParty{
		Remarks: r.Remarks,
		RoleId:  r.RoleID,
	}
	if len(r.Props) > 0 {
		props := *ConvertPropsToOscal(r.Props)
		rp.Props = &props
	}
	if len(r.Links) > 0 {
		links := *ConvertLinksToOscal(r.Links)
		rp.Links = &links
	}
	if len(r.Parties) > 0 {
		uuids := make([]string, len(r.Parties))
		for i, p := range r.Parties {
			uuids[i] = p.UUIDModel.ID.String()
		}
		rp.PartyUuids = uuids
	}
	return rp
}

type UUIDModel struct {
	ID *uuid.UUID `json:"id" gorm:"type:uuid;primary_key;"`
}

func (u *UUIDModel) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == nil {
		id := uuid.New()
		u.ID = &id
	}
	return
}
