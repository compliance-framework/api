package relational

import (
	"time"

	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Metadata struct {
	UUIDModel

	// Metadata is shared across many resources, and so it mapped using a polymorphic relationship
	ParentID   *string
	ParentType *string

	Title              string                          `json:"title"`
	Published          *time.Time                      `json:"published"`
	LastModified       *time.Time                      `json:"last-modified"`
	Version            string                          `json:"version"`
	OscalVersion       string                          `json:"oscal-version"`
	DocumentIDs        datatypes.JSONSlice[DocumentID] `json:"document-ids"` // -> DocumentID
	Props              datatypes.JSONSlice[Prop]       `json:"props"`
	Links              datatypes.JSONSlice[Link]       `json:"links"`
	ResponsibleParties []ResponsibleParty              `gorm:"many2many:metadata_responsible_parties;"`
	Revisions          []Revision                      `json:"revisions"`
	Roles              []Role                          `json:"roles" gorm:"many2many:metadata_roles"`
	Locations          []Location                      `json:"locations"`
	Parties            []Party                         `json:"parties" gorm:"many2many:metadata_parties"`
	Actions            []Action                        `json:"actions"`
	Remarks            string                          `json:"remarks"`

	/**
	"required": [
		"title",
		"last-modified",
		"version",
		"oscal-version"
	],
	*/
}

func (m *Metadata) UnmarshalOscal(metadata oscaltypes113.Metadata) *Metadata {
	*m = Metadata{
		Title:        metadata.Title,
		Published:    metadata.Published,
		LastModified: &metadata.LastModified,
		Version:      metadata.Version,
		OscalVersion: metadata.OscalVersion,
		DocumentIDs: func() datatypes.JSONSlice[DocumentID] {
			list := make([]DocumentID, 0)
			if metadata.DocumentIds != nil {
				for _, document := range *metadata.DocumentIds {
					doc := DocumentID{}
					doc.UnmarshalOscal(document)
					list = append(list, doc)
				}
			}
			return datatypes.NewJSONSlice[DocumentID](list)
		}(),
		Props: ConvertOscalToProps(metadata.Props),
		Links: ConvertOscalToLinks(metadata.Links),
		Revisions: ConvertList(metadata.Revisions, func(entry oscaltypes113.RevisionHistoryEntry) Revision {
			revision := Revision{}
			revision.UnmarshalOscal(entry)
			return revision
		}),
		Roles: ConvertList(metadata.Roles, func(orole oscaltypes113.Role) Role {
			role := Role{}
			role.UnmarshalOscal(orole)
			return role
		}),
		Locations: ConvertList(metadata.Locations, func(oloc oscaltypes113.Location) Location {
			location := Location{}
			location.UnmarshalOscal(oloc)
			return location
		}),
		Parties: ConvertList(metadata.Parties, func(oparty oscaltypes113.Party) Party {
			party := Party{}
			party.UnmarshalOscal(oparty)
			return party
		}),
		ResponsibleParties: ConvertList(metadata.ResponsibleParties, func(oparty oscaltypes113.ResponsibleParty) ResponsibleParty {
			party := ResponsibleParty{}
			party.UnmarshalOscal(oparty)
			return party
		}),
		Actions: ConvertList(metadata.Actions, func(oaction oscaltypes113.Action) Action {
			action := Action{}
			action.UnmarshalOscal(oaction)
			return action
		}),
		Remarks: metadata.Remarks,
	}
	return m
}

// MarshalOscal converts the Metadata back to an OSCAL Metadata
func (m *Metadata) MarshalOscal() *oscaltypes113.Metadata {
	md := &oscaltypes113.Metadata{
		Title:        m.Title,
		Published:    m.Published,
		Version:      m.Version,
		OscalVersion: m.OscalVersion,
		Remarks:      m.Remarks,
	}
	if m.LastModified != nil {
		md.LastModified = *m.LastModified
	}
	if len(m.DocumentIDs) > 0 {
		docs := make([]oscaltypes113.DocumentId, len(m.DocumentIDs))
		for i, d := range m.DocumentIDs {
			docs[i] = *d.MarshalOscal()
		}
		md.DocumentIds = &docs
	}
	if len(m.Props) > 0 {
		props := *ConvertPropsToOscal(m.Props)
		md.Props = &props
	}
	if len(m.Links) > 0 {
		links := *ConvertLinksToOscal(m.Links)
		md.Links = &links
	}
	if len(m.Revisions) > 0 {
		revs := make([]oscaltypes113.RevisionHistoryEntry, len(m.Revisions))
		for i, r := range m.Revisions {
			revs[i] = *r.MarshalOscal()
		}
		md.Revisions = &revs
	}
	if len(m.Roles) > 0 {
		roles := make([]oscaltypes113.Role, len(m.Roles))
		for i, r := range m.Roles {
			roles[i] = *r.MarshalOscal()
		}
		md.Roles = &roles
	}
	if len(m.Locations) > 0 {
		locs := make([]oscaltypes113.Location, len(m.Locations))
		for i, l := range m.Locations {
			locs[i] = *l.MarshalOscal()
		}
		md.Locations = &locs
	}
	if len(m.Parties) > 0 {
		parts := make([]oscaltypes113.Party, len(m.Parties))
		for i, p := range m.Parties {
			parts[i] = *p.MarshalOscal()
		}
		md.Parties = &parts
	}
	if len(m.ResponsibleParties) > 0 {
		rps := make([]oscaltypes113.ResponsibleParty, len(m.ResponsibleParties))
		for i, rp := range m.ResponsibleParties {
			rps[i] = *rp.MarshalOscal()
		}
		md.ResponsibleParties = &rps
	}
	if len(m.Actions) > 0 {
		acts := make([]oscaltypes113.Action, len(m.Actions))
		for i, a := range m.Actions {
			acts[i] = *a.MarshalOscal()
		}
		md.Actions = &acts
	}
	return md
}

type Action struct {
	UUIDModel

	// Actions only exist on a metadata object. We'll link them straight there with a BelongsTo relationship
	MetadataID uuid.UUID `json:"metadata-id"`

	Date               *time.Time                `json:"date"`
	Type               string                    `json:"type"`   // required
	System             string                    `json:"system"` // required
	Props              datatypes.JSONSlice[Prop] `json:"props"`
	Links              datatypes.JSONSlice[Link] `json:"links"`
	ResponsibleParties []ResponsibleParty        `gorm:"many2many:action_responsible_parties;"`
	Remarks            string                    `json:"remarks"`
}

func (a *Action) UnmarshalOscal(action oscaltypes113.Action) *Action {
	var date *time.Time = nil
	if action.Date != nil {
		date = action.Date
	}
	*a = Action{
		UUIDModel: UUIDModel{
			ID: func() *uuid.UUID {
				id := uuid.MustParse(action.UUID)
				return &id
			}(),
		},
		Date:   date,
		Type:   action.Type,
		System: action.System,
		Props: ConvertList(action.Props, func(property oscaltypes113.Property) Prop {
			prop := Prop{}
			prop.UnmarshalOscal(property)
			return prop
		}),
		Links: ConvertList(action.Links, func(olink oscaltypes113.Link) Link {
			link := Link{}
			link.UnmarshalOscal(olink)
			return link
		}),
		ResponsibleParties: ConvertList(action.ResponsibleParties, func(oparty oscaltypes113.ResponsibleParty) ResponsibleParty {
			party := ResponsibleParty{}
			party.UnmarshalOscal(oparty)
			return party
		}),
		Remarks: action.Remarks,
	}

	return a
}

// MarshalOscal converts the Action back to an OSCAL Action
func (a *Action) MarshalOscal() *oscaltypes113.Action {
	act := &oscaltypes113.Action{
		UUID:    a.UUIDModel.ID.String(),
		Date:    nil,
		Type:    a.Type,
		System:  a.System,
		Remarks: a.Remarks,
	}
	if a.Date != nil {
		act.Date = a.Date
	}
	if len(a.Props) > 0 {
		props := *ConvertPropsToOscal(a.Props)
		act.Props = &props
	}
	if len(a.Links) > 0 {
		links := *ConvertLinksToOscal(a.Links)
		act.Links = &links
	}
	if len(a.ResponsibleParties) > 0 {
		rps := make([]oscaltypes113.ResponsibleParty, len(a.ResponsibleParties))
		for i, rp := range a.ResponsibleParties {
			rps[i] = *rp.MarshalOscal()
		}
		act.ResponsibleParties = &rps
	}
	return act
}

type PartyType string

const (
	PartyTypePerson       PartyType = "person"
	PartyTypeOrganization PartyType = "organization"
)

type PartyExternalIDScheme string

const PartyExternalIDSchemeOrchid PartyExternalIDScheme = "http://orcid.org/"

type PartyExternalID struct {
	ID     string                `json:"id"`
	Scheme PartyExternalIDScheme `json:"scheme"`

	/**
	"required": [
		"id",
		"scheme"
	],
	*/
}

func (p *PartyExternalID) UnmarshalOscal(oid oscaltypes113.PartyExternalIdentifier) *PartyExternalID {
	p.ID = oid.ID
	p.Scheme = PartyExternalIDScheme(oid.Scheme)

	return p
}

// MarshalOscal converts the PartyExternalID back to an OSCAL PartyExternalIdentifier
func (p *PartyExternalID) MarshalOscal() *oscaltypes113.PartyExternalIdentifier {
	return &oscaltypes113.PartyExternalIdentifier{
		ID:     p.ID,
		Scheme: string(p.Scheme),
	}
}

type Party struct {
	UUIDModel

	// Parties only exist on a metadata object. We'll link them straight there with a BelongsTo relationship
	MetadataID uuid.UUID `json:"metadata-id"`

	Type                  PartyType                            `json:"type"`
	Name                  *string                              `json:"name"`
	ShortName             *string                              `json:"short-name"`
	ExternalIds           datatypes.JSONSlice[PartyExternalID] `json:"external-ids"`
	Props                 datatypes.JSONSlice[Prop]            `json:"props"`
	Links                 datatypes.JSONSlice[Link]            `json:"links"`
	EmailAddresses        datatypes.JSONSlice[string]          `json:"email-addresses"`
	TelephoneNumbers      datatypes.JSONSlice[TelephoneNumber] `json:"telephone-numbers"`
	Addresses             datatypes.JSONSlice[Address]         `json:"addresses"`
	Locations             []Location                           `json:"locations" gorm:"many2many:party_locations;"`
	MemberOfOrganizations []Party                              `json:"member-of-organizations" gorm:"many2many:party_member_of_organisations;"` // -> Party
	Remarks               *string                              `json:"remarks"`

	/**
	"required": [
		"uuid",
		"type"
	],
	*/
}

func (p *Party) UnmarshalOscal(oparty oscaltypes113.Party) *Party {
	*p = Party{
		UUIDModel: UUIDModel{
			ID: func() *uuid.UUID {
				id := uuid.MustParse(oparty.UUID)
				return &id
			}(),
		},
		Type:      PartyType(oparty.Type),
		Name:      &oparty.Name,
		ShortName: &oparty.ShortName,
		ExternalIds: ConvertList(oparty.ExternalIds, func(id oscaltypes113.PartyExternalIdentifier) PartyExternalID {
			pei := PartyExternalID{}
			pei.UnmarshalOscal(id)
			return pei
		}),
		Props: ConvertList(oparty.Props, func(property oscaltypes113.Property) Prop {
			prop := Prop{}
			prop.UnmarshalOscal(property)
			return prop
		}),
		Links: ConvertList(oparty.Links, func(olink oscaltypes113.Link) Link {
			link := Link{}
			link.UnmarshalOscal(olink)
			return link
		}),
		TelephoneNumbers: ConvertList(oparty.TelephoneNumbers, func(onumber oscaltypes113.TelephoneNumber) TelephoneNumber {
			number := TelephoneNumber{}
			number.UnmarshalOscal(onumber)
			return number
		}),
		Addresses: ConvertList(oparty.Addresses, func(oaddress oscaltypes113.Address) Address {
			address := Address{}
			address.UnmarshalOscal(oaddress)
			return address
		}),
		Locations: ConvertList(oparty.LocationUuids, func(oloc string) Location {
			id := uuid.MustParse(oloc)
			location := Location{
				UUIDModel: UUIDModel{
					ID: &id,
				},
			}
			return location
		}),
		MemberOfOrganizations: ConvertList(oparty.MemberOfOrganizations, func(morg string) Party {
			id := uuid.MustParse(morg)
			organization := Party{
				UUIDModel: UUIDModel{
					ID: &id,
				},
			}
			return organization
		}),
		Remarks: &oparty.Remarks,
	}

	if oparty.EmailAddresses != nil {
		p.EmailAddresses = *oparty.EmailAddresses
	}

	return p
}

// MarshalOscal converts the Party back to an OSCAL Party
func (p *Party) MarshalOscal() *oscaltypes113.Party {
	party := &oscaltypes113.Party{
		UUID: p.UUIDModel.ID.String(),
		Type: string(p.Type),
	}
	if p.Name != nil {
		party.Name = *p.Name
	}
	if p.ShortName != nil {
		party.ShortName = *p.ShortName
	}
	if len(p.ExternalIds) > 0 {
		ext := make([]oscaltypes113.PartyExternalIdentifier, len(p.ExternalIds))
		for i, id := range p.ExternalIds {
			ext[i] = *id.MarshalOscal()
		}
		party.ExternalIds = &ext
	}
	if len(p.Props) > 0 {
		props := *ConvertPropsToOscal(p.Props)
		party.Props = &props
	}
	if len(p.Links) > 0 {
		links := *ConvertLinksToOscal(p.Links)
		party.Links = &links
	}
	if len(p.EmailAddresses) > 0 {
		emails := make([]string, len(p.EmailAddresses))
		copy(emails, p.EmailAddresses)
		party.EmailAddresses = &emails
	}
	if len(p.TelephoneNumbers) > 0 {
		tns := make([]oscaltypes113.TelephoneNumber, len(p.TelephoneNumbers))
		for i, tn := range p.TelephoneNumbers {
			tns[i] = *tn.MarshalOscal()
		}
		party.TelephoneNumbers = &tns
	}
	if len(p.Addresses) > 0 {
		addrs := make([]oscaltypes113.Address, len(p.Addresses))
		for i, a := range p.Addresses {
			addrs[i] = *a.MarshalOscal()
		}
		party.Addresses = &addrs
	}
	if p.Remarks != nil {
		party.Remarks = *p.Remarks
	}
	if p.MemberOfOrganizations != nil {
		morg := make([]string, len(p.MemberOfOrganizations))
		for i, org := range p.MemberOfOrganizations {
			morg[i] = org.ID.String()
		}
		party.MemberOfOrganizations = &morg
	}
	if p.Locations != nil {
		locs := make([]string, len(p.Locations))
		for i, loc := range p.Locations {
			locs[i] = loc.ID.String()
		}
		party.LocationUuids = &locs
	}

	return party
}

type Revision struct {
	// Only version is required
	UUIDModel

	// Revision only exist on a metadata object. We'll link them straight there with a BelongsTo relationship
	MetadataID uuid.UUID `json:"metadata-id"`

	Title        *string                   `json:"title"`
	Published    *time.Time                `json:"published"`
	LastModified *time.Time                `json:"last-modified"`
	Version      string                    `json:"version"` // required
	OscalVersion *string                   `json:"oscal-version"`
	Props        datatypes.JSONSlice[Prop] `json:"props"`
	Links        datatypes.JSONSlice[Link] `json:"links"`
	Remarks      *string                   `json:"remarks"`
}

func (r *Revision) UnmarshalOscal(entry oscaltypes113.RevisionHistoryEntry) *Revision {
	r.Published = entry.Published
	r.LastModified = entry.LastModified
	r.Version = entry.Version
	r.OscalVersion = &entry.OscalVersion
	r.Title = &entry.Title
	r.Remarks = &entry.Remarks
	r.Props = ConvertList(entry.Props, func(property oscaltypes113.Property) Prop {
		prop := Prop{}
		prop.UnmarshalOscal(property)
		return prop
	})
	r.Links = ConvertList(entry.Links, func(olink oscaltypes113.Link) Link {
		link := Link{}
		link.UnmarshalOscal(olink)
		return link
	})

	return r
}

// MarshalOscal converts the Revision back to an OSCAL RevisionHistoryEntry
func (r *Revision) MarshalOscal() *oscaltypes113.RevisionHistoryEntry {
	rev := &oscaltypes113.RevisionHistoryEntry{
		Version:      r.Version,
		Published:    r.Published,
		LastModified: r.LastModified,
	}
	if r.OscalVersion != nil {
		rev.OscalVersion = *r.OscalVersion
	}
	if r.Title != nil {
		rev.Title = *r.Title
	}
	if r.Remarks != nil {
		rev.Remarks = *r.Remarks
	}
	if len(r.Props) > 0 {
		props := *ConvertPropsToOscal(r.Props)
		rev.Props = &props
	}
	if len(r.Links) > 0 {
		links := *ConvertLinksToOscal(r.Links)
		rev.Links = &links
	}
	return rev
}

type Role struct {
	ID string `json:"id" gorm:"primary_key;"`

	// Roles only exist on a metadata object. We'll link them straight there with a BelongsTo relationship
	MetadataID uuid.UUID `json:"metadata-id"`

	Title       string                    `json:"title"`
	ShortName   *string                   `json:"short-name"`
	Description *string                   `json:"description"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Remarks     *string                   `json:"remarks"`
}

func (r *Role) UnmarshalOscal(entry oscaltypes113.Role) *Role {
	r.ID = entry.ID
	r.Title = entry.Title
	r.ShortName = &entry.ShortName
	r.Description = &entry.Description
	r.Remarks = &entry.Remarks
	r.Props = ConvertList(entry.Props, func(property oscaltypes113.Property) Prop {
		prop := Prop{}
		prop.UnmarshalOscal(property)
		return prop
	})
	r.Links = ConvertList(entry.Links, func(olink oscaltypes113.Link) Link {
		link := Link{}
		link.UnmarshalOscal(olink)
		return link
	})

	return r
}

// MarshalOscal converts the Role back to an OSCAL Role
func (r *Role) MarshalOscal() *oscaltypes113.Role {
	role := &oscaltypes113.Role{
		ID:          r.ID,
		Title:       r.Title,
		ShortName:   *r.ShortName,
		Description: *r.Description,
		Remarks:     *r.Remarks,
	}
	if len(r.Props) > 0 {
		props := *ConvertPropsToOscal(r.Props)
		role.Props = &props
	}
	if len(r.Links) > 0 {
		links := *ConvertLinksToOscal(r.Links)
		role.Links = &links
	}
	return role
}

type Location struct {
	UUIDModel

	// Locations only exist on a metadata object. We'll link them straight there with a BelongsTo relationship
	MetadataID uuid.UUID `json:"metadata-id"`

	Title            *string                              `json:"title"`
	Address          *datatypes.JSONType[Address]         `json:"address"`
	EmailAddresses   datatypes.JSONSlice[string]          `json:"email-addresses"`
	TelephoneNumbers datatypes.JSONSlice[TelephoneNumber] `json:"telephone-numbers"`
	Urls             datatypes.JSONSlice[string]          `json:"urls"`
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	Remarks          *string                              `json:"remarks"`
	/**
	"required": [
		"uuid"
	],
	*/
}

func (l *Location) UnmarshalOscal(olocation oscaltypes113.Location) *Location {
	*l = Location{
		UUIDModel: UUIDModel{
			ID: func() *uuid.UUID {
				id := uuid.MustParse(olocation.UUID)
				return &id
			}(),
		},
		Title: &olocation.Title,
		TelephoneNumbers: ConvertList(olocation.TelephoneNumbers, func(onumb oscaltypes113.TelephoneNumber) TelephoneNumber {
			numb := TelephoneNumber{}
			numb.UnmarshalOscal(onumb)
			return numb
		}),
		Props: ConvertList(olocation.Props, func(property oscaltypes113.Property) Prop {
			prop := Prop{}
			prop.UnmarshalOscal(property)
			return prop
		}),
		Links: ConvertList(olocation.Links, func(olink oscaltypes113.Link) Link {
			link := Link{}
			link.UnmarshalOscal(olink)
			return link
		}),
		Remarks: &olocation.Remarks,
	}

	if olocation.Urls != nil {
		l.Urls = *olocation.Urls
	}

	if olocation.EmailAddresses != nil {
		l.EmailAddresses = *olocation.EmailAddresses
	}

	if olocation.Address != nil {
		address := Address{}
		address.UnmarshalOscal(*olocation.Address)
		addressJson := datatypes.NewJSONType[Address](address)
		l.Address = &addressJson
	}

	return l
}

// MarshalOscal converts the Location back to an OSCAL Location
func (l *Location) MarshalOscal() *oscaltypes113.Location {
	loc := &oscaltypes113.Location{
		UUID:    l.UUIDModel.ID.String(),
		Remarks: *l.Remarks,
		Title:   *l.Title,
	}
	if len(l.Props) > 0 {
		props := *ConvertPropsToOscal(l.Props)
		loc.Props = &props
	}
	if len(l.Links) > 0 {
		links := *ConvertLinksToOscal(l.Links)
		loc.Links = &links
	}
	if len(l.EmailAddresses) > 0 {
		emails := make([]string, len(l.EmailAddresses))
		copy(emails, l.EmailAddresses)
		loc.EmailAddresses = &emails
	}
	if len(l.TelephoneNumbers) > 0 {
		tns := make([]oscaltypes113.TelephoneNumber, len(l.TelephoneNumbers))
		for i, tn := range l.TelephoneNumbers {
			tns[i] = *tn.MarshalOscal()
		}
		loc.TelephoneNumbers = &tns
	}
	if len(l.Urls) > 0 {
		urls := make([]string, len(l.Urls))
		copy(urls, l.Urls)
		loc.Urls = &urls
	}
	if l.Address != nil {
		addr := l.Address.Data()
		loc.Address = addr.MarshalOscal()
	}
	return loc
}
