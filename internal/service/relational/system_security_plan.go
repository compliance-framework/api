package relational

import (
	"fmt"
	"time"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type SystemSecurityPlan struct {
	UUIDModel
	Metadata   Metadata    `json:"metadata" gorm:"polymorphic:Parent;"`
	BackMatter *BackMatter `json:"back-matter" gorm:"polymorphic:Parent;"`

	ImportProfile         datatypes.JSONType[ImportProfile] `json:"import-profile"`
	SystemCharacteristics SystemCharacteristics             `json:"system-characteristics"`
	SystemImplementation  SystemImplementation              `json:"system-implementation"`
	ControlImplementation ControlImplementation             `json:"control-implementation"`

	ProfileID *uuid.UUID
	Profile   *Profile
}

func (s *SystemSecurityPlan) UnmarshalOscal(os oscalTypes_1_1_3.SystemSecurityPlan) *SystemSecurityPlan {
	id := uuid.MustParse(os.UUID)
	metadata := Metadata{}
	metadata.UnmarshalOscal(os.Metadata)

	importProfile := ImportProfile{}
	importProfile.UnmarshalOscal(os.ImportProfile)

	systemCharacteristics := SystemCharacteristics{}
	systemCharacteristics.UnmarshalOscal(os.SystemCharacteristics)

	systemImplementation := SystemImplementation{}
	systemImplementation.UnmarshalOscal(os.SystemImplementation)

	controlImplementation := ControlImplementation{}
	controlImplementation.UnmarshalOscal(os.ControlImplementation)

	*s = SystemSecurityPlan{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Metadata:              metadata,
		ImportProfile:         datatypes.NewJSONType(importProfile),
		SystemCharacteristics: systemCharacteristics,
		SystemImplementation:  systemImplementation,
		ControlImplementation: controlImplementation,
	}

	if os.BackMatter != nil {
		backMatter := &BackMatter{}
		backMatter.UnmarshalOscal(*os.BackMatter)
		s.BackMatter = backMatter
	}

	return s
}

func (s *SystemSecurityPlan) MarshalOscal() *oscalTypes_1_1_3.SystemSecurityPlan {
	plan := &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID:                  s.UUIDModel.ID.String(),
		Metadata:              *s.Metadata.MarshalOscal(),
		ControlImplementation: *s.ControlImplementation.MarshalOscal(),
		SystemCharacteristics: *s.SystemCharacteristics.MarshalOscal(),
		SystemImplementation:  *s.SystemImplementation.MarshalOscal(),
	}

	importProfile := s.ImportProfile.Data()
	plan.ImportProfile = *importProfile.MarshalOscal()

	if s.BackMatter != nil {
		plan.BackMatter = s.BackMatter.MarshalOscal()
	}

	return plan
}

type ImportProfile oscalTypes_1_1_3.ImportProfile

func (ip *ImportProfile) UnmarshalOscal(oip oscalTypes_1_1_3.ImportProfile) *ImportProfile {
	*ip = ImportProfile(oip)
	return ip
}

func (ip *ImportProfile) MarshalOscal() *oscalTypes_1_1_3.ImportProfile {
	p := oscalTypes_1_1_3.ImportProfile(*ip)
	return &p
}

type SystemCharacteristics struct {
	UUIDModel
	SystemName               string     `json:"system-name"`
	SystemNameShort          string     `json:"system-name-short"`
	Description              string     `json:"description"`
	DateAuthorized           *time.Time `json:"date-authorized"`
	SecuritySensitivityLevel string     `json:"security-sensitivity-level"`
	Remarks                  string     `json:"remarks"`

	SystemIds             datatypes.JSONSlice[SystemId]         `json:"system-ids"`
	Status                datatypes.JSONType[Status]            `json:"status"`
	SystemInformation     datatypes.JSONType[SystemInformation] `json:"system-information"`
	AuthorizationBoundary *AuthorizationBoundary                `json:"authorization-boundary"`
	NetworkArchitecture   *NetworkArchitecture
	DataFlow              *DataFlow
	SecurityImpactLevel   *datatypes.JSONType[SecurityImpactLevel] `json:"security-impact-level"`
	Links                 datatypes.JSONSlice[Link]                `json:"links"`
	Props                 datatypes.JSONSlice[Prop]                `json:"props"`
	ResponsibleParties    datatypes.JSONSlice[ResponsibleParty]    `json:"responsible-parties"`

	SystemSecurityPlanId uuid.UUID
}

func (sc *SystemCharacteristics) UnmarshalOscal(osc oscalTypes_1_1_3.SystemCharacteristics) *SystemCharacteristics {
	props := ConvertOscalToProps(osc.Props)
	links := ConvertOscalToLinks(osc.Links)

	systemIds := ConvertList(&osc.SystemIds, func(osi oscalTypes_1_1_3.SystemId) SystemId {
		sid := SystemId(osi)
		return sid
	})

	systemInformation := SystemInformation{}
	systemInformation.UnmarshalOscal(osc.SystemInformation)

	status := Status{}
	status.UnmarshalOscal(osc.Status)

	authBoundary := &AuthorizationBoundary{}
	authBoundary.UnmarshalOscal(osc.AuthorizationBoundary)

	responsibleParties := ConvertList(osc.ResponsibleParties, func(orp oscalTypes_1_1_3.ResponsibleParty) ResponsibleParty {
		rp := ResponsibleParty{}
		rp.UnmarshalOscal(orp)
		return rp
	})

	*sc = SystemCharacteristics{
		UUIDModel:                UUIDModel{},
		SystemName:               osc.SystemName,
		SystemNameShort:          osc.SystemNameShort,
		Description:              osc.Description,
		SecuritySensitivityLevel: osc.SecuritySensitivityLevel,
		Remarks:                  osc.Remarks,
		Links:                    links,
		Props:                    props,
		SystemIds:                systemIds,
		SystemInformation:        datatypes.NewJSONType(systemInformation),
		Status:                   datatypes.NewJSONType(status),
		AuthorizationBoundary:    authBoundary,
		ResponsibleParties:       datatypes.NewJSONSlice(responsibleParties),
	}

	if osc.NetworkArchitecture != nil {
		networkArchitecture := &NetworkArchitecture{}
		networkArchitecture.UnmarshalOscal(*osc.NetworkArchitecture)
		sc.NetworkArchitecture = networkArchitecture
	}

	if osc.DataFlow != nil {
		dataFlow := &DataFlow{}
		dataFlow.UnmarshalOscal(*osc.DataFlow)
		sc.DataFlow = dataFlow
	}

	if osc.DateAuthorized != "" {
		if len(osc.DateAuthorized) > 0 {
			parsed, err := time.Parse(time.DateOnly, osc.DateAuthorized)
			if err != nil {
				panic(err)
			}
			sc.DateAuthorized = &parsed
		}
	}

	if osc.SecurityImpactLevel != nil {
		securityImpact := SecurityImpactLevel{}
		jsonType := datatypes.NewJSONType(*securityImpact.UnmarshalOscal(*osc.SecurityImpactLevel))
		sc.SecurityImpactLevel = &jsonType
	}

	return sc
}

// MarshalOscal converts the SystemCharacteristics back to an OSCAL SystemCharacteristics
func (sc *SystemCharacteristics) MarshalOscal() *oscalTypes_1_1_3.SystemCharacteristics {
	oc := &oscalTypes_1_1_3.SystemCharacteristics{
		SystemName:               sc.SystemName,
		SystemNameShort:          sc.SystemNameShort,
		Description:              sc.Description,
		SecuritySensitivityLevel: sc.SecuritySensitivityLevel,
		Remarks:                  sc.Remarks,
	}
	if sc.DateAuthorized != nil {
		oc.DateAuthorized = sc.DateAuthorized.Format(time.DateOnly)
	}
	if len(sc.SystemIds) > 0 {
		ids := make([]oscalTypes_1_1_3.SystemId, len(sc.SystemIds))
		for i, sid := range sc.SystemIds {
			ids[i] = *sid.MarshalOscal()
		}
		oc.SystemIds = ids
	}

	systemInfo := sc.SystemInformation.Data()
	oc.SystemInformation = *systemInfo.MarshalOscal()

	status := sc.Status.Data()
	oc.Status = *status.MarshalOscal()

	if sc.AuthorizationBoundary != nil {
		oc.AuthorizationBoundary = *sc.AuthorizationBoundary.MarshalOscal()
	}
	if sc.NetworkArchitecture != nil {
		oc.NetworkArchitecture = sc.NetworkArchitecture.MarshalOscal()
	}
	if sc.DataFlow != nil {
		oc.DataFlow = sc.DataFlow.MarshalOscal()
	}
	if sc.SecurityImpactLevel != nil {
		securityImpact := sc.SecurityImpactLevel.Data()
		oc.SecurityImpactLevel = securityImpact.MarshalOscal()
	}
	if len(sc.Props) > 0 {
		oc.Props = ConvertPropsToOscal(sc.Props)
	}
	if len(sc.Links) > 0 {
		oc.Links = ConvertLinksToOscal(sc.Links)
	}
	if len(sc.ResponsibleParties) > 0 {
		rp := make([]oscalTypes_1_1_3.ResponsibleParty, len(sc.ResponsibleParties))
		for i, party := range sc.ResponsibleParties {
			rp[i] = *party.MarshalOscal()
		}
		oc.ResponsibleParties = &rp
	}
	return oc
}

type SystemId oscalTypes_1_1_3.SystemId

func (si *SystemId) UnmarshalOscal(osi oscalTypes_1_1_3.SystemId) *SystemId {
	*si = SystemId(osi)
	return si
}

func (si *SystemId) MarshalOscal() *oscalTypes_1_1_3.SystemId {
	ret := oscalTypes_1_1_3.SystemId(*si)
	return &ret
}

type SystemInformation struct {
	UUIDModel
	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`

	InformationTypes []InformationType `json:"information-types"`

	SystemCharacteristicsId uuid.UUID
}

func (si *SystemInformation) UnmarshalOscal(osi oscalTypes_1_1_3.SystemInformation) *SystemInformation {
	props := ConvertOscalToProps(osi.Props)
	links := ConvertOscalToLinks(osi.Links)

	informationTypes := ConvertList(&osi.InformationTypes, func(oit oscalTypes_1_1_3.InformationType) InformationType {
		informationType := InformationType{}
		informationType.UnmarshalOscal(oit)
		return informationType
	})

	*si = SystemInformation{
		UUIDModel:        UUIDModel{},
		Props:            props,
		Links:            links,
		InformationTypes: informationTypes,
	}

	return si
}

func (si *SystemInformation) MarshalOscal() *oscalTypes_1_1_3.SystemInformation {
	ret := &oscalTypes_1_1_3.SystemInformation{}
	if len(si.Props) > 0 {
		ret.Props = ConvertPropsToOscal(si.Props)
	}
	if len(si.Links) > 0 {
		ret.Links = ConvertLinksToOscal(si.Links)
	}
	if len(si.InformationTypes) > 0 {
		its := make([]oscalTypes_1_1_3.InformationType, len(si.InformationTypes))
		for i, it := range si.InformationTypes {
			its[i] = *it.MarshalOscal()
		}
		ret.InformationTypes = its
	}
	return ret
}

type InformationType struct {
	UUIDModel
	Title                 string                                             `json:"title"`
	Description           string                                             `json:"description"`
	Props                 datatypes.JSONSlice[Prop]                          `json:"props"`
	Links                 datatypes.JSONSlice[Link]                          `json:"links"`
	ConfidentialityImpact *datatypes.JSONType[Impact]                        `json:"confidentiality-impact"`
	IntegrityImpact       *datatypes.JSONType[Impact]                        `json:"integrity-impact"`
	AvailabilityImpact    *datatypes.JSONType[Impact]                        `json:"availability-impact"`
	Categorizations       datatypes.JSONSlice[InformationTypeCategorization] `json:"categorizations"`

	SystemInformationId uuid.UUID
}

func (it *InformationType) UnmarshalOscal(oit oscalTypes_1_1_3.InformationType) *InformationType {
	id := uuid.MustParse(oit.UUID)

	props := ConvertOscalToProps(oit.Props)
	links := ConvertOscalToLinks(oit.Links)

	categorizations := ConvertList(oit.Categorizations, func(oitc oscalTypes_1_1_3.InformationTypeCategorization) InformationTypeCategorization {
		category := InformationTypeCategorization{}
		category.UnmarshalOscal(oitc)
		return category
	})

	*it = InformationType{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:           oit.Title,
		Description:     oit.Description,
		Props:           props,
		Links:           links,
		Categorizations: categorizations,
	}

	if oit.ConfidentialityImpact != nil {
		confImpact := Impact{}
		confImpact.UnmarshalOscal(*oit.ConfidentialityImpact)
		jsonImp := datatypes.NewJSONType(confImpact)
		it.ConfidentialityImpact = &jsonImp
	}

	if oit.IntegrityImpact != nil {
		intImpact := Impact{}
		intImpact.UnmarshalOscal(*oit.IntegrityImpact)
		jsonImp := datatypes.NewJSONType(intImpact)
		it.IntegrityImpact = &jsonImp
	}

	if oit.AvailabilityImpact != nil {
		availImpact := Impact{}
		availImpact.UnmarshalOscal(*oit.AvailabilityImpact)
		jsonImp := datatypes.NewJSONType(availImpact)
		it.AvailabilityImpact = &jsonImp
	}

	return it
}

func (it *InformationType) MarshalOscal() *oscalTypes_1_1_3.InformationType {
	ret := &oscalTypes_1_1_3.InformationType{
		UUID:        it.UUIDModel.ID.String(),
		Title:       it.Title,
		Description: it.Description,
	}
	if len(it.Props) > 0 {
		ret.Props = ConvertPropsToOscal(it.Props)
	}
	if len(it.Links) > 0 {
		ret.Links = ConvertLinksToOscal(it.Links)
	}
	// JSONType fields
	if it.ConfidentialityImpact != nil {
		ci := it.ConfidentialityImpact.Data()
		ret.ConfidentialityImpact = ci.MarshalOscal()
	}
	if it.IntegrityImpact != nil {
		ii := it.IntegrityImpact.Data()
		ret.IntegrityImpact = ii.MarshalOscal()
	}
	if it.AvailabilityImpact != nil {
		ai := it.AvailabilityImpact.Data()
		ret.AvailabilityImpact = ai.MarshalOscal()
	}
	if len(it.Categorizations) > 0 {
		cats := make([]oscalTypes_1_1_3.InformationTypeCategorization, len(it.Categorizations))
		for i, cat := range it.Categorizations {
			cats[i] = *cat.MarshalOscal()
		}
		ret.Categorizations = &cats
	}
	return ret
}

type Impact oscalTypes_1_1_3.Impact

func (i *Impact) UnmarshalOscal(osi oscalTypes_1_1_3.Impact) *Impact {
	*i = Impact(osi)
	return i
}

func (i *Impact) MarshalOscal() *oscalTypes_1_1_3.Impact {
	ret := oscalTypes_1_1_3.Impact(*i)
	return &ret
}

type InformationTypeCategorization oscalTypes_1_1_3.InformationTypeCategorization

func (itc *InformationTypeCategorization) UnmarshalOscal(oitc oscalTypes_1_1_3.InformationTypeCategorization) *InformationTypeCategorization {
	*itc = InformationTypeCategorization(oitc)
	return itc
}

func (itc *InformationTypeCategorization) MarshalOscal() *oscalTypes_1_1_3.InformationTypeCategorization {
	ret := oscalTypes_1_1_3.InformationTypeCategorization(*itc)
	return &ret
}

type SecurityImpactLevel oscalTypes_1_1_3.SecurityImpactLevel

func (s *SecurityImpactLevel) UnmarshalOscal(osi oscalTypes_1_1_3.SecurityImpactLevel) *SecurityImpactLevel {
	*s = SecurityImpactLevel(osi)
	return s
}

func (s *SecurityImpactLevel) MarshalOscal() *oscalTypes_1_1_3.SecurityImpactLevel {
	ret := oscalTypes_1_1_3.SecurityImpactLevel(*s)
	return &ret
}

type Status oscalTypes_1_1_3.Status

func (s *Status) UnmarshalOscal(osi oscalTypes_1_1_3.Status) *Status {
	*s = Status(osi)
	return s
}

func (s *Status) MarshalOscal() *oscalTypes_1_1_3.Status {
	ret := oscalTypes_1_1_3.Status(*s)
	return &ret
}

type AuthorizationBoundary struct {
	UUIDModel
	Description string                    `json:"description"`
	Remarks     string                    `json:"remarks"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Diagrams    []Diagram                 `json:"diagrams" gorm:"polymorphic:Parent;"`

	SystemCharacteristicsId uuid.UUID
}

func (ab *AuthorizationBoundary) UnmarshalOscal(oab oscalTypes_1_1_3.AuthorizationBoundary) *AuthorizationBoundary {
	links := ConvertOscalToLinks(oab.Links)
	props := ConvertOscalToProps(oab.Props)

	diagrams := ConvertList(oab.Diagrams, func(od oscalTypes_1_1_3.Diagram) Diagram {
		diagram := Diagram{}
		diagram.UnmarshalOscal(od)
		return diagram
	})

	*ab = AuthorizationBoundary{
		UUIDModel:   UUIDModel{},
		Description: oab.Description,
		Remarks:     oab.Remarks,
		Props:       props,
		Links:       links,
		Diagrams:    diagrams,
	}
	return ab
}

func (ab *AuthorizationBoundary) MarshalOscal() *oscalTypes_1_1_3.AuthorizationBoundary {
	ret := &oscalTypes_1_1_3.AuthorizationBoundary{
		Description: ab.Description,
		Remarks:     ab.Remarks,
	}
	if len(ab.Props) > 0 {
		ret.Props = ConvertPropsToOscal(ab.Props)
	}
	if len(ab.Links) > 0 {
		ret.Links = ConvertLinksToOscal(ab.Links)
	}
	if len(ab.Diagrams) > 0 {
		diagrams := make([]oscalTypes_1_1_3.Diagram, len(ab.Diagrams))
		for i, d := range ab.Diagrams {
			diagrams[i] = *d.MarshalOscal()
		}
		ret.Diagrams = &diagrams
	}
	return ret
}

type NetworkArchitecture struct {
	UUIDModel
	Description string                    `json:"description"`
	Remarks     string                    `json:"remarks"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Diagrams    []Diagram                 `json:"diagrams" gorm:"polymorphic:Parent;"`

	SystemCharacteristicsId uuid.UUID
}

func (na *NetworkArchitecture) UnmarshalOscal(ona oscalTypes_1_1_3.NetworkArchitecture) *NetworkArchitecture {
	props := ConvertOscalToProps(ona.Props)
	links := ConvertOscalToLinks(ona.Links)

	diagrams := ConvertList(ona.Diagrams, func(od oscalTypes_1_1_3.Diagram) Diagram {
		diagram := Diagram{}
		diagram.UnmarshalOscal(od)
		return diagram
	})

	*na = NetworkArchitecture{
		UUIDModel:   UUIDModel{},
		Description: ona.Description,
		Props:       props,
		Links:       links,
		Remarks:     ona.Remarks,
		Diagrams:    diagrams,
	}
	return na
}

func (na *NetworkArchitecture) MarshalOscal() *oscalTypes_1_1_3.NetworkArchitecture {
	ret := &oscalTypes_1_1_3.NetworkArchitecture{
		Description: na.Description,
		Remarks:     na.Remarks,
	}
	if len(na.Props) > 0 {
		ret.Props = ConvertPropsToOscal(na.Props)
	}
	if len(na.Links) > 0 {
		ret.Links = ConvertLinksToOscal(na.Links)
	}
	if len(na.Diagrams) > 0 {
		diagrams := make([]oscalTypes_1_1_3.Diagram, len(na.Diagrams))
		for i, d := range na.Diagrams {
			diagrams[i] = *d.MarshalOscal()
		}
		ret.Diagrams = &diagrams
	}
	return ret
}

type DataFlow struct {
	UUIDModel
	Description string                    `json:"description"`
	Remarks     string                    `json:"remarks"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Diagrams    []Diagram                 `json:"diagrams" gorm:"polymorphic:Parent;"`

	SystemCharacteristicsId uuid.UUID
}

func (df *DataFlow) UnmarshalOscal(odf oscalTypes_1_1_3.DataFlow) *DataFlow {
	props := ConvertOscalToProps(odf.Props)
	links := ConvertOscalToLinks(odf.Links)

	diagrams := ConvertList(odf.Diagrams, func(od oscalTypes_1_1_3.Diagram) Diagram {
		diagram := Diagram{}
		diagram.UnmarshalOscal(od)
		return diagram
	})

	*df = DataFlow{
		UUIDModel:   UUIDModel{},
		Description: odf.Description,
		Props:       props,
		Links:       links,
		Remarks:     odf.Remarks,
		Diagrams:    diagrams,
	}

	return df
}

func (df *DataFlow) MarshalOscal() *oscalTypes_1_1_3.DataFlow {
	ret := &oscalTypes_1_1_3.DataFlow{
		Description: df.Description,
		Remarks:     df.Remarks,
	}
	if len(df.Props) > 0 {
		ret.Props = ConvertPropsToOscal(df.Props)
	}
	if len(df.Links) > 0 {
		ret.Links = ConvertLinksToOscal(df.Links)
	}
	if len(df.Diagrams) > 0 {
		diagrams := make([]oscalTypes_1_1_3.Diagram, len(df.Diagrams))
		for i, d := range df.Diagrams {
			diagrams[i] = *d.MarshalOscal()
		}
		ret.Diagrams = &diagrams
	}
	return ret
}

type Diagram struct {
	UUIDModel
	Description string                    `json:"description"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Caption     string                    `json:"caption"`
	Remarks     string                    `json:"remarks"`

	ParentID   *string
	ParentType *string
}

func (d *Diagram) UnmarshalOscal(od oscalTypes_1_1_3.Diagram) *Diagram {
	id := uuid.MustParse(od.UUID)
	links := ConvertOscalToLinks(od.Links)
	props := ConvertOscalToProps(od.Props)

	*d = Diagram{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Description: od.Description,
		Props:       props,
		Links:       links,
		Caption:     od.Caption,
		Remarks:     od.Remarks,
	}

	return d
}

func (d *Diagram) MarshalOscal() *oscalTypes_1_1_3.Diagram {
	ret := &oscalTypes_1_1_3.Diagram{
		UUID:        d.UUIDModel.ID.String(),
		Description: d.Description,
		Caption:     d.Caption,
		Remarks:     d.Remarks,
	}
	if len(d.Props) > 0 {
		ret.Props = ConvertPropsToOscal(d.Props)
	}
	if len(d.Links) > 0 {
		ret.Links = ConvertLinksToOscal(d.Links)
	}
	return ret
}

type SystemImplementation struct {
	UUIDModel
	Props                   datatypes.JSONSlice[Prop] `json:"props,omitempty"`
	Links                   datatypes.JSONSlice[Link] `json:"links,omitempty"`
	Remarks                 string                    `json:"remarks"`
	Users                   []SystemUser              `json:"users"`
	LeveragedAuthorizations []LeveragedAuthorization  `json:"leveraged-authorizations"`
	Components              []SystemComponent         `json:"components" gorm:"many2many:system_implementation_components"`
	InventoryItems          []InventoryItem           `json:"inventory-items"`

	SystemSecurityPlanId uuid.UUID
}

func (si *SystemImplementation) UnmarshalOscal(osi oscalTypes_1_1_3.SystemImplementation) *SystemImplementation {
	// There may be a better way to do this but for now we generate in advance so we know it when creating FKs
	// If GORM has a way of doing this we should change to that.
	id := uuid.New()
	uuid := UUIDModel{
		ID: &id,
	}
	fmt.Printf("UUID %v\n", uuid)
	*si = SystemImplementation{
		UUIDModel: uuid,
		Props:     ConvertOscalToProps(osi.Props),
		Links:     ConvertOscalToLinks(osi.Links),
		Remarks:   osi.Remarks,
		Users: ConvertList(&osi.Users, func(osu oscalTypes_1_1_3.SystemUser) SystemUser {
			user := SystemUser{}
			user.UnmarshalOscal(osu)
			return user
		}),
		LeveragedAuthorizations: ConvertList(osi.LeveragedAuthorizations, func(ola oscalTypes_1_1_3.LeveragedAuthorization) LeveragedAuthorization {
			la := LeveragedAuthorization{}
			la.UnmarshalOscal(ola)
			return la
		}),
		Components: ConvertList(&osi.Components, func(osc oscalTypes_1_1_3.SystemComponent) SystemComponent {
			component := SystemComponent{}
			component.UnmarshalOscal(osc)
			component.ParentType = "system_implementation"
			component.ParentID = &id
			return component
		}),
		InventoryItems: ConvertList(osi.InventoryItems, func(oii oscalTypes_1_1_3.InventoryItem) InventoryItem {
			item := InventoryItem{}
			item.UnmarshalOscal(oii)
			return item
		}),
	}

	return si
}

func (si *SystemImplementation) MarshalOscal() *oscalTypes_1_1_3.SystemImplementation {
	ret := oscalTypes_1_1_3.SystemImplementation{
		Remarks: si.Remarks,
	}

	if len(si.Users) > 0 {
		ret.Users = ConvertList(&si.Users, func(osu SystemUser) oscalTypes_1_1_3.SystemUser {
			return *osu.MarshalOscal()
		})
	}

	if len(si.Links) > 0 {
		ret.Links = ConvertLinksToOscal(si.Links)
	}

	if len(si.Props) > 0 {
		ret.Props = ConvertPropsToOscal(si.Props)
	}

	if len(si.LeveragedAuthorizations) > 0 {
		auths := ConvertList(&si.LeveragedAuthorizations, func(osu LeveragedAuthorization) oscalTypes_1_1_3.LeveragedAuthorization {
			return *osu.MarshalOscal()
		})
		ret.LeveragedAuthorizations = &auths
	}

	if len(si.Components) > 0 {
		comps := ConvertList(&si.Components, func(in SystemComponent) oscalTypes_1_1_3.SystemComponent {
			return *in.MarshalOscal()
		})
		ret.Components = comps
	}

	if len(si.InventoryItems) > 0 {
		outs := ConvertList(&si.InventoryItems, func(in InventoryItem) oscalTypes_1_1_3.InventoryItem {
			return in.MarshalOscal()
		})
		ret.InventoryItems = &outs
	}

	return &ret
}

type SystemUser struct {
	UUIDModel
	Title                string                      `json:"title"`
	ShortName            string                      `json:"short-name"`
	Description          string                      `json:"description"`
	Remarks              string                      `json:"remarks"`
	Props                datatypes.JSONSlice[Prop]   `json:"props"`
	Links                datatypes.JSONSlice[Link]   `json:"links"`
	RoleIDs              datatypes.JSONSlice[string] `json:"role-ids"`
	AuthorizedPrivileges []AuthorizedPrivilege       `json:"authorized-privileges"`

	SystemImplementationId uuid.UUID
}

func (u *SystemUser) UnmarshalOscal(ou oscalTypes_1_1_3.SystemUser) *SystemUser {
	id := uuid.MustParse(ou.UUID)
	*u = SystemUser{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:       ou.Title,
		ShortName:   ou.ShortName,
		Description: ou.Description,
		Remarks:     ou.Remarks,
		Props:       ConvertOscalToProps(ou.Props),
		Links:       ConvertOscalToLinks(ou.Links),
		AuthorizedPrivileges: ConvertList(ou.AuthorizedPrivileges, func(oap oscalTypes_1_1_3.AuthorizedPrivilege) AuthorizedPrivilege {
			privilege := AuthorizedPrivilege{}
			privilege.UnmarshalOscal(oap)
			return privilege
		}),
	}

	if ou.RoleIds != nil {
		u.RoleIDs = datatypes.NewJSONSlice(*ou.RoleIds)
	}

	return u
}

func (u *SystemUser) MarshalOscal() *oscalTypes_1_1_3.SystemUser {
	ret := &oscalTypes_1_1_3.SystemUser{
		UUID:        u.UUIDModel.ID.String(),
		Title:       u.Title,
		ShortName:   u.ShortName,
		Description: u.Description,
		Remarks:     u.Remarks,
	}
	if len(u.Props) > 0 {
		ret.Props = ConvertPropsToOscal(u.Props)
	}
	if len(u.Links) > 0 {
		ret.Links = ConvertLinksToOscal(u.Links)
	}
	if len(u.RoleIDs) > 0 {
		rs := make([]string, len(u.RoleIDs))
		copy(rs, u.RoleIDs)
		ret.RoleIds = &rs
	}
	if len(u.AuthorizedPrivileges) > 0 {
		privs := make([]oscalTypes_1_1_3.AuthorizedPrivilege, len(u.AuthorizedPrivileges))
		for i, ap := range u.AuthorizedPrivileges {
			privs[i] = *ap.MarshalOscal()
		}
		ret.AuthorizedPrivileges = &privs
	}
	return ret
}

type AuthorizedPrivilege struct {
	UUIDModel
	Title              string                      `json:"title"`
	Description        string                      `json:"description"`
	FunctionsPerformed datatypes.JSONSlice[string] `json:"functions-performed"`

	SystemUserId uuid.UUID
}

func (ap *AuthorizedPrivilege) UnmarshalOscal(oap oscalTypes_1_1_3.AuthorizedPrivilege) *AuthorizedPrivilege {
	*ap = AuthorizedPrivilege{
		UUIDModel:          UUIDModel{},
		Title:              oap.Title,
		Description:        oap.Description,
		FunctionsPerformed: datatypes.NewJSONSlice(oap.FunctionsPerformed),
	}

	return ap
}

func (ap *AuthorizedPrivilege) MarshalOscal() *oscalTypes_1_1_3.AuthorizedPrivilege {
	ret := &oscalTypes_1_1_3.AuthorizedPrivilege{
		Title:              ap.Title,
		Description:        ap.Description,
		FunctionsPerformed: ap.FunctionsPerformed,
	}
	return ret
}

type LeveragedAuthorization struct {
	UUIDModel
	Title          string                    `json:"title"`
	PartyUUID      uuid.UUID                 `json:"party-uuid"`
	DateAuthorized time.Time                 `json:"date-authorized"`
	Remarks        string                    `json:"remarks"`
	Props          datatypes.JSONSlice[Prop] `json:"props"`
	Links          datatypes.JSONSlice[Link] `json:"links"`

	SystemImplementationId uuid.UUID
}

func (la *LeveragedAuthorization) UnmarshalOscal(ola oscalTypes_1_1_3.LeveragedAuthorization) *LeveragedAuthorization {
	id := uuid.MustParse(ola.UUID)
	partyId := uuid.MustParse(ola.PartyUuid)

	dateAuthorized, err := time.Parse(time.DateOnly, ola.DateAuthorized)
	if err != nil {
		panic("Date parse must parse: " + err.Error())
	}

	*la = LeveragedAuthorization{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:          ola.Title,
		PartyUUID:      partyId,
		DateAuthorized: dateAuthorized,
		Remarks:        ola.Remarks,
		Props:          ConvertOscalToProps(ola.Props),
		Links:          ConvertOscalToLinks(ola.Links),
	}

	return la
}

// MarshalOscal converts the LeveragedAuthorization back to an OSCAL LeveragedAuthorization
func (la *LeveragedAuthorization) MarshalOscal() *oscalTypes_1_1_3.LeveragedAuthorization {
	ret := &oscalTypes_1_1_3.LeveragedAuthorization{
		UUID:           la.UUIDModel.ID.String(),
		Title:          la.Title,
		PartyUuid:      la.PartyUUID.String(),
		DateAuthorized: la.DateAuthorized.Format(time.DateOnly),
		Remarks:        la.Remarks,
	}
	if len(la.Props) > 0 {
		ret.Props = ConvertPropsToOscal(la.Props)
	}
	if len(la.Links) > 0 {
		ret.Links = ConvertLinksToOscal(la.Links)
	}
	return ret
}

type SystemComponentStatus oscalTypes_1_1_3.SystemComponentStatus

func (s *SystemComponentStatus) UnmarshalOscal(os oscalTypes_1_1_3.SystemComponentStatus) *SystemComponentStatus {
	*s = SystemComponentStatus(os)
	return s
}

func (s *SystemComponentStatus) MarshalOscal() *oscalTypes_1_1_3.SystemComponentStatus {
	ret := oscalTypes_1_1_3.SystemComponentStatus(*s)
	return &ret
}

type SystemComponent struct {
	UUIDModel
	Type             string                                    `json:"type"`
	Title            string                                    `json:"title"`
	Description      string                                    `json:"description"`
	Purpose          string                                    `json:"purpose"`
	Status           datatypes.JSONType[SystemComponentStatus] `json:"status"`
	ResponsibleRoles []ResponsibleRole                         `json:"responsible-roles" gorm:"polymorphic:Parent;"`
	Protocols        datatypes.JSONSlice[Protocol]             `json:"protocols"`
	Remarks          string                                    `json:"remarks"`
	Props            datatypes.JSONSlice[Prop]                 `json:"props"`
	Links            datatypes.JSONSlice[Link]                 `json:"links"`

	ParentID   *uuid.UUID
	ParentType string

	Evidence []Evidence `gorm:"many2many:evidence_components"`
}

func (sc *SystemComponent) UnmarshalOscal(osc oscalTypes_1_1_3.SystemComponent) *SystemComponent {
	id := uuid.MustParse(osc.UUID)
	status := SystemComponentStatus{}
	status.UnmarshalOscal(osc.Status)

	*sc = SystemComponent{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Type:        osc.Type,
		Title:       osc.Title,
		Description: osc.Description,
		Purpose:     osc.Purpose,
		Status:      datatypes.NewJSONType(status),
		ResponsibleRoles: ConvertList(osc.ResponsibleRoles, func(orr oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(orr)
			return role
		}),
		Protocols: ConvertList(osc.Protocols, func(op oscalTypes_1_1_3.Protocol) Protocol {
			protocol := Protocol{}
			protocol.UnmarshalOscal(op)
			return protocol
		}),
		Remarks: osc.Remarks,
		Props:   ConvertOscalToProps(osc.Props),
		Links:   ConvertOscalToLinks(osc.Links),
	}

	return sc
}

// MarshalOscal converts the SystemComponent back to an OSCAL SystemComponent
func (sc *SystemComponent) MarshalOscal() *oscalTypes_1_1_3.SystemComponent {
	status := sc.Status.Data()
	ret := &oscalTypes_1_1_3.SystemComponent{
		UUID:        sc.UUIDModel.ID.String(),
		Type:        sc.Type,
		Title:       sc.Title,
		Description: sc.Description,
		Purpose:     sc.Purpose,
		Status:      *status.MarshalOscal(),
		Remarks:     sc.Remarks,
	}

	if len(sc.Props) > 0 {
		ret.Props = ConvertPropsToOscal(sc.Props)
	}
	if len(sc.Links) > 0 {
		ret.Links = ConvertLinksToOscal(sc.Links)
	}
	if len(sc.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(sc.ResponsibleRoles))
		for i, rr := range sc.ResponsibleRoles {
			roles[i] = *rr.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}
	if len(sc.Protocols) > 0 {
		protos := make([]oscalTypes_1_1_3.Protocol, len(sc.Protocols))
		for i, p := range sc.Protocols {
			protos[i] = *p.MarshalOscal()
		}
		ret.Protocols = &protos
	}
	return ret
}

type InventoryItem struct {
	UUIDModel
	Description           string                                `json:"description"`
	Props                 datatypes.JSONSlice[Prop]             `json:"props"`
	Links                 datatypes.JSONSlice[Link]             `json:"links"`
	ResponsibleParties    datatypes.JSONSlice[ResponsibleParty] `json:"responsible-parties"`
	Remarks               string                                `json:"remarks"`
	ImplementedComponents []ImplementedComponent                `json:"implemented-components"`

	SystemImplementationId uuid.UUID

	Evidence []Evidence `gorm:"many2many:evidence_inventory_items"`
}

func (ii *InventoryItem) UnmarshalOscal(oii oscalTypes_1_1_3.InventoryItem) *InventoryItem {
	id := uuid.MustParse(oii.UUID)

	*ii = InventoryItem{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Description: oii.Description,
		Props:       ConvertOscalToProps(oii.Props),
		Links:       ConvertOscalToLinks(oii.Links),
		ResponsibleParties: ConvertList(oii.ResponsibleParties, func(op oscalTypes_1_1_3.ResponsibleParty) ResponsibleParty {
			party := ResponsibleParty{}
			party.UnmarshalOscal(op)
			return party
		}),
		ImplementedComponents: ConvertList(oii.ImplementedComponents, func(oic oscalTypes_1_1_3.ImplementedComponent) ImplementedComponent {
			component := ImplementedComponent{}
			component.UnmarshalOscal(oic)
			return component
		}),
		Remarks: oii.Remarks,
	}

	return ii
}

func (ii *InventoryItem) MarshalOscal() oscalTypes_1_1_3.InventoryItem {
	ret := oscalTypes_1_1_3.InventoryItem{
		UUID:        ii.ID.String(),
		Remarks:     ii.Remarks,
		Description: ii.Description,
	}

	if len(ii.Props) > 0 {
		ret.Props = ConvertPropsToOscal(ii.Props)
	}

	if len(ii.Links) > 0 {
		ret.Links = ConvertLinksToOscal(ii.Links)
	}

	if len(ii.ResponsibleParties) > 0 {
		outs := make([]oscalTypes_1_1_3.ResponsibleParty, len(ii.ResponsibleParties))
		for i, rp := range ii.ResponsibleParties {
			outs[i] = *rp.MarshalOscal()
		}
		ret.ResponsibleParties = &outs
	}

	if len(ii.ImplementedComponents) > 0 {
		outs := make([]oscalTypes_1_1_3.ImplementedComponent, len(ii.ImplementedComponents))
		for i, out := range ii.ImplementedComponents {
			outs[i] = out.MarshalOscal()
		}
		ret.ImplementedComponents = &outs
	}

	return ret
}

type ImplementedComponent struct {
	UUIDModel
	ComponentID uuid.UUID `json:"component-uuid"`
	Component   DefinedComponent

	Props              datatypes.JSONSlice[Prop]             `json:"props"`
	Links              datatypes.JSONSlice[Link]             `json:"links"`
	ResponsibleParties datatypes.JSONSlice[ResponsibleParty] `json:"responsible-parties"`
	Remarks            string                                `json:"remarks"`

	InventoryItemId uuid.UUID
}

func (ic *ImplementedComponent) UnmarshalOscal(oic oscalTypes_1_1_3.ImplementedComponent) *ImplementedComponent {
	// Handle empty or invalid component UUID
	var componentId uuid.UUID
	if oic.ComponentUuid == "" {
		componentId = uuid.New() // Generate a new UUID for empty component UUID
	} else {
		var err error
		componentId, err = uuid.Parse(oic.ComponentUuid)
		if err != nil {
			componentId = uuid.New() // Generate a new UUID for invalid component UUID
		}
	}
	*ic = ImplementedComponent{
		UUIDModel:   UUIDModel{},
		ComponentID: componentId,
		Props:       ConvertOscalToProps(oic.Props),
		Links:       ConvertOscalToLinks(oic.Links),
		Remarks:     oic.Remarks,
		ResponsibleParties: ConvertList(oic.ResponsibleParties, func(op oscalTypes_1_1_3.ResponsibleParty) ResponsibleParty {
			party := ResponsibleParty{}
			party.UnmarshalOscal(op)
			return party
		}),
	}

	return ic
}

func (ic *ImplementedComponent) MarshalOscal() oscalTypes_1_1_3.ImplementedComponent {
	ret := oscalTypes_1_1_3.ImplementedComponent{
		ComponentUuid: ic.ComponentID.String(),
		Remarks:       ic.Remarks,
	}

	if len(ic.Props) > 0 {
		ret.Props = ConvertPropsToOscal(ic.Props)
	}

	if len(ic.Links) > 0 {
		ret.Links = ConvertLinksToOscal(ic.Links)
	}

	if len(ic.ResponsibleParties) > 0 {
		outs := make([]oscalTypes_1_1_3.ResponsibleParty, len(ic.ResponsibleParties))
		for i, rp := range ic.ResponsibleParties {
			outs[i] = *rp.MarshalOscal()
		}
		ret.ResponsibleParties = &outs
	}

	return ret
}

type ControlImplementation struct {
	UUIDModel
	Description             string                            `json:"description"`
	SetParameters           datatypes.JSONSlice[SetParameter] `json:"set-parameters"`
	ImplementedRequirements []ImplementedRequirement          `json:"implemented-requirements"`

	SystemSecurityPlanId uuid.UUID
}

func (ci *ControlImplementation) UnmarshalOscal(oci oscalTypes_1_1_3.ControlImplementation) *ControlImplementation {
	*ci = ControlImplementation{
		UUIDModel:   UUIDModel{},
		Description: oci.Description,
		SetParameters: ConvertList(oci.SetParameters, func(sp oscalTypes_1_1_3.SetParameter) SetParameter {
			param := SetParameter{}
			param.UnmarshalOscal(sp)
			return param
		}),
		ImplementedRequirements: ConvertList(&oci.ImplementedRequirements, func(oir oscalTypes_1_1_3.ImplementedRequirement) ImplementedRequirement {
			req := ImplementedRequirement{}
			req.UnmarshalOscal(oir)
			return req
		}),
	}

	return ci
}

func (ci *ControlImplementation) MarshalOscal() *oscalTypes_1_1_3.ControlImplementation {
	ret := &oscalTypes_1_1_3.ControlImplementation{
		Description: ci.Description,
	}
	if len(ci.SetParameters) > 0 {
		params := make([]oscalTypes_1_1_3.SetParameter, len(ci.SetParameters))
		for i, sp := range ci.SetParameters {
			params[i] = *sp.MarshalOscal()
		}
		ret.SetParameters = &params
	}
	if len(ci.ImplementedRequirements) > 0 {
		reqs := make([]oscalTypes_1_1_3.ImplementedRequirement, len(ci.ImplementedRequirements))
		for i, ir := range ci.ImplementedRequirements {
			reqs[i] = *ir.MarshalOscal()
		}
		ret.ImplementedRequirements = reqs
	}
	return ret
}

type ImplementedRequirement struct {
	UUIDModel
	ControlImplementationId uuid.UUID

	ControlId        string                            `json:"control-id"`
	Props            datatypes.JSONSlice[Prop]         `json:"props"`
	Links            datatypes.JSONSlice[Link]         `json:"links"`
	SetParameters    datatypes.JSONSlice[SetParameter] `json:"set-parameters"`
	ResponsibleRoles []ResponsibleRole                 `json:"responsible-roles" gorm:"polymorphic:Parent;"`
	Remarks          string                            `json:"remarks"`
	ByComponents     []ByComponent                     `json:"by-components" gorm:"Polymorphic:Parent"`
	Statements       []Statement                       `json:"statements"`
}

func (ir *ImplementedRequirement) UnmarshalOscal(oir oscalTypes_1_1_3.ImplementedRequirement) *ImplementedRequirement {
	id := uuid.MustParse(oir.UUID)
	*ir = ImplementedRequirement{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ControlId: oir.ControlId,
		Props:     ConvertOscalToProps(oir.Props),
		Links:     ConvertOscalToLinks(oir.Links),
		SetParameters: ConvertList(oir.SetParameters, func(op oscalTypes_1_1_3.SetParameter) SetParameter {
			param := SetParameter{}
			param.UnmarshalOscal(op)
			return param
		}),
		ResponsibleRoles: ConvertList(oir.ResponsibleRoles, func(op oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(op)
			return role
		}),
		ByComponents: ConvertList(oir.ByComponents, func(op oscalTypes_1_1_3.ByComponent) ByComponent {
			component := ByComponent{}
			component.UnmarshalOscal(op)
			return component
		}),
		Statements: ConvertList(oir.Statements, func(op oscalTypes_1_1_3.Statement) Statement {
			statement := Statement{}
			statement.UnmarshalOscal(op)
			return statement
		}),
		Remarks: oir.Remarks,
	}

	return ir
}

func (ir *ImplementedRequirement) MarshalOscal() *oscalTypes_1_1_3.ImplementedRequirement {
	ret := &oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      ir.UUIDModel.ID.String(),
		ControlId: ir.ControlId,
		Remarks:   ir.Remarks,
	}
	if len(ir.Props) > 0 {
		ret.Props = ConvertPropsToOscal(ir.Props)
	}
	if len(ir.Links) > 0 {
		ret.Links = ConvertLinksToOscal(ir.Links)
	}
	if len(ir.SetParameters) > 0 {
		params := make([]oscalTypes_1_1_3.SetParameter, len(ir.SetParameters))
		for i, sp := range ir.SetParameters {
			params[i] = *sp.MarshalOscal()
		}
		ret.SetParameters = &params
	}
	if len(ir.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(ir.ResponsibleRoles))
		for i, rr := range ir.ResponsibleRoles {
			roles[i] = *rr.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}
	if len(ir.ByComponents) > 0 {
		bcs := make([]oscalTypes_1_1_3.ByComponent, len(ir.ByComponents))
		for i, bc := range ir.ByComponents {
			bcs[i] = *bc.MarshalOscal()
		}
		ret.ByComponents = &bcs
	}
	if len(ir.Statements) > 0 {
		stmts := make([]oscalTypes_1_1_3.Statement, len(ir.Statements))
		for i, st := range ir.Statements {
			stmts[i] = *st.MarshalOscal()
		}
		ret.Statements = &stmts
	}
	return ret
}

type ByComponent struct {
	UUIDModel

	// As ByComponent can be found in Implemented Requirements & Statements, using GORM polymorphism to tell us where to attach
	ParentID   *uuid.UUID
	ParentType *string

	ComponentUUID        uuid.UUID                                      `json:"component-uuid"`
	Description          string                                         `json:"description"`
	Props                datatypes.JSONSlice[Prop]                      `json:"props"`
	Links                datatypes.JSONSlice[Link]                      `json:"links"`
	SetParameters        datatypes.JSONSlice[SetParameter]              `json:"set-parameters"`
	ResponsibleRoles     []ResponsibleRole                              `json:"responsible-parties" gorm:"polymorphic:Parent;"`
	Remarks              string                                         `json:"remarks"`
	ImplementationStatus datatypes.JSONType[ImplementationStatus]       `json:"implementation-status"`
	Export               *Export                                        `json:"export,omitempty"`
	Inherited            []InheritedControlImplementation               `json:"inherited-control-implementations,omitempty"`
	Satisfied            []SatisfiedControlImplementationResponsibility `json:"satisfied"`
}

func (bc *ByComponent) UnmarshalOscal(obc oscalTypes_1_1_3.ByComponent) *ByComponent {
	id := uuid.MustParse(obc.UUID)
	componentId := uuid.MustParse(obc.ComponentUuid)

	*bc = ByComponent{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ComponentUUID: componentId,
		Description:   obc.Description,
		Remarks:       obc.Remarks,
		Props:         ConvertOscalToProps(obc.Props),
		Links:         ConvertOscalToLinks(obc.Links),
		SetParameters: ConvertList(obc.SetParameters, func(op oscalTypes_1_1_3.SetParameter) SetParameter {
			param := SetParameter{}
			param.UnmarshalOscal(op)
			return param
		}),
		ResponsibleRoles: ConvertList(obc.ResponsibleRoles, func(orr oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(orr)
			return role
		}),
		Inherited: ConvertList(obc.Inherited, func(in oscalTypes_1_1_3.InheritedControlImplementation) InheritedControlImplementation {
			ret := InheritedControlImplementation{}
			ret.UnmarshalOscal(in)
			return ret
		}),
		Satisfied: ConvertList(obc.Satisfied, func(in oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility) SatisfiedControlImplementationResponsibility {
			ret := SatisfiedControlImplementationResponsibility{}
			ret.UnmarshalOscal(in)
			return ret
		}),
	}

	if obc.Export != nil {
		export := Export{}
		bc.Export = export.UnmarshalOscal(*obc.Export)
	}

	return bc
}

func (bc *ByComponent) MarshalOscal() *oscalTypes_1_1_3.ByComponent {
	ret := &oscalTypes_1_1_3.ByComponent{
		UUID:          bc.UUIDModel.ID.String(),
		ComponentUuid: bc.ComponentUUID.String(),
		Description:   bc.Description,
		Remarks:       bc.Remarks,
	}
	if len(bc.Props) > 0 {
		ret.Props = ConvertPropsToOscal(bc.Props)
	}
	if len(bc.Links) > 0 {
		ret.Links = ConvertLinksToOscal(bc.Links)
	}
	if len(bc.SetParameters) > 0 {
		params := make([]oscalTypes_1_1_3.SetParameter, len(bc.SetParameters))
		for i, sp := range bc.SetParameters {
			params[i] = *sp.MarshalOscal()
		}
		ret.SetParameters = &params
	}
	if len(bc.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(bc.ResponsibleRoles))
		for i, rr := range bc.ResponsibleRoles {
			roles[i] = *rr.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}
	if len(bc.Inherited) > 0 {
		inherited := make([]oscalTypes_1_1_3.InheritedControlImplementation, len(bc.Inherited))
		for i, rr := range bc.Inherited {
			inherited[i] = *rr.MarshalOscal()
		}
		ret.Inherited = &inherited
	}
	if bc.Export != nil {
		ret.Export = bc.Export.MarshalOscal()
	}
	if len(bc.Satisfied) > 0 {
		satisfied := make([]oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility, len(bc.Inherited))
		for i, rr := range bc.Satisfied {
			satisfied[i] = *rr.MarshalOscal()
		}
		ret.Satisfied = &satisfied
	}
	return ret
}

type ImplementationStatus oscalTypes_1_1_3.ImplementationStatus

func (is *ImplementationStatus) UnmarshalOscal(ois oscalTypes_1_1_3.ImplementationStatus) *ImplementationStatus {
	*is = ImplementationStatus(ois)
	return is
}

func (is *ImplementationStatus) MarshalOscal() *oscalTypes_1_1_3.ImplementationStatus {
	ret := oscalTypes_1_1_3.ImplementationStatus(*is)
	return &ret
}

type Export struct {
	UUIDModel
	Description      string                                `json:"description"`
	Props            datatypes.JSONSlice[Prop]             `json:"props"`
	Links            datatypes.JSONSlice[Link]             `json:"links"`
	Remarks          string                                `json:"remarks"`
	Provided         []ProvidedControlImplementation       `json:"provided"`
	Responsibilities []ControlImplementationResponsibility `json:"responsibilities"`

	ByComponentId uuid.UUID
}

func (e *Export) UnmarshalOscal(oe oscalTypes_1_1_3.Export) *Export {
	*e = Export{
		Description: oe.Description,
		Props:       ConvertOscalToProps(oe.Props),
		Links:       ConvertOscalToLinks(oe.Links),
		Remarks:     oe.Remarks,
		Provided: ConvertList(oe.Provided, func(opci oscalTypes_1_1_3.ProvidedControlImplementation) ProvidedControlImplementation {
			provided := ProvidedControlImplementation{}
			provided.UnmarshalOscal(opci)
			return provided
		}),
		Responsibilities: ConvertList(oe.Responsibilities, func(cir oscalTypes_1_1_3.ControlImplementationResponsibility) ControlImplementationResponsibility {
			responsibility := ControlImplementationResponsibility{}
			responsibility.UnmarshalOscal(cir)
			return responsibility
		}),
	}

	return e
}

func (e *Export) MarshalOscal() *oscalTypes_1_1_3.Export {
	ret := &oscalTypes_1_1_3.Export{
		Description: e.Description,
		Remarks:     e.Remarks,
	}
	if len(e.Props) > 0 {
		ret.Props = ConvertPropsToOscal(e.Props)
	}
	if len(e.Links) > 0 {
		ret.Links = ConvertLinksToOscal(e.Links)
	}
	if len(e.Provided) > 0 {
		prov := make([]oscalTypes_1_1_3.ProvidedControlImplementation, len(e.Provided))
		for i, p := range e.Provided {
			prov[i] = *p.MarshalOscal()
		}
		ret.Provided = &prov
	}
	if len(e.Responsibilities) > 0 {
		resp := make([]oscalTypes_1_1_3.ControlImplementationResponsibility, len(e.Responsibilities))
		for i, r := range e.Responsibilities {
			resp[i] = *r.MarshalOscal()
		}
		ret.Responsibilities = &resp
	}
	return ret
}

type ProvidedControlImplementation struct {
	UUIDModel
	Description      string                    `json:"description"`
	Links            datatypes.JSONSlice[Link] `json:"links"`
	Props            datatypes.JSONSlice[Prop] `json:"props"`
	Remarks          string                    `json:"remarks"`
	ResponsibleRoles []ResponsibleRole         `json:"responsible-roles" gorm:"polymorphic:Parent;"`

	ExportId uuid.UUID
}

func (pci *ProvidedControlImplementation) UnmarshalOscal(opci oscalTypes_1_1_3.ProvidedControlImplementation) *ProvidedControlImplementation {
	id := uuid.MustParse(opci.UUID)
	*pci = ProvidedControlImplementation{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Description: opci.Description,
		Props:       ConvertOscalToProps(opci.Props),
		Links:       ConvertOscalToLinks(opci.Links),
		Remarks:     opci.Remarks,
		ResponsibleRoles: ConvertList(opci.ResponsibleRoles, func(or oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(or)
			return role
		}),
	}
	return pci
}

func (pci *ProvidedControlImplementation) MarshalOscal() *oscalTypes_1_1_3.ProvidedControlImplementation {
	ret := oscalTypes_1_1_3.ProvidedControlImplementation{
		UUID:        pci.UUIDModel.ID.String(),
		Description: pci.Description,
	}

	if pci.Remarks != "" {
		ret.Remarks = pci.Remarks
	}

	if len(pci.Props) > 0 {
		ret.Props = ConvertPropsToOscal(pci.Props)
	}

	if len(pci.Links) > 0 {
		ret.Links = ConvertLinksToOscal(pci.Links)
	}

	if len(pci.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(pci.ResponsibleRoles))
		for i, role := range pci.ResponsibleRoles {
			roles[i] = *role.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}

	return &ret
}

type ControlImplementationResponsibility struct {
	UUIDModel
	Description      string                    `json:"description"` // required
	Links            datatypes.JSONSlice[Link] `json:"links"`
	Props            datatypes.JSONSlice[Prop] `json:"props"`
	ProvidedUuid     uuid.UUID                 `json:"provided-uuid"`
	Remarks          string                    `json:"remarks"`
	ResponsibleRoles []ResponsibleRole         `json:"responsible-roles" gorm:"polymorphic:Parent"`

	ExportId uuid.UUID
}

func (cir *ControlImplementationResponsibility) UnmarshalOscal(ocir oscalTypes_1_1_3.ControlImplementationResponsibility) *ControlImplementationResponsibility {
	id := uuid.MustParse(ocir.UUID)

	providedUuid, err := uuid.Parse(ocir.ProvidedUuid)
	if err != nil {
		// Force nil if parse fails
		providedUuid = uuid.Nil
	}

	*cir = ControlImplementationResponsibility{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ProvidedUuid: providedUuid,
		Description:  ocir.Description,
		Remarks:      ocir.Remarks,
		Props:        ConvertOscalToProps(ocir.Props),
		Links:        ConvertOscalToLinks(ocir.Links),
		ResponsibleRoles: ConvertList(ocir.ResponsibleRoles, func(or oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(or)
			return role
		}),
	}

	return cir
}

func (cir *ControlImplementationResponsibility) MarshalOscal() *oscalTypes_1_1_3.ControlImplementationResponsibility {
	ret := oscalTypes_1_1_3.ControlImplementationResponsibility{
		UUID:        cir.UUIDModel.ID.String(),
		Description: cir.Description,
	}

	if cir.ProvidedUuid != uuid.Nil {
		ret.ProvidedUuid = cir.ProvidedUuid.String()
	}

	if cir.Remarks != "" {
		ret.Remarks = cir.Remarks
	}

	if len(cir.Props) > 0 {
		ret.Props = ConvertPropsToOscal(cir.Props)
	}

	if len(cir.Links) > 0 {
		ret.Links = ConvertLinksToOscal(cir.Links)
	}

	if len(cir.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(cir.ResponsibleRoles))
		for i, role := range cir.ResponsibleRoles {
			roles[i] = *role.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}

	return &ret
}

type InheritedControlImplementation struct {
	UUIDModel                                  //required
	ProvidedUuid     uuid.UUID                 `json:"provided-uuid"`
	Description      string                    `json:"description"` //required
	Links            datatypes.JSONSlice[Link] `json:"links"`
	Props            datatypes.JSONSlice[Prop] `json:"props"`
	ResponsibleRoles []ResponsibleRole         `json:"responsible-roles" gorm:"polymorphic:Parent"`

	ByComponentId uuid.UUID
}

func (i *InheritedControlImplementation) UnmarshalOscal(oi oscalTypes_1_1_3.InheritedControlImplementation) *InheritedControlImplementation {
	id := uuid.MustParse(oi.UUID)
	providedUuid, err := uuid.Parse(oi.ProvidedUuid)
	if err != nil {
		providedUuid = uuid.Nil
	}
	*i = InheritedControlImplementation{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ProvidedUuid: providedUuid,
		Description:  oi.Description,
		Links:        ConvertOscalToLinks(oi.Links),
		Props:        ConvertOscalToProps(oi.Props),
		ResponsibleRoles: ConvertList(oi.ResponsibleRoles, func(or oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(or)
			return role
		}),
	}

	return i
}

func (i *InheritedControlImplementation) MarshalOscal() *oscalTypes_1_1_3.InheritedControlImplementation {
	ret := oscalTypes_1_1_3.InheritedControlImplementation{
		UUID:        i.UUIDModel.ID.String(),
		Description: i.Description,
	}

	if i.ProvidedUuid != uuid.Nil {
		ret.ProvidedUuid = i.ProvidedUuid.String()
	}

	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}

	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}

	if len(i.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(i.ResponsibleRoles))
		for i, role := range i.ResponsibleRoles {
			roles[i] = *role.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}

	return &ret
}

type SatisfiedControlImplementationResponsibility struct {
	UUIDModel
	ResponsibilityUuid uuid.UUID                 `json:"responsibility-uuid"`
	Description        string                    `json:"description"`
	Props              datatypes.JSONSlice[Prop] `json:"props"`
	Links              datatypes.JSONSlice[Link] `json:"links"`
	ResponsibleRoles   []ResponsibleRole         `json:"responsible-roles" gorm:"polymorphic:Parent"`
	Remarks            string                    `json:"remarks"`

	ByComponentId uuid.UUID `json:"by-component-id"`
}

func (s *SatisfiedControlImplementationResponsibility) UnmarshalOscal(os oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility) *SatisfiedControlImplementationResponsibility {
	id := uuid.MustParse(os.UUID)
	responsiblityUuid, err := uuid.Parse(os.ResponsibilityUuid)
	if err != nil {
		responsiblityUuid = uuid.Nil
	}

	*s = SatisfiedControlImplementationResponsibility{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ResponsibilityUuid: responsiblityUuid,
		Description:        os.Description,
		Links:              ConvertOscalToLinks(os.Links),
		Props:              ConvertOscalToProps(os.Props),
		Remarks:            os.Remarks,
		ResponsibleRoles: ConvertList(os.ResponsibleRoles, func(or oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(or)
			return role
		}),
	}
	return s
}

func (s *SatisfiedControlImplementationResponsibility) MarshalOscal() *oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility {
	ret := oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility{
		UUID:               s.UUIDModel.ID.String(),
		ResponsibilityUuid: s.ResponsibilityUuid.String(),
		Description:        "",
		Remarks:            "",
	}

	if s.ResponsibilityUuid != uuid.Nil {
		ret.ResponsibilityUuid = s.ResponsibilityUuid.String()
	}

	if len(s.Props) > 0 {
		ret.Props = ConvertPropsToOscal(s.Props)
	}

	if len(s.Links) > 0 {
		ret.Links = ConvertLinksToOscal(s.Links)
	}

	if s.Description != "" {
		ret.Description = s.Description
	}

	if s.Remarks != "" {
		ret.Remarks = s.Remarks
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

type Statement struct {
	UUIDModel
	StatementId      string                    `json:"statement-id"`
	Props            datatypes.JSONSlice[Prop] `json:"props"`
	Links            datatypes.JSONSlice[Link] `json:"links"`
	ResponsibleRoles []ResponsibleRole         `json:"responsible-roles" gorm:"polymorphic:Parent"`
	ByComponents     []ByComponent             `json:"by-components,omitempty" gorm:"polymorphic:Parent"`
	Remarks          string                    `json:"remarks"`

	ImplementedRequirementId uuid.UUID
}

func (s *Statement) UnmarshalOscal(os oscalTypes_1_1_3.Statement) *Statement {
	id := uuid.MustParse(os.UUID)

	*s = Statement{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		StatementId: os.StatementId,
		Props:       ConvertOscalToProps(os.Props),
		Links:       ConvertOscalToLinks(os.Links),
		ResponsibleRoles: ConvertList(os.ResponsibleRoles, func(op oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
			role := ResponsibleRole{}
			role.UnmarshalOscal(op)
			return role
		}),
		ByComponents: ConvertList(os.ByComponents, func(op oscalTypes_1_1_3.ByComponent) ByComponent {
			component := ByComponent{}
			component.UnmarshalOscal(op)
			return component
		}),
		Remarks: os.Remarks,
	}

	return s
}

func (s *Statement) MarshalOscal() *oscalTypes_1_1_3.Statement {
	ret := &oscalTypes_1_1_3.Statement{
		UUID:        s.UUIDModel.ID.String(),
		StatementId: s.StatementId,
		Remarks:     s.Remarks,
	}
	if len(s.Props) > 0 {
		ret.Props = ConvertPropsToOscal(s.Props)
	}
	if len(s.Links) > 0 {
		ret.Links = ConvertLinksToOscal(s.Links)
	}
	if len(s.ResponsibleRoles) > 0 {
		roles := make([]oscalTypes_1_1_3.ResponsibleRole, len(s.ResponsibleRoles))
		for i, rr := range s.ResponsibleRoles {
			roles[i] = *rr.MarshalOscal()
		}
		ret.ResponsibleRoles = &roles
	}
	if len(s.ByComponents) > 0 {
		comps := ConvertList(&s.ByComponents, func(in ByComponent) oscalTypes_1_1_3.ByComponent {
			return *in.MarshalOscal()
		})
		ret.ByComponents = &comps
	}
	return ret
}
