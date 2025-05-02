package relational

import (
	"database/sql"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"time"
)

type SystemSecurityPlan struct {
	UUIDModel
	Metadata   Metadata   `json:"metadata" gorm:"polymorphic:Parent;"`
	BackMatter BackMatter `json:"back-matter" gorm:"polymorphic:Parent;"`

	ImportProfile         datatypes.JSONType[ImportProfile] `json:"import-profile"`
	SystemCharacteristics SystemCharacteristics             `json:"system-characteristics"`
	SystemImplementation  SystemImplementation              `json:"system-implementation"`
	ControlImplementation ControlImplementation             `json:"control-implementation"`
}

func (s *SystemSecurityPlan) UnmarshalOscal(os oscalTypes_1_1_3.SystemSecurityPlan) *SystemSecurityPlan {
	id := uuid.MustParse(os.UUID)
	metadata := Metadata{}
	metadata.UnmarshalOscal(os.Metadata)

	backMatter := BackMatter{}
	backMatter.UnmarshalOscal(*os.BackMatter)

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
		BackMatter:            backMatter,
		ImportProfile:         datatypes.NewJSONType[ImportProfile](importProfile),
		SystemCharacteristics: systemCharacteristics,
		SystemImplementation:  systemImplementation,
		ControlImplementation: controlImplementation,
	}

	return s
}

type ImportProfile oscalTypes_1_1_3.ImportProfile

func (ip *ImportProfile) UnmarshalOscal(oip oscalTypes_1_1_3.ImportProfile) *ImportProfile {
	*ip = ImportProfile(oip)
	return ip
}

type SystemCharacteristics struct {
	UUIDModel
	SystemName               string       `json:"system-name"`
	SystemNameShort          string       `json:"system-name-short"`
	Description              string       `json:"description"`
	DateAuthorized           sql.NullTime `json:"date-authorized"`
	SecuritySensitivityLevel string       `json:"security-sensitivity-level"`
	Remarks                  string       `json:"remarks"`

	SystemIds            datatypes.JSONSlice[SystemId] `json:"system-ids"`
	SystemInformation    SystemInformation             `json:"system-information"`
	Status               datatypes.JSONType[Status]    `json:"status"`
	AuthorizationBoundry AuthorizationBoundary         `json:"authorization-boundary"`
	NetworkArchitecture  NetworkArchitecture           `json:"network-architecture"`
	DataFlow             DataFlow                      `json:"data-flow"`

	Links              datatypes.JSONSlice[Link]             `json:"links"`
	Props              datatypes.JSONSlice[Prop]             `json:"props"`
	ResponsibleParties datatypes.JSONSlice[ResponsibleParty] `json:"responsible-role"`

	SystemSecurityPlanId uuid.UUID
}

func (sc *SystemCharacteristics) UnmarshalOscal(osc oscalTypes_1_1_3.SystemCharacteristics) *SystemCharacteristics {
	props := ConvertOscalToProps(osc.Props)
	links := ConvertOscalToLinks(osc.Links)

	dateAuthorized := sql.NullTime{}
	if len(osc.DateAuthorized) > 0 {
		// Todo: Assume that a timezone is attached as per the spec - https://pages.nist.gov/metaschema/specification/datatypes/#date
		parsed, err := time.Parse(time.DateOnly, osc.DateAuthorized)
		if err != nil {
			panic(err)
		}
		dateAuthorized = sql.NullTime{
			Time:  parsed,
			Valid: true,
		}

	}

	systemIds := ConvertList(&osc.SystemIds, func(osi oscalTypes_1_1_3.SystemId) SystemId {
		sid := SystemId(osi)
		return sid
	})

	systemInformation := SystemInformation{}
	systemInformation.UnmarshalOscal(osc.SystemInformation)

	status := Status{}
	status.UnmarshalOscal(osc.Status)

	authBoundary := AuthorizationBoundary{}
	authBoundary.UnmarshalOscal(osc.AuthorizationBoundary)

	var networkArchitecture NetworkArchitecture
	if osc.NetworkArchitecture != nil {
		networkArchitecture = NetworkArchitecture{}
		networkArchitecture.UnmarshalOscal(*osc.NetworkArchitecture)
	}

	var dataflow DataFlow
	if osc.DataFlow != nil {
		dataflow = DataFlow{}
		dataflow.UnmarshalOscal(*osc.DataFlow)
	}

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
		DateAuthorized:           dateAuthorized,
		SecuritySensitivityLevel: osc.SecuritySensitivityLevel,
		Remarks:                  osc.Remarks,
		Links:                    links,
		Props:                    props,
		SystemIds:                systemIds,
		SystemInformation:        systemInformation,
		Status:                   datatypes.NewJSONType[Status](status),
		AuthorizationBoundry:     authBoundary,
		NetworkArchitecture:      networkArchitecture,
		DataFlow:                 dataflow,
		ResponsibleParties:       datatypes.NewJSONSlice[ResponsibleParty](responsibleParties),
	}

	return sc
}

type SystemId oscalTypes_1_1_3.SystemId

func (si *SystemId) UnmarshalOscal(osi oscalTypes_1_1_3.SystemId) *SystemId {
	*si = SystemId(osi)
	return si
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

type InformationType struct {
	UUIDModel
	Title       string `json:"title"`
	Description string `json:"description"`

	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`

	ConfidentialityImpact datatypes.JSONType[Impact] `json:"confidentiality-impact"`
	IntegrityImpact       datatypes.JSONType[Impact] `json:"integrity-impact"`
	AvailabilityImpact    datatypes.JSONType[Impact] `json:"availability-impact"`

	Categorizations datatypes.JSONSlice[InformationTypeCategorization] `json:"categorizations"`

	SystemInformationId uuid.UUID
}

func (it *InformationType) UnmarshalOscal(oit oscalTypes_1_1_3.InformationType) *InformationType {
	id := uuid.MustParse(oit.UUID)

	props := ConvertOscalToProps(oit.Props)
	links := ConvertOscalToLinks(oit.Links)

	confImpact := Impact{}
	confImpact.UnmarshalOscal(*oit.ConfidentialityImpact)

	integrityImpact := Impact{}
	integrityImpact.UnmarshalOscal(*oit.IntegrityImpact)

	availabilityImpact := Impact{}
	availabilityImpact.UnmarshalOscal(*oit.AvailabilityImpact)

	categorizations := ConvertList(oit.Categorizations, func(oitc oscalTypes_1_1_3.InformationTypeCategorization) InformationTypeCategorization {
		category := InformationTypeCategorization{}
		category.UnmarshalOscal(oitc)
		return category
	})

	*it = InformationType{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:                 oit.Title,
		Description:           oit.Description,
		Props:                 props,
		Links:                 links,
		ConfidentialityImpact: datatypes.NewJSONType[Impact](confImpact),
		IntegrityImpact:       datatypes.NewJSONType[Impact](integrityImpact),
		AvailabilityImpact:    datatypes.NewJSONType[Impact](availabilityImpact),
		Categorizations:       categorizations,
	}

	return it
}

type Impact oscalTypes_1_1_3.Impact

func (i *Impact) UnmarshalOscal(osi oscalTypes_1_1_3.Impact) *Impact {
	*i = Impact(osi)
	return i
}

type InformationTypeCategorization oscalTypes_1_1_3.InformationTypeCategorization

func (itc *InformationTypeCategorization) UnmarshalOscal(oitc oscalTypes_1_1_3.InformationTypeCategorization) *InformationTypeCategorization {
	*itc = InformationTypeCategorization(oitc)
	return itc
}

type SecurityImpactLevel oscalTypes_1_1_3.SecurityImpactLevel

type Status oscalTypes_1_1_3.Status

func (s *Status) UnmarshalOscal(osi oscalTypes_1_1_3.Status) *Status {
	*s = Status(osi)
	return s
}

type AuthorizationBoundary struct {
	UUIDModel
	Description string                    `json:"description"`
	Remarks     string                    `json:"remarks"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Diagrams    []Diagram                 `json:"diagrams" gorm:"many2many:authorization_boundary_diagrams;"`

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

type NetworkArchitecture struct {
	UUIDModel
	Description string                    `json:"description"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Remarks     string                    `json:"remarks"`
	Diagrams    []Diagram                 `json:"diagrams" gorm:"many2many:network_architecture_diagrams;"`

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

type DataFlow struct {
	UUIDModel
	Description string                    `json:"description"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Remarks     string                    `json:"remarks"`
	Diagrams    []Diagram                 `json:"diagrams" gorm:"many2many:data_flow_diagrams;"`

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

type Diagram struct {
	UUIDModel
	Description string                    `json:"description"`
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`
	Caption     string                    `json:"caption"`
	Remarks     string                    `json:"remarks"`
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

type SystemImplementation struct {
	UUIDModel
	Props                   datatypes.JSONSlice[Prop] `json:"props"`
	Links                   datatypes.JSONSlice[Link] `json:"links"`
	Remarks                 string                    `json:"remarks"`
	Users                   []SystemUser              `json:"users"`
	LeveragedAuthorizations []LeveragedAuthorization  `json:"leveraged-authorizations"`
	Components              []SystemComponent         `json:"components"`
	InventoryItems          []InventoryItem           `json:"inventory-items"`

	SystemSecurityPlanId uuid.UUID
}

func (si *SystemImplementation) UnmarshalOscal(osi oscalTypes_1_1_3.SystemImplementation) *SystemImplementation {
	*si = SystemImplementation{
		UUIDModel: UUIDModel{},
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

type SystemUser struct {
	UUIDModel
	Title                string                      `json:"title"`
	ShortName            string                      `json:"short-name"`
	Description          string                      `json:"description"`
	Props                datatypes.JSONSlice[Prop]   `json:"props"`
	Links                datatypes.JSONSlice[Link]   `json:"links"`
	RoleIDs              datatypes.JSONSlice[string] `json:"role_ids"`
	AuthorizedPrivileges []AuthorizedPrivilege       `json:"authorized-privileges"`

	SystemImplementationId uuid.UUID

	//oscalTypes_1_1_3.SystemUser
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
		Props:       ConvertOscalToProps(ou.Props),
		Links:       ConvertOscalToLinks(ou.Links),
		RoleIDs:     datatypes.NewJSONSlice[string](u.RoleIDs),
		AuthorizedPrivileges: ConvertList(ou.AuthorizedPrivileges, func(oap oscalTypes_1_1_3.AuthorizedPrivilege) AuthorizedPrivilege {
			privilege := AuthorizedPrivilege{}
			privilege.UnmarshalOscal(oap)
			return privilege
		}),
	}
	return u
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
		FunctionsPerformed: datatypes.NewJSONSlice[string](oap.FunctionsPerformed),
	}

	return ap
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

type SystemComponentStatus oscalTypes_1_1_3.SystemComponentStatus

func (s *SystemComponentStatus) UnmarshalOscal(os oscalTypes_1_1_3.SystemComponentStatus) *SystemComponentStatus {
	*s = SystemComponentStatus(os)
	return s
}

type SystemComponent struct {
	UUIDModel
	Type             string                                    `json:"type"`
	Title            string                                    `json:"title"`
	Description      string                                    `json:"description"`
	Purpose          string                                    `json:"purpose"`
	Status           datatypes.JSONType[SystemComponentStatus] `json:"status"`
	ResponsableRoles datatypes.JSONSlice[ResponsibleRole]      `json:"responsable-roles"`
	Protocols        datatypes.JSONSlice[Protocol]             `json:"protocols"`
	Remarks          string                                    `json:"remarks"`
	Props            datatypes.JSONSlice[Prop]                 `json:"props"`
	Links            datatypes.JSONSlice[Link]                 `json:"links"`

	SystemImplementationId uuid.UUID
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
		Status:      datatypes.NewJSONType[SystemComponentStatus](status),
		ResponsableRoles: ConvertList(osc.ResponsibleRoles, func(orr oscalTypes_1_1_3.ResponsibleRole) ResponsibleRole {
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

type InventoryItem struct {
	UUIDModel
	Description           string                                `json:"description"`
	Props                 datatypes.JSONSlice[Prop]             `json:"props"`
	Links                 datatypes.JSONSlice[Link]             `json:"links"`
	ResponsibleParties    datatypes.JSONSlice[ResponsibleParty] `json:"responsible-parties"`
	Remarks               string                                `json:"remarks"`
	ImplementedComponents []ImplementedComponent                `json:"implemented-components"`

	SystemImplementationId uuid.UUID
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

type ImplementedComponent struct {
	UUIDModel
	ComponentUUID      uuid.UUID                             `json:"component-uuid"`
	Props              datatypes.JSONSlice[Prop]             `json:"props"`
	Links              datatypes.JSONSlice[Link]             `json:"links"`
	ResponsibleParties datatypes.JSONSlice[ResponsibleParty] `json:"responsible-parties"`
	Remarks            string                                `json:"remarks"`

	InventoryItemId uuid.UUID
}

func (ic *ImplementedComponent) UnmarshalOscal(oic oscalTypes_1_1_3.ImplementedComponent) *ImplementedComponent {
	componentId := uuid.MustParse(oic.ComponentUuid)
	*ic = ImplementedComponent{
		UUIDModel:     UUIDModel{},
		ComponentUUID: componentId,
		Props:         ConvertOscalToProps(oic.Props),
		Links:         ConvertOscalToLinks(oic.Links),
		Remarks:       oic.Remarks,
		ResponsibleParties: ConvertList(oic.ResponsibleParties, func(op oscalTypes_1_1_3.ResponsibleParty) ResponsibleParty {
			party := ResponsibleParty{}
			party.UnmarshalOscal(op)
			return party
		}),
	}

	return ic
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

type ImplementedRequirement struct {
	UUIDModel
	ControlId        string                               `json:"control-id"`
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	SetParameters    datatypes.JSONSlice[SetParameter]    `json:"set-parameters"`
	ResponsibleRoles datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`
	Remarks          string                               `json:"remarks"`
	ByComponents     []ByComponent                        `json:"by-components" gorm:"Polymorphic:Parent"`
	Statements       []Statement                          `json:"statements"`

	ControlImplementationId uuid.UUID

	// Statements
	// ByComponents
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
	ResponsibleRoles     datatypes.JSONSlice[ResponsibleRole]           `json:"responsible-parties"`
	Remarks              string                                         `json:"remarks"`
	ImplementationStatus datatypes.JSONSlice[ImplementationStatus]      `json:"implementation-status"`
	Export               Export                                         `json:"export"`
	Inherited            []InheritedControlImplementation               `json:"inherited-control-implementations"`
	Satisfied            []SatisfiedControlImplementationResponsibility `json:"satisfied"`
}

func (bc *ByComponent) UnmarshalOscal(obc oscalTypes_1_1_3.ByComponent) *ByComponent {
	id := uuid.MustParse(obc.UUID)
	componentId := uuid.MustParse(obc.ComponentUuid)

	export := Export{}
	if obc.Export != nil {
		export.UnmarshalOscal(*obc.Export)
	}

	*bc = ByComponent{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ComponentUUID: componentId,
		Description:   obc.Description,
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
		Remarks: obc.Remarks,
		Export:  export,
	}
	return bc
}

type ImplementationStatus oscalTypes_1_1_3.ImplementationStatus

func (is *ImplementationStatus) UnmarshalOscal(ois oscalTypes_1_1_3.ImplementationStatus) *ImplementationStatus {
	*is = ImplementationStatus(ois)
	return is
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
		UUIDModel:   UUIDModel{},
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

type ProvidedControlImplementation struct {
	UUIDModel
	Description      string                               `json:"description"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	Remarks          string                               `json:"remarks"`
	ResponsibleRoles datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`

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

type ControlImplementationResponsibility struct {
	UUIDModel
	Description      string                               `json:"description"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	ProvidedUuid     uuid.UUID                            `json:"provided-uuid"`
	Remarks          string                               `json:"remarks"`
	ResponsibleRoles datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`

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

type InheritedControlImplementation struct {
	UUIDModel
	ProvidedUuid     uuid.UUID                            `json:"provided-uuid"`
	Description      string                               `json:"description"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	ResponsibleRoles datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`

	ByComponentId uuid.UUID
}

func (i *InheritedControlImplementation) UnmarshalOscal(oi oscalTypes_1_1_3.InheritedControlImplementation) *InheritedControlImplementation {
	providedUuid, err := uuid.Parse(oi.ProvidedUuid)
	if err != nil {
		providedUuid = uuid.Nil
	}
	*i = InheritedControlImplementation{
		UUIDModel:    UUIDModel{},
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

type SatisfiedControlImplementationResponsibility struct {
	UUIDModel
	ResponsibilityUuid uuid.UUID                            `json:"responsibility-uuid"`
	Description        string                               `json:"description"`
	Props              datatypes.JSONSlice[Prop]            `json:"props"`
	Links              datatypes.JSONSlice[Link]            `json:"links"`
	ResponsibleRoles   datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`
	Remarks            string                               `json:"remarks"`

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

type Statement struct {
	UUIDModel
	StatementId      string                               `json:"statement-id"`
	Props            datatypes.JSONSlice[Prop]            `json:"props"`
	Links            datatypes.JSONSlice[Link]            `json:"links"`
	ResponsibleRoles datatypes.JSONSlice[ResponsibleRole] `json:"responsible-roles"`
	ByComponents     []ByComponent                        `json:"by-components" gorm:"polymorphic:Parent"`
	Remarks          string                               `json:"remarks"`

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
