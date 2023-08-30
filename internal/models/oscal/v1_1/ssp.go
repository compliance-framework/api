package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/jsonschema"
	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// AuthorizationBoundary A description of this system's authorization boundary, optionally supplemented by diagrams that illustrate the authorization boundary.
type AuthorizationBoundary struct {

	// A summary of the system's authorization boundary.
	Description string      `json:"description"`
	Diagrams    []*Diagram  `json:"diagrams,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
}

// ComponentControlImplementation Defines how the referenced component implements a set of controls.
type ComponentControlImplementation struct {

	// A machine-oriented identifier reference to the component that is implemeting a given control.
	ComponentUuid string `json:"component-uuid"`

	// An implementation statement that describes how a control or a control statement is implemented within the referenced system component.
	Description string `json:"description"`

	// Identifies content intended for external consumption, such as with leveraged organizations.
	Export               *Export                                         `json:"export,omitempty"`
	ImplementationStatus *ImplementationStatus                           `json:"implementation-status,omitempty"`
	Inherited            []*InheritedControlImplementation               `json:"inherited,omitempty"`
	Links                []*Link                                         `json:"links,omitempty"`
	Props                []*Property                                     `json:"props,omitempty"`
	Remarks              string                                          `json:"remarks,omitempty"`
	ResponsibleRoles     []*ResponsibleRole                              `json:"responsible-roles,omitempty"`
	Satisfied            []*SatisfiedControlImplementationResponsibility `json:"satisfied,omitempty"`
	SetParameters        []*ImplementationCommonSetParameter             `json:"set-parameters,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this by-component entry elsewhere in this or other OSCAL instances. The locally defined UUID of the by-component entry can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// ControlBasedRequirement Describes how the system satisfies the requirements of an individual control.
type ControlBasedRequirement struct {
	ByComponents []*ComponentControlImplementation `json:"by-components,omitempty"`

	// A reference to a control with a corresponding id value. When referencing an externally defined control, the Control Identifier Reference must be used in the context of the external / imported OSCAL instance (e.g., uri-reference).
	ControlId        string               `json:"control-id"`
	Links            []*Link              `json:"links,omitempty"`
	Props            []*Property          `json:"props,omitempty"`
	Remarks          string               `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole   `json:"responsible-roles,omitempty"`
	SetParameters    []*SetParameterValue `json:"set-parameters,omitempty"`
	Statements       []*SystemStatement   `json:"statements,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this control requirement elsewhere in this or other OSCAL instances. The locally defined UUID of the control requirement can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// ControlImplementationResponsibility Describes a control implementation responsibility imposed on a leveraging system.
type ControlImplementationResponsibility struct {

	// An implementation statement that describes the aspects of the control or control statement implementation that a leveraging system must implement to satisfy the control provided by a leveraged system.
	Description string      `json:"description"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`

	// A machine-oriented identifier reference to an inherited control implementation that a leveraging system is inheriting from a leveraged system.
	ProvidedUuid     string             `json:"provided-uuid,omitempty"`
	Remarks          string             `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this responsibility elsewhere in this or other OSCAL instances. The locally defined UUID of the responsibility can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// DataFlow A description of the logical flow of information within the system and across its boundaries, optionally supplemented by diagrams that illustrate these flows.
type DataFlow struct {

	// A summary of the system's data flow.
	Description string      `json:"description"`
	Diagrams    []*Diagram  `json:"diagrams,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
}

// Diagram A graphic that provides a visual representation the system, or some aspect of it.
type Diagram struct {

	// A brief caption to annotate the diagram.
	Caption string `json:"caption,omitempty"`

	// A summary of the diagram.
	Description string      `json:"description,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this diagram elsewhere in this or other OSCAL instances. The locally defined UUID of the diagram can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// Export Identifies content intended for external consumption, such as with leveraged organizations.
type Export struct {

	// An implementation statement that describes the aspects of the control or control statement implementation that can be available to another system leveraging this system.
	Description      string                                 `json:"description,omitempty"`
	Links            []*Link                                `json:"links,omitempty"`
	Props            []*Property                            `json:"props,omitempty"`
	Provided         []*ProvidedControlImplementation       `json:"provided,omitempty"`
	Remarks          string                                 `json:"remarks,omitempty"`
	Responsibilities []*ControlImplementationResponsibility `json:"responsibilities,omitempty"`
}

// ImplementedComponent The set of components that are implemented in a given system inventory item.
type ImplementedComponent struct {

	// A machine-oriented identifier reference to a component that is implemented as part of an inventory item.
	ComponentUuid      string              `json:"component-uuid"`
	Links              []*Link             `json:"links,omitempty"`
	Props              []*Property         `json:"props,omitempty"`
	Remarks            string              `json:"remarks,omitempty"`
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`
}

// InformationType Contains details about one information type that is stored, processed, or transmitted by the system, such as privacy information, and those defined in NIST SP 800-60.
type InformationType struct {
	AvailabilityImpact    *SystemImpact                    `json:"availability-impact,omitempty"`
	Categorizations       []*InformationTypeCategorization `json:"categorizations,omitempty"`
	ConfidentialityImpact *SystemImpact                    `json:"confidentiality-impact,omitempty"`

	// A summary of how this information type is used within the system.
	Description     string        `json:"description"`
	IntegrityImpact *SystemImpact `json:"integrity-impact,omitempty"`
	Links           []*Link       `json:"links,omitempty"`
	Props           []*Property   `json:"props,omitempty"`

	// A human readable name for the information type. This title should be meaningful within the context of the system.
	Title string `json:"title"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this information type elsewhere in this or other OSCAL instances. The locally defined UUID of the information type can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid,omitempty"`
}

// InformationTypeCategorization A set of information type identifiers qualified by the given identification system used, such as NIST SP 800-60.
type InformationTypeCategorization struct {
	InformationTypeIds []string `json:"information-type-ids,omitempty"`

	// Specifies the information type identification system used.
	System interface{} `json:"system"`
}

// InheritedControlImplementation Describes a control implementation inherited by a leveraging system.
type InheritedControlImplementation struct {

	// An implementation statement that describes the aspects of a control or control statement implementation that a leveraging system is inheriting from a leveraged system.
	Description string      `json:"description"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`

	// A machine-oriented identifier reference to an inherited control implementation that a leveraging system is inheriting from a leveraged system.
	ProvidedUuid     string             `json:"provided-uuid,omitempty"`
	ResponsibleRoles []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this inherited entry elsewhere in this or other OSCAL instances. The locally defined UUID of the inherited control implementation can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// LeveragedAuthorization A description of another authorized system from which this system inherits capabilities that satisfy security requirements. Another term for this concept is a common control provider.
type LeveragedAuthorization struct {
	DateAuthorized string  `json:"date-authorized"`
	Links          []*Link `json:"links,omitempty"`

	// A machine-oriented identifier reference to the party that manages the leveraged system.
	PartyUuid string      `json:"party-uuid"`
	Props     []*Property `json:"props,omitempty"`
	Remarks   string      `json:"remarks,omitempty"`

	// A human readable name for the leveraged authorization in the context of the system.
	Title string `json:"title"`

	// A machine-oriented, globally unique identifier with cross-instance scope and can be used to reference this leveraged authorization elsewhere in this or other OSCAL instances. The locally defined UUID of the leveraged authorization can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// NetworkArchitecture A description of the system's network architecture, optionally supplemented by diagrams that illustrate the network architecture.
type NetworkArchitecture struct {

	// A summary of the system's network architecture.
	Description string      `json:"description"`
	Diagrams    []*Diagram  `json:"diagrams,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
}

// CommonAuthorizedPrivilege Identifies a specific system privilege held by the user, along with an associated description and/or rationale for the privilege.
type CommonAuthorizedPrivilege struct {

	// A summary of the privilege's purpose within the system.
	Description        string   `json:"description,omitempty"`
	FunctionsPerformed []string `json:"functions-performed"`

	// A human readable name for the privilege.
	Title string `json:"title"`
}

// ImplementationStatus Indicates the degree to which the a given control is implemented.
type ImplementationStatus struct {
	Remarks string `json:"remarks,omitempty"`

	// Identifies the implementation status of the control or control objective.
	State interface{} `json:"state"`
}

// CommonInventoryItem A single managed inventory item within the system.
type CommonInventoryItem struct {

	// A summary of the inventory item stating its purpose within the system.
	Description           string                  `json:"description"`
	ImplementedComponents []*ImplementedComponent `json:"implemented-components,omitempty"`
	Links                 []*Link                 `json:"links,omitempty"`
	Props                 []*Property             `json:"props,omitempty"`
	Remarks               string                  `json:"remarks,omitempty"`
	ResponsibleParties    []*ResponsibleParty     `json:"responsible-parties,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this inventory item elsewhere in this or other OSCAL instances. The locally defined UUID of the inventory item can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// ImplementationCommonSetParameter Identifies the parameter that will be set by the enclosed value.
type ImplementationCommonSetParameter struct {

	// A human-oriented reference to a parameter within a control, who's catalog has been imported into the current implementation context.
	ParamId string   `json:"param-id"`
	Remarks string   `json:"remarks,omitempty"`
	Values  []string `json:"values"`
}

// SystemComponent A defined component that can be part of an implemented system.
type SystemComponent struct {

	// A description of the component, including information about its function.
	Description string                        `json:"description"`
	Links       []*Link                       `json:"links,omitempty"`
	Props       []*Property                   `json:"props,omitempty"`
	Protocols   []*ServiceProtocolInformation `json:"protocols,omitempty"`

	// A summary of the technological or business purpose of the component.
	Purpose          string             `json:"purpose,omitempty"`
	Remarks          string             `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// Describes the operational status of the system component.
	Status *Status `json:"status"`

	// A human readable name for the system component.
	Title string `json:"title"`

	// A category describing the purpose of the component.
	Type string `json:"type"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this component elsewhere in this or other OSCAL instances. The locally defined UUID of the component can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// CommonSystemUser A type of user that interacts with the system based on an associated role.
type CommonSystemUser struct {
	AuthorizedPrivileges []*CommonAuthorizedPrivilege `json:"authorized-privileges,omitempty"`

	// A summary of the user's purpose within the system.
	Description string      `json:"description,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
	RoleIds     []string    `json:"role-ids,omitempty"`

	// A short common name, abbreviation, or acronym for the user.
	ShortName string `json:"short-name,omitempty"`

	// A name given to the user, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this user class elsewhere in this or other OSCAL instances. The locally defined UUID of the system user can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// SystemPlanControlImplementation Describes how the system satisfies a set of controls.
type SystemPlanControlImplementation struct {

	// A statement describing important things to know about how this set of control satisfaction documentation is approached.
	Description             string                              `json:"description"`
	ImplementedRequirements []*ControlBasedRequirement          `json:"implemented-requirements"`
	SetParameters           []*ImplementationCommonSetParameter `json:"set-parameters,omitempty"`
}

// SystemImpact The expected level of impact resulting from the described information.
type SystemImpact struct {
	AdjustmentJustification string      `json:"adjustment-justification,omitempty"`
	Base                    string      `json:"base"`
	Links                   []*Link     `json:"links,omitempty"`
	Props                   []*Property `json:"props,omitempty"`
	Selected                string      `json:"selected,omitempty"`
}

// ImportProfile Used to import the OSCAL profile representing the system's control baseline.
type ImportProfile struct {

	// A resolvable URL reference to the profile or catalog to use as the system's control baseline.
	Href    string `json:"href"`
	Remarks string `json:"remarks,omitempty"`
}

// SystemStatement Identifies which statements within a control are addressed.
type SystemStatement struct {
	ByComponents     []*ComponentControlImplementation `json:"by-components,omitempty"`
	Links            []*Link                           `json:"links,omitempty"`
	Props            []*Property                       `json:"props,omitempty"`
	Remarks          string                            `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole                `json:"responsible-roles,omitempty"`

	// A human-oriented identifier reference to a control statement.
	StatementId string `json:"statement-id"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this control statement elsewhere in this or other OSCAL instances. The UUID of the control statement in the source OSCAL instance is sufficient to reference the data item locally or globally (e.g., in an imported OSCAL instance).
	Uuid string `json:"uuid"`
}

// SystemCharacteristics Contains the characteristics of the system, such as its name, purpose, and security impact level.
type SystemCharacteristics struct {
	AuthorizationBoundary *AuthorizationBoundary `json:"authorization-boundary"`
	DataFlow              *DataFlow              `json:"data-flow,omitempty"`
	DateAuthorized        string                 `json:"date-authorized,omitempty"`

	// A summary of the system.
	Description         string               `json:"description"`
	Links               []*Link              `json:"links,omitempty"`
	NetworkArchitecture *NetworkArchitecture `json:"network-architecture,omitempty"`
	Props               []*Property          `json:"props,omitempty"`
	Remarks             string               `json:"remarks,omitempty"`
	ResponsibleParties  []*ResponsibleParty  `json:"responsible-parties,omitempty"`
	SecurityImpactLevel *SecurityImpactLevel `json:"security-impact-level,omitempty"`

	// The overall information system sensitivity categorization, such as defined by FIPS-199.
	SecuritySensitivityLevel string                  `json:"security-sensitivity-level,omitempty"`
	Status                   *Status                 `json:"status"`
	SystemIds                []*SystemIdentification `json:"system-ids"`
	SystemInformation        *SystemInformation      `json:"system-information"`

	// The full name of the system.
	SystemName string `json:"system-name"`

	// A short name for the system, such as an acronym, that is suitable for display in a data table or summary list.
	SystemNameShort string `json:"system-name-short,omitempty"`
}

// SystemImplementation Provides information as to how the system is implemented.
type SystemImplementation struct {
	Components              []*SystemComponent        `json:"components"`
	InventoryItems          []*CommonInventoryItem    `json:"inventory-items,omitempty"`
	LeveragedAuthorizations []*LeveragedAuthorization `json:"leveraged-authorizations,omitempty"`
	Links                   []*Link                   `json:"links,omitempty"`
	Props                   []*Property               `json:"props,omitempty"`
	Remarks                 string                    `json:"remarks,omitempty"`
	Users                   []*CommonSystemUser       `json:"users"`
}

// ProvidedControlImplementation Describes a capability which may be inherited by a leveraging system.
type ProvidedControlImplementation struct {

	// An implementation statement that describes the aspects of the control or control statement implementation that can be provided to another system leveraging this system.
	Description      string             `json:"description"`
	Links            []*Link            `json:"links,omitempty"`
	Props            []*Property        `json:"props,omitempty"`
	Remarks          string             `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this provided entry elsewhere in this or other OSCAL instances. The locally defined UUID of the provided entry can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// SatisfiedControlImplementationResponsibility Describes how this system satisfies a responsibility imposed by a leveraged system.
type SatisfiedControlImplementationResponsibility struct {

	// An implementation statement that describes the aspects of a control or control statement implementation that a leveraging system is implementing based on a requirement from a leveraged system.
	Description string      `json:"description"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`

	// A machine-oriented identifier reference to a control implementation that satisfies a responsibility imposed by a leveraged system.
	ResponsibilityUuid string             `json:"responsibility-uuid,omitempty"`
	ResponsibleRoles   []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this satisfied control implementation entry elsewhere in this or other OSCAL instances. The locally defined UUID of the control implementation can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// SecurityImpactLevel The overall level of expected impact resulting from unauthorized disclosure, modification, or loss of access to information.
type SecurityImpactLevel struct {

	// A target-level of availability for the system, based on the sensitivity of information within the system.
	SecurityObjectiveAvailability string `json:"security-objective-availability"`

	// A target-level of confidentiality for the system, based on the sensitivity of information within the system.
	SecurityObjectiveConfidentiality string `json:"security-objective-confidentiality"`

	// A target-level of integrity for the system, based on the sensitivity of information within the system.
	SecurityObjectiveIntegrity string `json:"security-objective-integrity"`
}

// Status Describes the operational status of the system component.
type Status struct {
	Remarks string `json:"remarks,omitempty"`

	// The operational status.
	State string `json:"state"`
}

// SystemIdentification A human-oriented, globally unique identifier with cross-instance scope that can be used to reference this system identification property elsewhere in this or other OSCAL instances. When referencing an externally defined system identification, the system identification must be used in the context of the external / imported OSCAL instance (e.g., uri-reference). This string should be assigned per-subject, which means it should be consistently used to identify the same system across revisions of the document.
type SystemIdentification struct {
	Id string `json:"id"`

	// Identifies the identification system from which the provided identifier was assigned.
	IdentifierType interface{} `json:"identifier-type,omitempty"`
}

// SystemInformation Contains details about all information types that are stored, processed, or transmitted by the system, such as privacy information, and those defined in NIST SP 800-60.
type SystemInformation struct {
	InformationTypes []*InformationType `json:"information-types"`
	Links            []*Link            `json:"links,omitempty"`
	Props            []*Property        `json:"props,omitempty"`
}

// SystemSecurityPlan A system security plan, such as those described in NIST SP 800-18.
type SystemSecurityPlan struct {
	BackMatter            *BackMatter                      `json:"back-matter,omitempty"`
	ControlImplementation *SystemPlanControlImplementation `json:"control-implementation,omitempty"`
	ImportProfile         *ImportProfile                   `json:"import-profile,omitempty"`
	Metadata              map[string]interface{}           `json:"metadata"`
	SystemCharacteristics *SystemCharacteristics           `json:"system-characteristics,omitempty"`
	SystemImplementation  *SystemImplementation            `json:"system-implementation,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this system security plan (SSP) elsewhere in this or other OSCAL instances. The locally defined UUID of the SSP can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance).This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *SystemSecurityPlan) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *SystemSecurityPlan) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *SystemSecurityPlan) DeepCopy() schema.BaseModel {
	d := &SystemSecurityPlan{}
	p, err := c.ToJSON()
	if err != nil {
		panic(err)
	}
	err = d.FromJSON(p)
	if err != nil {
		panic(err)
	}
	return d
}

func (c *SystemSecurityPlan) UUID() string {
	return c.Uuid
}

// TODO Add tests
func (c *SystemSecurityPlan) Validate() error {

	sch, err := jsonschema.Compile("https://github.com/usnistgov/OSCAL/releases/download/v1.1.0/oscal_ssp_schema.json")
	if err != nil {
		return err
	}
	var p = map[string]interface{}{
		"system-security-plan": c,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = json.Unmarshal(d, &p)
	if err != nil {
		return err
	}
	return sch.Validate(p)
}

func init() {
	schema.MustRegister("ssp", &SystemSecurityPlan{})
}
