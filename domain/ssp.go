package domain

import (
	"time"
)

type OperationalStatus int

const (
	Disposition OperationalStatus = iota
	Operational
	Other
	UnderDevelopment
	UnderMajorModification
)

func (os OperationalStatus) String() string {
	return [...]string{"disposition", "operational", "other", "under-development", "under-major-modification"}[os]
}

// AuthorizationBoundary defines the system's authorization boundary. It includes a description and optional diagrams illustrating the boundary.
// It can also contain links to additional resources and arbitrary properties.
// For example, the boundary of a cloud-based service might include the cloud infrastructure, network components, and hosted applications.
type AuthorizationBoundary struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	// Diagrams is an optional collection of visual representations of the boundary.
	Diagrams []Diagram `json:"diagrams,omitempty"`
}

// DataFlow describes the logical flow of information within the system and across its boundaries.
// For example, this could represent how data flows from user interfaces to backend services in a web application.
type DataFlow struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	// Description is a summary of the system's data flow.
	Diagrams []Diagram `json:"diagrams,omitempty"`
}

// Diagram provides a visual representation of the system, or some aspect of it.
// For example, a diagram could illustrate the system's network architecture.
type Diagram struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	// Caption provides a brief annotation for the diagram.
	Caption string `json:"caption,omitempty"`
	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this diagram elsewhere in this or other OSCAL instances.
	Uuid string `json:"uuid"`
}

type Impact struct {
	Props                   []Property `json:"props"`
	Links                   []Link     `json:"links"`
	Base                    string     `json:"base"`
	Selected                string     `json:"selected"`
	AdjustmentJustification string     `json:"adjustment_justification"`
}

// InventoryItem A single managed inventory item within the system.
type InventoryItem struct {
	Uuid Uuid `json:"uuid"`

	// A summary of the inventory item stating its purpose within the system.
	ImplementedComponents []Component `json:"implemented-components,omitempty"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	// Reference to Party docs
	ResponsibleParties []Uuid `json:"responsible-parties,omitempty"`
}

// LeveragedAuthorization A description of another authorized system from which this system inherits capabilities that satisfy security requirements. Another term for this concept is a common catalog provider.
type LeveragedAuthorization struct {
	Uuid Uuid `json:"uuid"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	DateAuthorized string `json:"date-authorized"`

	// A machine-oriented identifier reference to the party that manages the leveraged system.
	Party Uuid `json:"party-uuid"`
}

// NetworkArchitecture A description of the system's network architecture, optionally supplemented by diagrams that illustrate the network architecture.
type NetworkArchitecture struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Diagrams []Diagram `json:"diagrams,omitempty"`
}

type Statement struct {
	// TODO: By-components
	Uuid Uuid   `json:"uuid"`
	Id   string `json:"id"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	ResponsibleRoles []Uuid `json:"responsibleRoles"`
}

// SystemCharacteristics Contains the characteristics of the system, such as its name, purpose, and security impact level.
type SystemCharacteristics struct {
	Uuid Uuid `json:"uuid"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Metadata

	AuthorizationBoundary AuthorizationBoundary `json:"authorization_boundary"`
	ControlImplementation []Uuid                `json:"control_implementation"`
	DataFlow              DataFlow              `json:"data_flow"`
	DateAuthorized        time.Time             `json:"date_authorized"`
	ImportProfile         []Uuid                `json:"import_profile"`
	NetworkArchitecture   NetworkArchitecture   `json:"network_architecture"`
	ResponsibleParties    []Uuid                `json:"responsible_parties"`
	SecurityImpactLevel   SecurityImpactLevel   `json:"security_impact_level"`

	// The overall information system sensitivity categorization, such as defined by FIPS-199.
	SecuritySensitivityLevel string            `json:"security_sensitivity_level"`
	Status                   OperationalStatus `json:"status"`

	// One of http://fedramp.gov/ns/oscal, https://fedramp.gov", http://ietf.org/rfc/rfc4122", https://ietf.org/rfc/rfc4122
	SystemIds         []string          `json:"system_ids"`
	SystemInformation SystemInformation `json:"system_information"`

	// The full name of the system.
	SystemName string `json:"system_name"`

	// A short name for the system, such as an acronym, that is suitable for display in a data table or summary list.
	SystemNameShort string `json:"system_name_short"`
}

type SecurityImpactLevel struct {
	ObjectiveAvailability    string `json:"objective_availability"`
	ObjectiveConfidentiality string `json:"objective_confidentiality"`
	ObjectiveIntegrity       string `json:"objective_integrity"`
}

// SystemImplementation Provides information as to how the system is implemented.
type SystemImplementation struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Components              []Component              `json:"components"`
	InventoryItems          []InventoryItem          `json:"inventory-items,omitempty"`
	LeveragedAuthorizations []LeveragedAuthorization `json:"leveraged-authorizations,omitempty"`
	Users                   []User                   `json:"users"`
}

type SystemInformation struct {
	// Contains details about one information type that is stored, processed, or transmitted by the system, such as privacy information, and those defined in NIST SP 800-60.
	InformationTypes []InformationType `json:"information_types"`
	Links            []Link            `json:"links"`
	Props            []Property        `json:"props"`
	Uuid             Uuid              `json:"uuid"`
}

type InformationType struct {
	Uuid        Uuid       `json:"uuid"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	AvailabilityImpact    Impact                          `json:"availability_impact"`
	Categorizations       []InformationTypeCategorization `json:"categorizations"`
	ConfidentialityImpact Impact                          `json:"confidentiality_impact"`
	IntegrityImpact       Impact                          `json:"integrity_impact"`
}

type InformationTypeCategorization struct {
	Ids    []string `json:"ids"`    // NOTE: This part is a bit blurred
	System string   `json:"system"` // This is an enum but right now it has only one value: http://doi.org/10.6028/NIST.SP.800-60v2r1
}

type SystemSecurityPlan struct {
	Title      string     `json:"title"`
	Uuid       Uuid       `json:"uuid"`
	BackMatter BackMatter `json:"backmatter"`
	Metadata

	// Reference to the control implementation
	ControlImplementation []Uuid `json:"control_implementation"`

	// Reference to a profile
	ImportProfile         Uuid                  `json:"import_profile"`
	SystemCharacteristics SystemCharacteristics `json:"system_characteristics"`
}
