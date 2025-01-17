package domain

import (
	"time"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// In the realm of security and compliance assessments, "Risks" are identified and articulated based on the information presented in "Findings" and "Observations." Here's a breakdown of the process:
//
// Observations:
//
// Observations are typically the raw data or facts identified during the assessment. They capture what the assessor noticed, without necessarily assigning a value judgment.
// For instance, an observation might note that a certain server lacks a recent security patch.
// Findings:
//
// Findings are derived from observations and are more evaluative. They indicate whether an observation has implications for compliance, security, or other assessment criteria.
// Building on the previous example, a finding might state that the server's lack of a recent security patch makes it vulnerable to a specific known exploit.
// Risks:
//
// Risks are broader evaluations that consider the potential consequences and implications of findings. They look at the potential harm or impact that might result if the issues noted in findings aren't addressed.
// Continuing with our example, a risk might point out that the server's vulnerability could lead to a data breach, potentially exposing sensitive customer data and incurring legal penalties.
// In this sequence:
//
// Observations provide the factual basis.
// Findings offer an evaluative judgment based on those facts.
// Risks project forward to estimate the potential consequences and impacts of those findings.
// After an assessment, the risks identified based on findings and observations are typically used to prioritize remediation efforts. The most critical or high-impact risks might be addressed first, followed by less severe ones. This process helps organizations manage their security postures effectively and allocate resources where they are most needed.

type Result struct {
	Id               *primitive.ObjectID     `json:"_id,omitempty" yaml:"_id,omitempty" bson:"_id,omitempty"`
	StreamID         uuid.UUID               `json:"streamId,omitempty" yaml:"streamId,omitempty" bson:"streamId,omitempty"`
	Title            string                  `json:"title,omitempty" yaml:"title,omitempty"`
	Description      string                  `json:"description,omitempty" yaml:"description,omitempty"`
	Start            time.Time               `json:"start" yaml:"start"`
	End              time.Time               `json:"end" yaml:"end"`
	Props            []Property              `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link                  `json:"links,omitempty" yaml:"links,omitempty"`
	LocalDefinitions LocalDefinition         `json:"localDefinitions" yaml:"localDefinitions"`
	ReviewedControls []ControlsAndObjectives `json:"reviewedControls" yaml:"reviewedControls"`
	AssessmentLog    []LogEntry              `json:"assessmentLogEntries" yaml:"assessmentLogEntries"`
	Attestations     []Attestation           `json:"attestations" yaml:"attestations"`
	Observations     []Observation           `json:"observations" yaml:"observations"`
	Risks            []Risk                  `json:"risks" yaml:"risks"`
	Findings         []Finding               `json:"findings" yaml:"findings"`
	Remarks          string                  `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Labels           map[string]string       `json:"labels,omitempty" yaml:"labels,omitempty" bson:"labels,omitempty"`
}

// Attestation represents a formal assertion, declaration, or acknowledgment by an authoritative
// entity in the context of the OSCAL assessment schema. It confirms the accuracy or truth of
// assessment results, system configurations, or other relevant details. Each attestation is
// typically associated with specific assessment results, targets, or findings and may contain
// information about the party making the attestation and any relevant timestamps or metadata.
//
// Example:
//
//	Attestor: Jane Smith, Chief Security Officer
//	Date: 2023-10-31
//	Statement: I hereby attest to the accuracy and completeness of the assessment results
//	for the production server environment dated 2023-10-30.
type Attestation struct {
	Parts              []Part               `json:"parts" yaml:"parts"`
	ResponsibleParties []primitive.ObjectID `json:"responsibleParties" yaml:"responsibleParties"`
}

// Characterization provides a classification or description of the nature
// of an observation or finding within the OSCAL assessment context. It helps
// in understanding the kind, type, or category of the observation.
//
// Example:
//
//	Characterization: Configuration Setting
//	Detail: Describes observations related to system configurations.
type Characterization struct {
	Links  []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props  []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Facets []Facet    `json:"facets" yaml:"facets"`

	// Actors / Tasks Identify the source of the finding, such as a tool, interviewed person, or activity
	Actors []primitive.ObjectID `json:"originActors" yaml:"originActors"`
	Tasks  []primitive.ObjectID `json:"relatedTasks" yaml:"relatedTasks"`
}

// Facet represents specific aspects or dimensions of a characterization in
// the OSCAL assessment context. Facets offer more granular details about the
// nature, source, or implications of an observation or finding.
//
// Example for a Configuration Setting Characterization:
//
//	Facet: Update Frequency
//	Detail: Describes how often the configuration setting updates.
type Facet struct {
	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Name        string     `json:"name" yaml:"name"`
	Value       string     `json:"value" yaml:"value"`
	// One of: http://fedramp.gov, http://fedramp.gov/ns/oscal, http://csrc.nist.gov/ns/oscal, http://csrc.nist.gov/ns/oscal/unknown, http://cve.mitre.org, http://www.first.org/cvss/v2.0, http://www.first.org/cvss/v3.0, http://www.first.org/cvss/v3.1
	System string `json:"system" yaml:"system"`
}

// Finding represents a conclusion or determination drawn from one or more
// observations, typically indicating compliance or non-compliance with specific
// requirements. Findings often lead to recommendations or actions.
//
// Example:
//
//	Finding: The "auto-update" feature's activation goes against the organization's policy
//	of manually vetting and approving system updates. This poses a potential security risk
//	as unvetted updates could introduce vulnerabilities.
type Finding struct {
	Id          primitive.ObjectID `json:"id" yaml:"id"`
	Title       string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Tasks       []Task             `json:"tasks,omitempty" yaml:"tasks,omitempty"`
	Remarks     string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// ImplementationStatementId Reference to the implementation statement in the SSP to which this finding is related.
	ImplementationStatementId primitive.ObjectID `json:"implementationStatementId" yaml:"implementationStatementId"`

	// Actors identify the source of the finding, such as a tool, interviewed person, or activity
	// Maps to the OSCAL "origins" property
	Actors []primitive.ObjectID `json:"originActors" yaml:"originActors"`

	TargetId primitive.ObjectID `json:"target" yaml:"target"`

	RelatedObservations []primitive.ObjectID `json:"relatedObservations" yaml:"relatedObservations"`
	RelatedRisks        []primitive.ObjectID `json:"relatedRisks" yaml:"relatedRisks"`
	Status              string               `json:"status,omitempty" yaml:"status,omitempty"`
}

// LogEntry represents a record in an assessment log that documents a specific
// event or action during the assessment. A log entry can contain various
// information, including observations or findings, but it's essentially a
// chronological record.
//
// Example:
//
//	Date/Time: 2023-10-30 10:00 AM
//	Activity: Review of system configuration settings.
//	Actor: Jane Smith
//	Notes: Started the review of system settings as per the assessment plan. No anomalies observed at this time.
type LogEntry struct {
	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// Identifies the start date and time of an event.
	Start time.Time `json:"start" yaml:"start"`

	// Identifies the end date and time of an event. If the event is a point in time, the start and end will be the same date and time.
	End      time.Time            `json:"end" yaml:"end"`
	LoggedBy []primitive.ObjectID `json:"loggedBy" yaml:"loggedBy"`
}

// Evidence represents data or records collected during an assessment to support
// findings, observations, or attestations within the OSCAL assessment context.
// Evidence can include documents, screenshots, logs, or any other proof that
// verifies the state or behavior of a system.
//
// Example:
//
//	Evidence Type: Screenshot
//	Description: Screenshot showing that the auto-update feature is enabled.
//	URL: path/to/screenshot.png
type Evidence struct {
	Id          primitive.ObjectID `json:"id" yaml:"id"`
	Title       string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}

type ObservationMethod string

const (
	ObservationMethodExamine   ObservationMethod = "examine"
	ObservationMethodInterview ObservationMethod = "interview"
	ObservationMethodTest      ObservationMethod = "test"
	ObservationMethodUnknown   ObservationMethod = "unknown"
)

type ObservationType string

const (
	ObservationTypeSSPStatementIssue ObservationType = "ssp-statement-issue"
	ObservationTypeControlObjective  ObservationType = "control-objective"
	ObservationTypeMitigation        ObservationType = "mitigation"
	ObservationTypeFinding           ObservationType = "finding"
	ObservationTypeHistoric          ObservationType = "historic"
)

// Observation represents a note or remark made by an assessor about something
// they noticed during the assessment. It is a neutral statement that captures
// what was seen or understood without necessarily assigning a value judgment.
//
// Example:
//
//	During the system configuration review, it was observed that the "auto-update" feature was enabled.
type Observation struct {
	Id          primitive.ObjectID  `json:"id" yaml:"id"`
	Title       string              `json:"title,omitempty" yaml:"title,omitempty"`
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property          `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link              `json:"links,omitempty" yaml:"links,omitempty"`
	Methods     []ObservationMethod `json:"methods" yaml:"methods"`
	Types       []ObservationType   `json:"types" yaml:"types"`

	// Actors / Tasks Identify the source of the finding, such as a tool, interviewed person, or activity
	Actors []primitive.ObjectID `json:"originActors" yaml:"originActors"`
	Tasks  []primitive.ObjectID `json:"relatedTasks" yaml:"relatedTasks"`

	Subjects         []primitive.ObjectID `json:"subjects" yaml:"subjects"`
	RelevantEvidence []Evidence           `json:"evidences" yaml:"evidences"`
	Collected        time.Time            `json:"collected" yaml:"collected"`
	Expires          time.Time            `json:"expires" yaml:"expires"`
	Remarks          string               `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}

type RiskStatus string

const (
	RiskStatusOpen               RiskStatus = "open"
	RiskStatusInvestigating      RiskStatus = "investigating"
	RiskStatusRemediating        RiskStatus = "remediating"
	RiskStatusDeviationRequested RiskStatus = "deviation-requested"
	RiskStatusDeviationApproved  RiskStatus = "deviation-approved"
	RiskStatusClosed             RiskStatus = "closed"
)

// Risk represents a potential event or circumstance that may exploit a vulnerability
// in a system or its environment. Risks often have associated impacts and likelihoods,
// which help in determining their severity and priority.
//
// A risk is typically identified from findings and can lead to recommendations
// or mitigating actions to address or reduce the potential impact.
//
// Example:
//
//	Risk: Due to the "auto-update" feature being enabled, there's a chance that
//	unvetted system updates could introduce vulnerabilities.
//	Impact: High - This could compromise the integrity of the system.
//	Likelihood: Medium - Based on past updates and the frequency of potentially harmful updates.
type Risk struct {
	Id primitive.ObjectID `json:"id" yaml:"id"`

	// The title for this risk.
	Title string `json:"title,omitempty" yaml:"title,omitempty"`

	// A human-readable summary of the identified risk, to include a statement of how the risk impacts the system.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// A summary of impact for how the risk affects the system.
	Statement string `json:"statement,omitempty" yaml:"statement,omitempty"`

	Props []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links []Link     `json:"links,omitempty" yaml:"links,omitempty"`

	// Describes the status of the risk.
	Status RiskStatus `json:"status" yaml:"status"`

	// Actors / Tasks Identify the source of the finding, such as a tool, interviewed person, or activity
	Actors []primitive.ObjectID `json:"originActors" yaml:"originActors"`
	Tasks  []primitive.ObjectID `json:"relatedTasks" yaml:"relatedTasks"`

	Threats             []primitive.ObjectID `json:"threats" yaml:"threats"`
	Characterizations   []Characterization   `json:"characterizations" yaml:"characterizations"`
	MitigatingFactors   []primitive.ObjectID `json:"mitigatingFactors" yaml:"mitigatingFactors"`
	Deadline            time.Time            `json:"deadline" yaml:"deadline"`
	Remediations        []Response           `json:"remediations" yaml:"remediations"`
	Log                 []RiskLogEntry       `json:"riskLog" yaml:"riskLog"`
	RelatedObservations []primitive.ObjectID `json:"relatedObservations" yaml:"relatedObservations"`
}

type RiskLogEntry struct {
	Id          primitive.ObjectID `json:"id" yaml:"id"`
	Title       string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description string             `json:"description,omitempty" yaml:"description,omitempty"`
	Start       time.Time          `json:"start" yaml:"start"`
	End         time.Time          `json:"end" yaml:"end"`
	Props       []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	LoggedBy    Actor              `json:"loggedBy" yaml:"loggedBy"`

	// TODO: More fields should be important from the OSCAL schema
}

// MitigatingFactor Describes an existing mitigating factor that may affect the overall determination of the risk, with an optional link to an implementation statement in the SSP.
type MitigatingFactor struct {
	Id               primitive.ObjectID   `json:"id" yaml:"id"`
	ImplementationId primitive.ObjectID   `json:"implementationId" yaml:"implementationId"`
	Description      string               `json:"description" yaml:"description"`
	Props            []Property           `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link               `json:"links,omitempty" yaml:"links,omitempty"`
	Subjects         []primitive.ObjectID `json:"subjects" yaml:"subjects"`
}

// Response Describes either recommended or an actual plan for addressing the risk.
// TODO: Needs more work
type Response struct {
	Id primitive.ObjectID `json:"id" yaml:"id"`

	// Identifies whether this is a recommendation, such as from an assessor or tool, or an actual plan accepted by the system owner.
	// One of: recommendation, planned, completed
	Lifecycle string `json:"lifecycle" yaml:"lifecycle"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`

	// Actors / Tasks Identify the source of the finding, such as a tool, interviewed person, or activity
	Actors []primitive.ObjectID `json:"originActors" yaml:"originActors"`
	Tasks  []primitive.ObjectID `json:"relatedTasks" yaml:"relatedTasks"`
}

// Target Captures an assessor's conclusions regarding the degree to which an objective is satisfied.
// It represents an item or entity that is the subject of an assessment within the OSCAL context.
// It can be a system component, process, configuration, or any other element that has undergone assessment.
// Each target has a unique identifier and may contain additional metadata or details relevant to the assessment.
//
// Example:
//
//	TargetId ID: server-1234
//	Type: System Component
//	Description: Primary web server running in the production environment.
type Target struct {
	TargetId    primitive.ObjectID `json:"targetId" yaml:"targetId"`
	Title       string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Status      TargetStatus       `json:"status" yaml:"status"`
}

type TargetStatus struct {
	// An indication whether the objective is satisfied or not. [Pass/Fail/Other]
	State   string `json:"state" yaml:"state"`
	Reason  string `json:"reason" yaml:"reason"`
	Remarks string `json:"remarks" yaml:"remarks"`
}

type Threat struct {
	Id     primitive.ObjectID `json:"id" yaml:"id"`
	System string             `json:"system" yaml:"system"`
	Href   string             `json:"href" yaml:"href"`
}
