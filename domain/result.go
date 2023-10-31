package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
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
	Id               primitive.ObjectID      `json:"id"`
	Title            string                  `json:"title,omitempty"`
	Description      string                  `json:"description,omitempty"`
	Props            []Property              `json:"props,omitempty"`
	Links            []Link                  `json:"links,omitempty"`
	Remarks          string                  `json:"remarks,omitempty"`
	LocalDefinitions LocalDefinition         `json:"localDefinitions"`
	AssessmentLog    []LogEntry              `json:"assessmentLogEntries"`
	Attestations     []Attestation           `json:"attestations"`
	Start            time.Time               `json:"start"`
	End              time.Time               `json:"end"`
	Findings         []Finding               `json:"findings"`
	Observations     []Observation           `json:"observations"`
	ReviewedControls []ControlsAndObjectives `json:"reviewedControls"`
	Risks            []Risk                  `json:"risks"`
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
	Parts              []Part `json:"parts"`
	ResponsibleParties []Uuid `json:"responsibleParties"`
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
	Links  []Link     `json:"links,omitempty"`
	Props  []Property `json:"props,omitempty"`
	Facets []Facet    `json:"facets"`
	Origin Origin     `json:"origin"`
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
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`
	Name        string     `json:"name"`
	Value       string     `json:"value"`
	// One of: http://fedramp.gov, http://fedramp.gov/ns/oscal, http://csrc.nist.gov/ns/oscal, http://csrc.nist.gov/ns/oscal/unknown, http://cve.mitre.org, http://www.first.org/cvss/v2.0, http://www.first.org/cvss/v3.0, http://www.first.org/cvss/v3.1
	System string `json:"system"`
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
	Id                      primitive.ObjectID   `json:"id"`
	Title                   string               `json:"title,omitempty"`
	Description             string               `json:"description,omitempty"`
	Props                   []Property           `json:"props,omitempty"`
	Links                   []Link               `json:"links,omitempty"`
	Remarks                 string               `json:"remarks,omitempty"`
	ImplementationStatement Uuid                 `json:"implementationStatementUuid"`
	Origins                 []Uuid               `json:"origins"`
	RelatedObservations     []primitive.ObjectID `json:"relatedObservations"`
	RelatedRisks            []primitive.ObjectID `json:"relatedRisks"`
	Target                  []primitive.ObjectID `json:"target"`
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
	Timestamp   time.Time            `json:"timestamp"`
	Type        int32                `json:"type"`
	Title       string               `json:"title,omitempty"`
	Description string               `json:"description,omitempty"`
	Props       []Property           `json:"props,omitempty"`
	Links       []Link               `json:"links,omitempty"`
	Remarks     string               `json:"remarks,omitempty"`
	Start       time.Time            `json:"start"`
	End         time.Time            `json:"end"`
	LoggedBy    []primitive.ObjectID `json:"loggedBy"`
}

// Observation represents a note or remark made by an assessor about something
// they noticed during the assessment. It is a neutral statement that captures
// what was seen or understood without necessarily assigning a value judgment.
//
// Example:
//
//	During the system configuration review, it was observed that the "auto-update" feature was enabled.
type Observation struct {
	Id          primitive.ObjectID `json:"id"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description,omitempty"`
	Props       []Property         `json:"props,omitempty"`
	Links       []Link             `json:"links,omitempty"`
	Remarks     string             `json:"remarks,omitempty"`
	Collected   time.Time          `json:"collected"`
	Expires     time.Time          `json:"expires"`
}

type Origin struct {
	Actors       []primitive.ObjectID `json:"actors"`
	RelatedTasks []primitive.ObjectID `json:"relatedTasks"`
}

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
	Id                primitive.ObjectID `json:"uuid"`
	Title             string             `json:"title,omitempty"`
	Description       string             `json:"description,omitempty"`
	Props             []Property         `json:"props,omitempty"`
	Links             []Link             `json:"links,omitempty"`
	Remarks           string             `json:"remarks,omitempty"`
	Characterizations []Characterization `json:"characterizations"`
	Deadline          time.Time          `json:"deadline"`
}

// Target Captures an assessor's conclusions regarding the degree to which an objective is satisfied.
// It represents an item or entity that is the subject of an assessment within the OSCAL context.
// It can be a system component, process, configuration, or any other element that has undergone assessment.
// Each target has a unique identifier and may contain additional metadata or details relevant to the assessment.
//
// Example:
//
//	Target ID: server-1234
//	Type: System Component
//	Description: Primary web server running in the production environment.
type Target struct {
	TargetId    primitive.ObjectID `json:"targetId"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description,omitempty"`
	Props       []Property         `json:"props,omitempty"`
	Links       []Link             `json:"links,omitempty"`
	Remarks     string             `json:"remarks,omitempty"`
	Status      TargetStatus       `json:"status"`
}

type TargetStatus struct {
	// An indication whether the objective is satisfied or not. [Pass/Fail/Other]
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Remarks string `json:"remarks"`
}
