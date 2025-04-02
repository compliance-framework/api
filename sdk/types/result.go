package types

import (
	"time"

	"github.com/google/uuid"
)

// ComponentReference is a reference to a component definition which will be defined in CCF and administered
// via the UI or through common components libraries.
type ComponentReference struct {
	// A reference for this component. Example: `common-components/mongodb` or `internal-components/logging-system`
	Identifier string `json:"identifier" yaml:"identifier"`

	// Where can the definition for this component be imported from ? optional. If not specified, and empty identifier
	// will be created for later administration in the CCF UI
	Href string `json:"href,omitempty" yaml:"href,omitempty"`
}

// ControlReference is a reference to controls specified in catalogues and profiles from standards for example
type ControlReference struct {
	Class        string    `json:"class" yaml:"class"`
	ControlId    string    `json:"control-id" yaml:"control-id"`
	StatementIds *[]string `json:"statement-ids,omitempty" yaml:"statement-ids,omitempty"`
}

// FindingStatus represents the outcome of a finding.
// State defines the final decision as `satisfied` or `not-satisfied`
type FindingStatus struct {
	Title       string      `json:"title,omitempty" yaml:"title,omitempty"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Remarks     string      `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	State       string      `json:"state" yaml:"state"`
	Links       *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props       *[]Property `json:"props,omitempty" yaml:"props,omitempty"`
}

type Finding struct {
	// UUID needs to remain consistent when automation runs again, but unique for each subject
	// This will become the previously referenced streamId for CCF
	UUID        uuid.UUID `json:"uuid" yaml:"uuid"`
	ID          uuid.UUID `json:"id" yaml:"id"`
	Title       string    `json:"title" yaml:"title"`
	Collected   time.Time `json:"collected" yaml:"collected"`
	Description string    `json:"description" yaml:"description"`
	Remarks     string    `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// Labels represent the unique labels which can be used to filter for findings in the UI.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Who is generating this finding
	Origins *[]Origin `json:"origins,omitempty" yaml:"origins,omitempty"`
	// What are we making a judgement against
	Subjects *[]SubjectReference `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	// Which components of the subject are being judged
	Components *[]ComponentReference `json:"components,omitempty" yaml:"components,omitempty"`
	// Which observations led to this judgment ?
	RelatedObservations *[]RelatedObservation `json:"related-observations,omitempty" yaml:"related-observations,omitempty"`
	// Which controls did we validate
	Controls *[]ControlReference `json:"controls" yaml:"controls"`
	// Which risks are associated with what we've tested
	Risks *[]RiskReference `json:"risks,omitempty" yaml:"risks,omitempty"`
	// What is our conclusion drawn for this finding. satisfied | not-satisfied
	Status FindingStatus `json:"status" yaml:"status"`

	// Oscal
	Links *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props *[]Property `json:"props,omitempty" yaml:"props,omitempty"`
}

type Observation struct {
	// UUID needs to remain consistent when automation runs again, but unique for each subject
	UUID        uuid.UUID `json:"uuid" yaml:"uuid"`
	ID          uuid.UUID `json:"id" yaml:"id"`
	Title       string    `json:"title,omitempty" yaml:"title,omitempty"`
	Description string    `json:"description" yaml:"description"`
	Remarks     string    `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	Collected time.Time   `json:"collected" yaml:"collected"`
	Expires   *time.Time  `json:"expires,omitempty" yaml:"expires,omitempty"`
	Methods   *[]string   `json:"methods" yaml:"methods"`
	Links     *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props     *[]Property `json:"props,omitempty" yaml:"props,omitempty"`

	// Who is generating this finding
	Origins *[]Origin `json:"origins,omitempty" yaml:"origins,omitempty"`
	// What are we observing
	Subjects *[]SubjectReference `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	// What steps did we take to make this observation
	Activities *[]Activity `json:"activities,omitempty" yaml:"activities,omitempty"`
	// Which components of the subject are being observed
	Components *[]ComponentReference `json:"components,omitempty" yaml:"components,omitempty"`
	// What exactly did we see
	RelevantEvidence *[]RelevantEvidence `json:"relevant-evidence,omitempty" yaml:"relevant-evidence,omitempty"`
}

type RiskReference struct {
	Identifier string `json:"identifier" yaml:"identifier"`
	// If a Href is specified here, it means we are referencing a common risk, and should be pulled from there.
	Href string `json:"href,omitempty" yaml:"href,omitempty"`
	// The status for the risk. This can either be open|closed based on whether the risk is active or not.
	Status string `json:"status" yaml:"status"`

	// Who is generating this risk
	Origins *[]Origin `json:"origins,omitempty" yaml:"origins,omitempty"`

	// These threats relate to well known threats like phishing emails, brute force attacks, etc. often detailed
	// by cyber-security organisations.
	ThreatIds *[]ThreatId `json:"threat-ids,omitempty" yaml:"threat-ids,omitempty"`
}

// Activity represents a high level task that was executed.
// "Start & Configure CCF Plugin"
// "Collect information about host SSH configuration"
// "Execute policy engine"
// "Build Observations, Findings and Risks from policy output"
type Activity struct {
	UUID        *uuid.UUID  `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Title       string      `json:"title" yaml:"title"`
	Description string      `json:"description" yaml:"description"`
	Remarks     *string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Steps       *[]Step     `json:"steps,omitempty" yaml:"steps,omitempty"`
	Links       *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props       *[]Property `json:"props,omitempty" yaml:"props,omitempty"`
}

// Step represents a lower level task that was executed.
// For example, within an Activity "Collect information about host SSH Configuration", steps might include:
// "execute `sshd -T` to collect SSH configuration from host"
// "convert command output to JSON representation"
type Step struct {
	UUID        *uuid.UUID  `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Title       string      `json:"title" yaml:"title"`
	Description string      `json:"description" yaml:"description"`
	Remarks     *string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Links       *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props       *[]Property `json:"props,omitempty" yaml:"props,omitempty"`
}

// Origin defined where a observation, finding or risk came from. Who added the data ?
// In our agent case the main origin actor would be "The Continuous Compliance Framework"
type Origin struct {
	Actors []OriginActor `json:"actors" yaml:"actors"`
}

type RelatedObservation struct {
	ObservationUuid uuid.UUID `json:"observation-uuid" yaml:"observation-uuid"`
}

type RelevantEvidence struct {
	Description string      `json:"description" yaml:"description"`
	Remarks     string      `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Href        string      `json:"href,omitempty" yaml:"href,omitempty"`
	Links       *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props       *[]Property `json:"props,omitempty" yaml:"props,omitempty"`
}

type SubjectReference struct {
	Title      string            `json:"title,omitempty" yaml:"title,omitempty"`
	Remarks    string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Type       string            `json:"type" yaml:"type"`
	Attributes map[string]string `json:"attributes" yaml:"attributes"`
	Links      *[]Link           `json:"links,omitempty" yaml:"links,omitempty"`
	Props      *[]Property       `json:"props,omitempty" yaml:"props,omitempty"`
}

type ThreatId struct {
	Href   string `json:"href,omitempty" yaml:"href,omitempty"`
	ID     string `json:"id" yaml:"id"`
	System string `json:"system" yaml:"system"`
}

type OriginActor struct {
	UUID  *uuid.UUID  `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Title string      `json:"title" yaml:"title"`
	Type  string      `json:"type" yaml:"type"`
	Links *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props *[]Property `json:"props,omitempty" yaml:"props,omitempty"`
}
