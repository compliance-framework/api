package assessment

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"time"
)

type Result struct {
	Uuid oscal.Uuid `json:"uuid"`
	oscal.ComprehensiveDetails
	oscal.Props

	AssessmentLog []LogEntry    `json:"assessmentLogEntries"`
	Attestations  []Attestation `json:"attestations"`

	Start time.Time `json:"start"`
	End   time.Time `json:"end"`

	// NOTE: Does it make sense to store Findings in their own collection rather than embedding them into the Result?
	Findings []oscal.Uuid `json:"findings"`

	LocalDefinitions LocalDefinition         `json:"localDefinitions"`
	Observations     []Observation           `json:"observations"`
	ReviewedControls []ControlsAndObjectives `json:"reviewedControls"`

	Risks []oscal.Uuid `json:"risks"`
}

type Attestation struct {
	Parts              []oscal.Part `json:"parts"`
	ResponsibleParties []oscal.Uuid `json:"responsibleParties"`
}

type Characterization struct {
	oscal.Links
	oscal.Props

	Facets []Facet `json:"facets"`
	Origin Origin  `json:"origin"`
}

// Facet An individual characteristic that is part of a larger set produced by the same actor.
type Facet struct {
	oscal.ComprehensiveDetails

	Name string `json:"name"`

	// One of: http://fedramp.gov, http://fedramp.gov/ns/oscal, http://csrc.nist.gov/ns/oscal, http://csrc.nist.gov/ns/oscal/unknown, http://cve.mitre.org, http://www.first.org/cvss/v2.0, http://www.first.org/cvss/v3.0, http://www.first.org/cvss/v3.1
	System string `json:"system"`

	Value string `json:"value"`
}

type Finding struct {
	oscal.ComprehensiveDetails

	Title string     `json:"title"`
	Uuid  oscal.Uuid `json:"uuid"`

	ImplementationStatement oscal.Uuid   `json:"implementationStatementUuid"`
	Origins                 []oscal.Uuid `json:"origins"`
	RelatedObservations     []oscal.Uuid `json:"relatedObservations"`
	RelatedRisks            []oscal.Uuid `json:"relatedRisks"`
	Target                  []oscal.Uuid `json:"target"`
}

type LogEntry struct {
	oscal.ComprehensiveDetails

	Start    time.Time    `json:"start"`
	End      time.Time    `json:"end"`
	LoggedBy []oscal.Uuid `json:"loggedBy"`

	// Reference to Task(s)
	RelatedTasks []oscal.Uuid `json:"relatedTasks"`
}

type Observation struct {
	UUid oscal.Uuid `json:"uuid"`
	oscal.ComprehensiveDetails

	Collected time.Time `json:"collected"`
	Expires   time.Time `json:"expires"`
}

type Origin struct {
	Actors       []oscal.Uuid `json:"actors"`
	RelatedTasks []oscal.Uuid `json:"relatedTasks"`
}

type Risk struct {
	UUid oscal.Uuid `json:"uuid"`
	oscal.ComprehensiveDetails

	Characterizations []Characterization `json:"characterizations"`
	Deadline          time.Time          `json:"deadline"`
}

// Target Captures an assessor's conclusions regarding the degree to which an objective is satisfied.
type Target struct {
	oscal.ComprehensiveDetails

	// The title for this objective status.
	Title string `json:"title"`

	TargetId oscal.Uuid   `json:"targetId"`
	Status   TargetStatus `json:"status"`
}

type TargetStatus struct {
	// An indication whether the objective is satisfied or not. [Pass/Fail/Other]
	State string `json:"state"`

	// A determination of if the objective is satisfied or not within a given system. [Pass/Fail/Other]
	Reason string `json:"reason"`

	Remarks string `json:"remarks"`
}
