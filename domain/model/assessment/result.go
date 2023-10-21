package assessment

import (
	model2 "github.com/compliance-framework/configuration-service/domain/model"
	"time"
)

type Results struct {
	Uuid model2.Uuid `json:"uuid"`

	Metadata model2.Metadata `json:"metadata"`

	BackMatter model2.BackMatter `json:"backMatter"`

	// ImportAp represents the imported assessment plan used for this assessment result.
	// NOTE: In the OSCAL model, this is a web reference. We allow a reference to a local assessment plan.
	ImportAp []model2.Uuid `json:"import-ap"`

	// LocalDefinitions is an optional field used to define data objects that are used in the assessment plan, that do not appear in the referenced System Security Plan (SSP).
	LocalDefinitions LocalDefinition `json:"local-definitions,omitempty"`

	// Results is a collection of Result structures, each representing an individual result from the assessment.
	Results []Result `json:"results"`
}

type Result struct {
	Uuid model2.Uuid `json:"uuid"`
	model2.ComprehensiveDetails

	AssessmentLog []LogEntry    `json:"assessmentLogEntries"`
	Attestations  []Attestation `json:"attestations"`

	Start time.Time `json:"start"`
	End   time.Time `json:"end"`

	// NOTE: Does it make sense to store Findings in their own collection rather than embedding them into the Result?
	Findings []model2.Uuid `json:"findings"`

	LocalDefinitions LocalDefinition         `json:"localDefinitions"`
	Observations     []Observation           `json:"observations"`
	ReviewedControls []ControlsAndObjectives `json:"reviewedControls"`

	Risks []model2.Uuid `json:"risks"`
}

type Attestation struct {
	Parts              []model2.Part `json:"parts"`
	ResponsibleParties []model2.Uuid `json:"responsibleParties"`
}

type Characterization struct {
	model2.Links
	model2.Props

	Facets []Facet `json:"facets"`
	Origin Origin  `json:"origin"`
}

// Facet An individual characteristic that is part of a larger set produced by the same actor.
type Facet struct {
	model2.ComprehensiveDetails

	Name string `json:"name"`

	// One of: http://fedramp.gov, http://fedramp.gov/ns/oscal, http://csrc.nist.gov/ns/oscal, http://csrc.nist.gov/ns/oscal/unknown, http://cve.mitre.org, http://www.first.org/cvss/v2.0, http://www.first.org/cvss/v3.0, http://www.first.org/cvss/v3.1
	System string `json:"system"`

	Value string `json:"value"`
}

type Finding struct {
	model2.ComprehensiveDetails

	Title string      `json:"title"`
	Uuid  model2.Uuid `json:"uuid"`

	ImplementationStatement model2.Uuid   `json:"implementationStatementUuid"`
	Origins                 []model2.Uuid `json:"origins"`
	RelatedObservations     []model2.Uuid `json:"relatedObservations"`
	RelatedRisks            []model2.Uuid `json:"relatedRisks"`
	Target                  []model2.Uuid `json:"target"`
}

type LogEntry struct {
	model2.ComprehensiveDetails

	Start    time.Time     `json:"start"`
	End      time.Time     `json:"end"`
	LoggedBy []model2.Uuid `json:"loggedBy"`

	// Reference to Task(s)
	RelatedTasks []model2.Uuid `json:"relatedTasks"`
}

type Observation struct {
	UUid model2.Uuid `json:"uuid"`
	model2.ComprehensiveDetails

	Collected time.Time `json:"collected"`
	Expires   time.Time `json:"expires"`
}

type Origin struct {
	Actors       []model2.Uuid `json:"actors"`
	RelatedTasks []model2.Uuid `json:"relatedTasks"`
}

type Risk struct {
	UUid model2.Uuid `json:"uuid"`
	model2.ComprehensiveDetails

	Characterizations []Characterization `json:"characterizations"`
	Deadline          time.Time          `json:"deadline"`
}

// Target Captures an assessor's conclusions regarding the degree to which an objective is satisfied.
type Target struct {
	model2.ComprehensiveDetails

	// The title for this objective status.
	Title string `json:"title"`

	TargetId model2.Uuid  `json:"targetId"`
	Status   TargetStatus `json:"status"`
}

type TargetStatus struct {
	// An indication whether the objective is satisfied or not. [Pass/Fail/Other]
	State string `json:"state"`

	// A determination of if the objective is satisfied or not within a given system. [Pass/Fail/Other]
	Reason string `json:"reason"`

	Remarks string `json:"remarks"`
}
