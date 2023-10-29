package domain

import (
	"time"
)

type Results struct {
	Uuid Uuid `json:"uuid"`

	Metadata Metadata `json:"metadata"`

	BackMatter BackMatter `json:"backMatter"`

	// ImportAp represents the imported assessment plan used for this assessment result.
	// NOTE: In the OSCAL model, this is a web reference. We allow a reference to a local assessment plan.
	ImportAp []Uuid `json:"import-ap"`

	// LocalDefinitions is an optional field used to define data objects that are used in the assessment plan, that do not appear in the referenced System Security Plan (SSP).
	LocalDefinitions LocalDefinition `json:"local-definitions,omitempty"`

	// Results is a collection of Result structures, each representing an individual result from the assessment.
	Results []Result `json:"results"`
}

type Result struct {
	Uuid        Uuid       `json:"uuid"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	AssessmentLog []LogEntry    `json:"assessmentLogEntries"`
	Attestations  []Attestation `json:"attestations"`

	Start time.Time `json:"start"`
	End   time.Time `json:"end"`

	// NOTE: Does it make sense to store Findings in their own collection rather than embedding them into the Result?
	Findings []Uuid `json:"findings"`

	LocalDefinitions LocalDefinition         `json:"localDefinitions"`
	Observations     []Observation           `json:"observations"`
	ReviewedControls []ControlsAndObjectives `json:"reviewedControls"`

	Risks []Uuid `json:"risks"`
}

type Attestation struct {
	Parts              []Part `json:"parts"`
	ResponsibleParties []Uuid `json:"responsibleParties"`
}

type Characterization struct {
	Links []Link     `json:"links,omitempty"`
	Props []Property `json:"props,omitempty"`

	Facets []Facet `json:"facets"`
	Origin Origin  `json:"origin"`
}

// Facet An individual characteristic that is part of a larger set produced by the same actor.
type Facet struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	Name string `json:"name"`

	// One of: http://fedramp.gov, http://fedramp.gov/ns/oscal, http://csrc.nist.gov/ns/oscal, http://csrc.nist.gov/ns/oscal/unknown, http://cve.mitre.org, http://www.first.org/cvss/v2.0, http://www.first.org/cvss/v3.0, http://www.first.org/cvss/v3.1
	System string `json:"system"`

	Value string `json:"value"`
}

type Finding struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	Uuid Uuid `json:"uuid"`

	ImplementationStatement Uuid   `json:"implementationStatementUuid"`
	Origins                 []Uuid `json:"origins"`
	RelatedObservations     []Uuid `json:"relatedObservations"`
	RelatedRisks            []Uuid `json:"relatedRisks"`
	Target                  []Uuid `json:"target"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Details   string    `json:"details"`
	//Title       string     `json:"title,omitempty"`
	//Description string     `json:"description,omitempty"`
	//Props       []Property `json:"props,omitempty"`
	//
	//Links   []Link `json:"links,omitempty"`
	//Remarks string `json:"remarks,omitempty"`
	//
	//Start    time.Time `json:"start"`
	//End      time.Time `json:"end"`
	//LoggedBy []Uuid    `json:"loggedBy"`
	//
	//// Reference to Task(s)
	//RelatedTasks []Uuid `json:"relatedTasks"`
}

type Observation struct {
	Id          string     `json:"id"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	Collected time.Time `json:"collected"`
	Expires   time.Time `json:"expires"`
}

type Origin struct {
	Actors       []Uuid `json:"actors"`
	RelatedTasks []Uuid `json:"relatedTasks"`
}

type Risk struct {
	UUid        Uuid       `json:"uuid"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	Characterizations []Characterization `json:"characterizations"`
	Deadline          time.Time          `json:"deadline"`
}

// Target Captures an assessor's conclusions regarding the degree to which an objective is satisfied.
type Target struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	TargetId Uuid         `json:"targetId"`
	Status   TargetStatus `json:"status"`
}

type TargetStatus struct {
	// An indication whether the objective is satisfied or not. [Pass/Fail/Other]
	State string `json:"state"`

	// A determination of if the objective is satisfied or not within a given system. [Pass/Fail/Other]
	Reason string `json:"reason"`

	Remarks string `json:"remarks"`
}
