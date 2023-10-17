package assessment

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

// Plan An assessment plan, such as those provided by a FedRAMP assessor.
type Plan struct {
	oscal.Uuid
	oscal.Metadata

	Assets Assets `json:"assets"`

	Subjects []SubjectSelection `json:"subjects"`

	BackMatter oscal.BackMatter `json:"backMatter"`

	// Reference to a System Security Plan
	ImportSSP oscal.Uuid `json:"importSSP"`

	// LocalDefinitions Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
	// Reference to LocalDefinition
	LocalDefinitions LocalDefinition `json:"localDefinitions"`

	ReviewedControls   []ControlsAndObjectives `json:"reviewedControls"`
	Tasks              []oscal.Uuid            `json:"tasks"`
	TermsAndConditions []oscal.Part            `json:"termsAndConditions"`
}

// Assets Identifies the assets used to perform this assessment, such as the assessment team, scanning tools, and assumptions.
type Assets struct {
	// Reference to component.Component
	Components []oscal.Uuid `json:"components"`

	// Used to represent the toolset used to perform aspects of the assessment.
	Platforms []Platform `json:"platforms"`
}

type Platform struct {
	oscal.Uuid
	oscal.ComprehensiveDetails

	Title string `json:"title"`

	// Reference to component.Component
	UsesComponents []oscal.Uuid `json:"usesComponents"`
}

type ControlsAndObjectives struct {
	oscal.ComprehensiveDetails

	ControlObjectiveSelections []struct {
		oscal.ComprehensiveDetails
		oscal.Selection
	} `json:"controlObjectiveSelections"`

	ControlSelections oscal.Selection `json:"controlSelections"`
}

type LocalDefinition struct {
	oscal.Remarks

	// Reference to Activity
	Activities []oscal.Uuid `json:"activities"`

	// Reference to component.Component
	Components []oscal.Uuid `json:"components"`

	// Reference to ssp.InventoryItem
	InventoryItems []oscal.Uuid `json:"inventoryItems"`

	Objectives []Objective `json:"objectives"`

	// Reference to identity.User
	Users []oscal.Uuid `json:"users"`
}

// Objective A local objective is a security control or requirement that is specific to the system or organization under assessment.
type Objective struct {
	oscal.ComprehensiveDetails
	oscal.Parts

	Control oscal.Uuid `json:"control"`
}

type SubjectType string

const (
	SubjectTypeComponent     SubjectType = "component"
	SubjectTypeInventoryItem SubjectType = "inventoryItem"
	SubjectTypeLocation      SubjectType = "location"
	SubjectTypeParty         SubjectType = "party"
	SubjectTypeUser          SubjectType = "user"
)

type Subject struct {
	oscal.Uuid
	oscal.ComprehensiveDetails

	Title string      `json:"title"`
	Type  SubjectType `json:"type"`
}

// SubjectSelection Acts as a selector. It can hold either a Subject or a Selection.
type SubjectSelection struct {
	Uuid oscal.Uuid `json:"uuid"`
	oscal.ComprehensiveDetails
	oscal.Selection

	Type SubjectType `json:"type"`
}

type TaskType string

const (
	TaskTypeMilestone TaskType = "milestone"
	TaskTypeAction    TaskType = "action"
)

type Task struct {
	oscal.Uuid
	oscal.ComprehensiveDetails

	Title            string             `json:"title"`
	Type             TaskType           `json:"type"`
	Activities       []Activity         `json:"activities"`
	Dependencies     []TaskDependency   `json:"dependencies"`
	ResponsibleRoles []oscal.Uuid       `json:"responsibleRoles"`
	Subjects         []SubjectSelection `json:"subjects"`
	Tasks            []oscal.Uuid       `json:"tasks"`
	Timing           EventTiming        `json:"timing"`
}

type TaskDependency struct {
	TaskId  oscal.Uuid `json:"taskUuid"`
	Remarks string     `json:"remarks"`
}

// EventTiming The timing under which the task is intended to occur.
type EventTiming struct {
	// The task is intended to occur at the specified frequency.
	AtFrequency *FrequencyCondition `json:"at-frequency,omitempty"`

	// The task is intended to occur on the specified date.
	OnDate *OnDateCondition `json:"on-date,omitempty"`

	// The task is intended to occur within the specified date range.
	WithinDateRange *WithinDateRangeCondition `json:"within-date-range,omitempty"`
}

// FrequencyCondition The task is intended to occur at the specified frequency.
type FrequencyCondition struct {
	// The task must occur after the specified period has elapsed.
	Period int `json:"period"`

	// The unit of time for the period.
	Unit string `json:"unit"`
}

// OnDateCondition The task is intended to occur on the specified date.
type OnDateCondition struct {
	// The task must occur on the specified date.
	Date string `json:"date"`
}

// WithinDateRangeCondition The task is intended to occur within the specified date range.
type WithinDateRangeCondition struct {
	// The task must occur on or before the specified date.
	End string `json:"end"`

	// The task must occur on or after the specified date.
	Start string `json:"start"`
}
