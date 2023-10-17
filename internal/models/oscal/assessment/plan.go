package assessment

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/profile"
)

type Plan struct {
	oscal.Uuid
	oscal.Metadata

	Assets struct {
		// Reference to component.Component
		Components []oscal.Uuid `json:"components"`

		Platforms []struct {
			oscal.Uuid
			oscal.ComprehensiveDetails
			Title string `json:"title"`

			// Reference to component.Component
			UsesComponents []oscal.Uuid `json:"usesComponents"`
		}
	}

	Subjects []struct {
		oscal.Uuid
		oscal.ComprehensiveDetails
	} `json:"subjectSelection"`

	BackMatter oscal.BackMatter `json:"backMatter"`

	// Reference to a System Security Plan
	ImportSSP oscal.Uuid `json:"importSSP"`

	// Reference to LocalDefinition
	LocalDefinitions []LocalDefinition `json:"localDefinitions"`

	ReviewedControls []ControlsAndObjectives `json:"reviewedControls"`
	// Tasks
	// Terms and Conditions
}

type ControlsAndObjectives struct {
	oscal.ComprehensiveDetails

	ControlObjectiveSelections []struct {
		oscal.ComprehensiveDetails
		oscal.Selection
	} `json:"controlObjectiveSelections"`

	ControlSelections profile.Selection `json:"controlSelections"`
}

type LocalDefinition struct {
	// Reference to Activity
	Activities []oscal.Uuid `json:"activities"`

	// Reference to component.Component
	Components []oscal.Uuid `json:"components"`

	// Reference to ssp.InventoryItem
	InventoryItems []oscal.Uuid `json:"inventoryItems"`

	Objectives []Objective `json:"objectives"`
	oscal.Remarks

	// Reference to identity.User
	Users []oscal.Uuid `json:"users"`
}

// Objective A local objective is a security control or requirement that is specific to the system or organization under assessment.
type Objective struct {
	oscal.ComprehensiveDetails
	Control oscal.Uuid   `json:"control"`
	Parts   []oscal.Part `json:"parts"`
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

type TaskType string

const (
	TaskTypeMilestone TaskType = "milestone"
	TaskTypeAction    TaskType = "action"
)

type Task struct {
	oscal.Uuid
	oscal.ComprehensiveDetails

	Title string   `json:"title"`
	Type  TaskType `json:"type"`

	Activities   []Activity `json:"activities"`
	Dependencies []struct {
		TaskId  oscal.Uuid `json:"taskUuid"`
		Remarks string     `json:"remarks"`
	}

	ResponsibleRoles []oscal.Uuid `json:"responsibleRoles"`

	// Acts as a selector. It can hold either a Subject or a Selection.
	Subjects []struct {
		oscal.ComprehensiveDetails
		Subject
		oscal.Selection
	}

	Tasks []oscal.Uuid `json:"tasks"`

	Timing struct {
		AtFrequency struct {
			// The task must occur after the specified period has elapsed.
			Period int `json:"period"`

			// The unit of time for the period.
			Unit string `json:"unit"`
		}
		OnDateCondition struct {
			// The task must occur on the specified date.
			Date string `json:"date"`
		}
		OnDateRangeCondition struct {
			// The task must occur on or before the specified date.
			End string `json:"end"`

			// The task must occur on or after the specified date.
			Start string `json:"start"`
		}
	}
}
