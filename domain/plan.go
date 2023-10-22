package domain

// Plan An assessment plan, such as those provided by a FedRAMP assessor.
// Here are some real-world examples for Assets, Platforms, Subjects and Inventory Items within an OSCAL Assessment Plan:
// 1. Assets: This could be something like a customer database within a retail company. It's an asset because it's crucial to the business operation, storing all the essential customer details such as addresses, contact information, and purchase history.
// 2. Platforms: This could be the retail company's online E-commerce platform which hosts their online store, and where transactions occur. The platform might involve web servers, database servers, or a cloud environment.
// 3. Subjects: If the company is performing a security assessment, the subject could be the encryption method or security protocols used to protect the customer data while in transit or at rest in the database.
// 4. Inventory Items: These could be the individual servers or workstations used within the company. Inventory workstations are the physical machines or software applications used by employees that may have vulnerabilities or exposure to risk that need to be tracked and mitigated.
type Plan struct {
	Uuid

	// Title A name given to the assessment plan. OSCAL doesn't have this, but we need it for our use case.
	Title string `json:"title,omitempty"`

	// We might switch to struct embedding for fields like Metadata, Props, etc.
	Metadata Metadata `json:"metadata"`

	// Assets Identifies the assets used to perform this assessment, such as the assessment team, scanning tools, and assumptions. Mostly CF in our case.
	Assets Assets `json:"assets"`

	// Subjects Identifies system elements being assessed, such as components, inventory items, and locations. In the assessment plan, this identifies a planned assessment subject. In the assessment results this is an actual assessment subject, and reflects any changes from the plan. exactly what will be the focus of this assessment. Any subjects not identified in this
	// We do not directly store SubjectIds as we might not know the actual subjects before running the assessment.
	// The assessment runtime evaluates the selection by running the providers and returns back with subject ids.
	Subjects []SubjectSelection `json:"subjects"`

	// BackMatter A collection of resources that may be referenced from within the OSCAL document instance.
	BackMatter BackMatter `json:"backMatter"`

	// Reference to a System Security Plan
	ImportSSP Uuid `json:"importSSP"`

	// LocalDefinitions Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
	// Reference to LocalDefinition
	LocalDefinitions LocalDefinition `json:"localDefinitions"`

	// ReviewedControls Identifies the controls being assessed and their control objectives.
	ReviewedControls []ControlsAndObjectives `json:"reviewedControls"`

	// Tasks Represents a scheduled event or milestone, which may be associated with a series of assessment actions.
	Tasks []Uuid `json:"tasks"`

	// TermsAndConditions Used to define various terms and conditions under which an assessment, described by the plan, can be performed. Each child part defines a different type of term or condition.
	TermsAndConditions []Part `json:"termsAndConditions"`
}

func NewPlan() *Plan {
	revision := NewRevision("Initial version", "Initial version", "")

	metadata := Metadata{
		Revisions: []Revision{revision},
		Actions: []Action{
			{
				Uuid:  NewUuid(),
				Title: "Create",
			},
		},
	}

	return &Plan{
		Uuid:     NewUuid(),
		Metadata: metadata,
	}
}

func (p *Plan) AddSubjects(subjectIds []Uuid) {
}

// Assets Identifies the assets used to perform this assessment, such as the assessment team, scanning tools, and assumptions.
type Assets struct {
	// Reference to component.Component
	Components []Uuid `json:"components"`

	// Used to represent the toolset used to perform aspects of the assessment.
	Platforms []Uuid `json:"platforms"`
}

type Platform struct {
	Uuid
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	// Reference to component.Component
	UsesComponents []Uuid `json:"usesComponents"`
}

type ControlsAndObjectives struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	Objectives        []ObjectiveSelection `json:"objectives"`
	ControlSelections Selection            `json:"controlSelections"`
}

type ObjectiveSelection struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links      []Link `json:"links,omitempty"`
	Remarks    string `json:"remarks,omitempty"`
	IncludeAll bool   `json:"includeAll"`
	Exclude    []Uuid `json:"exclude"`
	Include    []Uuid `json:"include"`
}

type LocalDefinition struct {
	Remarks string `json:"remarks,omitempty"`

	// Reference to Activity
	Activities []Uuid `json:"activities"`

	// Reference to component.Component
	Components []Uuid `json:"components"`

	// Reference to ssp.InventoryItem
	InventoryItems []Uuid `json:"inventoryItems"`

	Objectives []Objective `json:"objectives"`

	// Reference to identity.User
	Users []Uuid `json:"users"`
}

// Objective A local objective is a security control or requirement that is specific to the system or organization under assessment.
type Objective struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`
	Parts   []Part `json:"parts,omitempty"`

	Control Uuid `json:"control"`
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
	Uuid
	Type        SubjectType `json:"type"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description,omitempty"`
	Props       []Property  `json:"props,omitempty"`
	Links       []Link      `json:"links,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
}

// SubjectSelection Acts as a selector. It can hold either a Subject or a Selection.
type SubjectSelection struct {
	Title       string                   `json:"title,omitempty"`
	Description string                   `json:"description,omitempty"`
	Query       string                   `yaml:"query" json:"query"`
	Labels      map[string]string        `yaml:"labels,omitempty" json:"labels,omitempty"`
	Expressions []SubjectMatchExpression `yaml:"expressions,omitempty" json:"expressions,omitempty"`
	Ids         []string                 `yaml:"ids,omitempty" json:"ids,omitempty"`
}

type SubjectMatchExpression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type TaskType string

const (
	TaskTypeMilestone TaskType = "milestone"
	TaskTypeAction    TaskType = "action"
)

type Task struct {
	Uuid
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	Type             TaskType           `json:"type"`
	Activities       []Activity         `json:"activities"`
	Dependencies     []TaskDependency   `json:"dependencies"`
	ResponsibleRoles []Uuid             `json:"responsibleRoles"`
	Subjects         []SubjectSelection `json:"subjects"`
	Tasks            []Uuid             `json:"tasks"`
	Timing           EventTiming        `json:"timing"`
}

type TaskDependency struct {
	TaskId  Uuid   `json:"taskUuid"`
	Remarks string `json:"remarks"`
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
