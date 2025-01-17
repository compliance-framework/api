package domain

import (
	"errors"
	"github.com/compliance-framework/configuration-service/converters/labelfilter"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Plan
//
// An assessment plan, such as those provided by a FedRAMP assessor.
// Here are some real-world examples for Assets, Platforms, Subjects and Inventory Items within an OSCAL Assessment Plan:
//
// 1. Assets: This could be something like a customer database within a retail company. It's an asset because it's crucial to the business operation, storing all the essential customer details such as addresses, contact information, and purchase history.
// 2. Platforms: This could be the retail company's online E-commerce platform which hosts their online store, and where transactions occur. The platform might involve web servers, database servers, or a cloud environment.
// 3. Subjects: If the company is performing a security assessment, the subject could be the encryption method or security protocols used to protect the customer data while in transit or at rest in the database.
// 4. Inventory Items: These could be the individual servers or workstations used within the company. Inventory workstations are the physical machines or software applications used by employees that may have vulnerabilities or exposure to risk that need to be tracked and mitigated.
//
// Relation between Tasks, Activities and Steps:
//
// Scenario: Conducting a cybersecurity assessment of an organization's systems.
//
// 1. Task: The major task could be "Conduct vulnerability scanning on servers."
// 2. Activity: Within this task, an activity could be "Prepare servers for vulnerability scan."
// 3. Step: The steps that make up this activity could be things like:
//   - "Identify all servers"
//   - "Ensure necessary permissions are in place for scanning"
//   - "Check that scanning software is properly installed and updated."
//
// Another activity under the same task could be "Execute vulnerability scanning," and steps for that activity might include:
//
// 1. "Begin scanning process through scanning software."
// 2. "Monitor progress of scan."
// 3. "Document any issues or vulnerabilities identified."
//
// The process would continue like this with tasks broken down into activities, and activities broken down into steps.
//
// These concepts still apply in the context of automated tools or systems. In fact, the OSCAL model is designed to support both manual and automated processes.
// 1.	Task: The major task could be “Automated Compliance Checking”
// 2.	Activity: This task could have multiple activities such as:
// ▪	“Configure Automated Tool with necessary parameters”
// ▪	“Run Compliance Check”
// ▪	“Collect and Analyze Compliance Data”
// 3.	Step: In each of these activities, there are several subprocesses or actions (Steps). For example, under “Configure Automated Tool with necessary parameters”, the steps could be:
// ▪	“Define the criteria based on selected standards”
// ▪	“Set the scope or target systems for the assessment”
// ▪	“Specify the output (report) format”
// In context of an automated compliance check, the description of Task, Activity, and Step provides a systematic plan or procedure that the tool is expected to follow. This breakdown of tasks, activities, and steps could also supply useful context and explain the tool’s operation and results to system admins, auditors or other stakeholders. It also allows for easier troubleshooting in the event of problems.
type Plan struct {
	Id primitive.ObjectID `bson:"_id,omitempty" json:"id" yaml:"id"`

	// Status The status of the assessment plan, such as "active" or "inactive".
	// These statuses are subject to change.
	Status string `json:"status,omitempty" yaml:"status,omitempty"`

	// We might switch to struct embedding for fields like Metadata, Props, etc.
	Metadata Metadata `json:"metadata" yaml:"metadata"`

	// Tasks Represents a scheduled event or milestone, which may be associated with a series of assessment actions.
	Tasks []Task `json:"tasks" yaml:"tasks"`

	// Title A name given to the assessment plan. OSCAL doesn't have this, but we need it for our use case.
	Title string `json:"title,omitempty" yaml:"title,omitempty"`

	// The following fields are part of the OSCAL spec, but we don't use them yet.
	// Assets Identifies the assets used to perform this assessment, such as the assessment team, scanning tools, and assumptions. Mostly CF in our case.
	Assets Assets `json:"assets" yaml:"assets"`
	// BackMatter A collection of resources that may be referenced from within the OSCAL document instance.
	BackMatter BackMatter `json:"backMatter" yaml:"backMatter"`
	// Reference to a System Security Plan
	ImportSSP string `json:"importSSP" yaml:"importSSP"`
	// LocalDefinitions Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
	// Reference to LocalDefinition
	LocalDefinitions LocalDefinition `json:"localDefinitions" yaml:"localDefinitions"`
	// ReviewedControls Identifies the controls being assessed and their control objectives.
	ReviewedControls []ControlsAndObjectives `json:"reviewedControls" yaml:"reviewedControls"`
	// TermsAndConditions Used to define various terms and conditions under which an assessment, described by the plan, can be performed. Each child part defines a different type of term or condition.
	TermsAndConditions []Part `json:"termsAndConditions" yaml:"termsAndConditions"`

	ResultFilter labelfilter.Filter `json:"resultFilter" yaml:"resultFilter"`
}

// A PlanPrecis is a cut down version of a plan limited to one level so user can get a view of what the plan is about.
type PlanPrecis struct {
	Id primitive.ObjectID `bson:"_id,omitempty" json:"id" yaml:"id"`
	// Title A name given to the assessment plan. OSCAL doesn't have this, but we need it for our use case.
	Title string `json:"title,omitempty" yaml:"title,omitempty"`
}

func NewPlan() *Plan {
	revision := NewRevision("Initial version", "Initial version", "")

	metadata := Metadata{
		Revisions: []Revision{revision},
		Actions: []Action{
			{
				Id:    primitive.NewObjectID(),
				Title: "Create",
			},
		},
	}

	return &Plan{
		Metadata: metadata,
		Tasks:    []Task{},
		Assets: Assets{
			Components: []primitive.ObjectID{},
			Platforms:  []primitive.ObjectID{},
		},
		Status: "inactive",
	}
}

func (p *Plan) AddAsset(assetId string, assetType string) error {
	oid, err := primitive.ObjectIDFromHex(assetId)
	if err != nil {
		return err
	}
	if assetType == "component" {
		p.Assets.Components = append(p.Assets.Components, oid)
	} else if assetType == "platform" {
		p.Assets.Platforms = append(p.Assets.Components, oid)
	}
	return nil
}

func (p *Plan) GetTask(id string) *Task {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil
	}
	for _, task := range p.Tasks {
		if task.Id == oid {
			return &task
		}
	}
	return nil
}

func (p *Plan) Ready() bool {
	// If there are no Tasks then there's nothing to run.
	if len(p.Tasks) == 0 {
		return false
	}

	// Check if the tasks have at least one activity and all activities have valid subjects.
	for _, task := range p.Tasks {
		if len(task.Activities) == 0 {
			return false
		}
		for _, activity := range task.Activities {
			if !activity.Subjects.Valid() {
				return false
			}
		}
	}

	return true
}

func (p *Plan) JobSpecification() JobSpecification {
	// TODO: We need to send component and control ids as well
	jobSpec := JobSpecification{
		Id:          p.Id.Hex(),
		ControlId:   NewUuid().String(),
		ComponentId: NewUuid().String(),
		Title:       p.Title,
		PlanId:      p.Id.Hex(),
	}

	for _, task := range p.Tasks {
		taskInfo := TaskInformation{
			Id:       task.Id.Hex(),
			Title:    task.Title,
			Schedule: task.Schedule,
		}

		for _, activity := range task.Activities {
			activityInfo := ActivityInformation{
				Id:       activity.Id.Hex(),
				Title:    activity.Title,
				Provider: activity.Provider,
				Selector: activity.Subjects,
			}
			taskInfo.Activities = append(taskInfo.Activities, activityInfo)
		}

		jobSpec.Tasks = append(jobSpec.Tasks, taskInfo)
	}

	return jobSpec
}

type TaskType string

const (
	TaskTypeMilestone TaskType = "milestone"
	TaskTypeAction    TaskType = "action"
)

// Task
//
// See Plan above
type Task struct {
	Id               primitive.ObjectID `json:"id" yaml:"id"`
	Title            string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description      string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props            []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks          string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Type             TaskType           `json:"type" yaml:"type"`
	Activities       []Activity         `json:"activities" yaml:"activities"`
	Dependencies     []TaskDependency   `json:"dependencies" yaml:"dependencies"`
	ResponsibleRoles []Uuid             `json:"responsibleRoles" yaml:"responsibleRoles"`
	// Subjects hold all the subjects that the activities act upon.
	// TODO: Should this be []Subject?
	Subjects []primitive.ObjectID `json:"subjects" yaml:"subjects"`
	Tasks    []Uuid               `json:"tasks" yaml:"tasks"`
	Schedule string               `json:"schedule" yaml:"schedule"`
}

func (t *Task) AddActivity(activity Activity) error {
	// Validate the activity
	if activity.Title == "" {
		return errors.New("activity title cannot be empty")
	}

	// Add the activity to the Activities slice
	t.Activities = append(t.Activities, activity)

	return nil
}

// TaskDependency
//
// A dependency for a Task
type TaskDependency struct {
	TaskId  primitive.ObjectID `json:"taskUuid" yaml:"taskUuid"`
	Remarks string             `json:"remarks" yaml:"remarks"`
}

// Assets
//
// Assets Identifies the assets used to perform this assessment, such as the assessment team, scanning tools, and assumptions.
type Assets struct {
	// Reference to component.Component
	Components []primitive.ObjectID `json:"components" yaml:"components"`

	// Used to represent the toolset used to perform aspects of the assessment.
	Platforms []primitive.ObjectID `json:"platforms" yaml:"platforms"`
}

// Platform
//
// See Plan above
type Platform struct {
	Id          primitive.ObjectID `json:"id" yaml:"id"`
	Title       string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property         `json:"props,omitempty" yaml:"props,omitempty"`

	Links   []Link `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks string `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// Reference to component.Component
	UsesComponents []string `json:"usesComponents" yaml:"usesComponents"`
}

// ControlsAndObjectives
//
// The Controls and Control Objectives that are part of the Plan
type ControlsAndObjectives struct {
	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`

	Links   []Link `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks string `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	Objectives        []ObjectiveSelection `json:"objectives" yaml:"objectives"`
	ControlSelections Selection            `json:"controlSelections" yaml:"controlSelections"`
}

// ObjectiveSelection
//
// Objectives included and excluded.
type ObjectiveSelection struct {
	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`

	Links      []Link   `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks    string   `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	IncludeAll bool     `json:"includeAll" yaml:"includeAll"`
	Exclude    []string `json:"exclude" yaml:"exclude"`
	Include    []string `json:"include" yaml:"include"`
}

// LocalDefinition
//
// See Plan
type LocalDefinition struct {
	Remarks string `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// Reference to Activity
	Activities []string `json:"activities" yaml:"activities"`

	// Reference to component.Component
	Components []primitive.ObjectID `json:"components" yaml:"components"`

	// Reference to ssp.InventoryItem
	InventoryItems []primitive.ObjectID `json:"inventoryItems" yaml:"inventoryItems"`

	Objectives []Objective `json:"objectives" yaml:"objectives"`

	// Reference to identity.User
	Users []primitive.ObjectID `json:"users" yaml:"users"`
}

// Objective
//
// An Objective is a local objective: a security control or requirement
// that is specific to the system or organization under assessment.
type Objective struct {
	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`

	Links      []Link   `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks    string   `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	IncludeAll bool     `json:"includeAll" yaml:"includeAll"`
	Exclude    []string `json:"exclude" yaml:"exclude"`
	Include    []string `json:"include" yaml:"include"`

	// Reference to Activity
	Activities []string `json:"activities" yaml:"activities"`

	// Reference to component.Component
	Components []primitive.ObjectID `json:"components" yaml:"components"`

	// Reference to ssp.InventoryItem
	InventoryItems []primitive.ObjectID `json:"inventoryItems" yaml:"inventoryItems"`

	Objectives []Objective `json:"objectives" yaml:"objectives"`

	// Reference to identity.User
	Users []primitive.ObjectID `json:"users" yaml:"users"`
}

type SubjectType string

const (
	SubjectTypeComponent     SubjectType = "component"
	SubjectTypeInventoryItem SubjectType = "inventoryItem"
	SubjectTypeLocation      SubjectType = "location"
	SubjectTypeParty         SubjectType = "party"
	SubjectTypeUser          SubjectType = "user"
)

// Subject
//
// Subject Identifies system elements being assessed, such as components, inventory items, and locations.
// In the assessment plan, this identifies a planned assessment subject.
// In the assessment results this is an actual assessment subject, and reflects any changes from the plan. exactly what will be the focus of this assessment.
type Subject struct {
	Id          primitive.ObjectID `json:"id" yaml:"id"`
	SubjectId   string             `json:"subjectId" yaml:"subjectId"`
	Type        SubjectType        `json:"type" yaml:"type"`
	Title       string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}

// SubjectSelection
//
// SubjectSelection Identifies system elements being assessed, such as components, inventory items, and locations by specifying a selection criteria.
// We do not directly store SubjectIds as we might not know the actual subjects before running the assessment.
// The assessment runtime evaluates the selection by running the providers and returns back with subject ids.
type SubjectSelection struct {
	Title       string                   `json:"title,omitempty" yaml:"title,omitempty"`
	Description string                   `json:"description,omitempty" yaml:"description,omitempty"`
	Query       string                   `json:"query,omitempty" yaml:"query,omitempty"`
	Labels      map[string]string        `json:"labels,omitempty" yaml:"labels,omitempty"`
	Expressions []SubjectMatchExpression `json:"expressions,omitempty" yaml:"expressions,omitempty"`
	Ids         []string                 `json:"ids,omitempty" yaml:"ids,omitempty"`
}

func (s *SubjectSelection) Valid() bool {
	return s.Query != "" || len(s.Labels) > 0 || len(s.Expressions) > 0 || len(s.Ids) > 0
}

type SubjectMatchExpression struct {
	Key      string   `json:"key" yaml:"key"`
	Operator string   `json:"operator" yaml:"operator"`
	Values   []string `json:"values" yaml:"values"`
}

type Activity struct {
	Id               primitive.ObjectID `json:"id" yaml:"id"`
	Title            string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description      string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props            []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Steps            []Step             `json:"steps,omitempty" yaml:"steps,omitempty"`
	Remarks          string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	ResponsibleRoles []string           `json:"responsibleRoles" yaml:"responsibleRoles"`
	Subjects         SubjectSelection   `json:"subjects" yaml:"subjects"`
	Provider         Provider           `json:"provider" yaml:"provider"`
	Type             string             `json:"type" yaml:"type"`
	Tools            []string           `json:"tools" yaml:"tools"`
}

type Step struct {
	Id               *primitive.ObjectID `json:"id,omitempty" yaml:"id,omitempty"`
	Title            string              `json:"title,omitempty" yaml:"title,omitempty"`
	Description      string              `json:"description,omitempty" yaml:"description,omitempty"`
	Props            []Property          `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link              `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks          string              `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	ResponsibleRoles []string            `json:"responsibleRoles" yaml:"responsibleRoles"`
}
