package relational

import (
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type AssessmentPlan struct {
	UUIDModel
	Metadata   Metadata    `gorm:"polymorphic:Parent;"`
	BackMatter *BackMatter `gorm:"polymorphic:Parent;"`
	ImportSSP  datatypes.JSONType[ImportSsp]

	Tasks []Task `gorm:"polymorphic:Parent"`

	ReviewedControls   ReviewedControls    `gorm:"polymorphic:Parent"`
	AssessmentAssets   []AssessmentAsset   `gorm:"many2many:assessment_plan_assessment_assets"`
	AssessmentSubjects []AssessmentSubject `gorm:"many2many:assessment_plan_assessment_subjects"`
	LocalDefinition    LocalDefinition     `gorm:"polymorphic:Parent"`

	TermsAndConditions TermsAndConditions
}

func (i *AssessmentPlan) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentPlan) *AssessmentPlan {
	*i = AssessmentPlan{}
	return i
}

func (i *AssessmentPlan) MarshalOscal() *oscalTypes_1_1_3.AssessmentPlan {
	ret := oscalTypes_1_1_3.AssessmentPlan{}
	return &ret
}

type TermsAndConditions struct {
	UUIDModel
	AssessmentPlanID uuid.UUID
	Parts            []Part `gorm:"many2many:terms_and_conditions_parts"`
}

type LocalDefinition struct {
	UUIDModel

	Remarks              *string
	Components           []SystemComponent `gorm:"many2many:local_definition_components"`
	InventoryItems       []InventoryItem   `gorm:"many2many:local_definition_inventory_items"`
	Users                []SystemUser      `gorm:"many2many:local_definition_users"`
	ObjectivesAndMethods []LocalObjective  `gorm:"many2many:local_definition_objectives"`
	Activities           []Activity        `gorm:"many2many:local_definition_activities"`

	ParentID   uuid.UUID
	ParentType string
}

func (i *LocalDefinition) UnmarshalOscal(op oscalTypes_1_1_3.LocalDefinitions) *LocalDefinition {
	*i = LocalDefinition{}
	return i
}

func (i *LocalDefinition) MarshalOscal() *oscalTypes_1_1_3.LocalDefinitions {
	ret := oscalTypes_1_1_3.LocalDefinitions{}
	return &ret
}

type LocalObjective struct {
	UUIDModel

	ControlID string // required
	Control   Control

	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop]
	Links       datatypes.JSONSlice[Link]

	Parts datatypes.JSONSlice[Part] // required
}

func (i *LocalObjective) UnmarshalOscal(op oscalTypes_1_1_3.LocalObjective) *LocalObjective {
	*i = LocalObjective{}
	return i
}

func (i *LocalObjective) MarshalOscal() *oscalTypes_1_1_3.LocalObjective {
	ret := oscalTypes_1_1_3.LocalObjective{}
	return &ret
}

type ImportSsp oscalTypes_1_1_3.ImportSsp

func (i *ImportSsp) UnmarshalOscal(oip oscalTypes_1_1_3.ImportSsp) *ImportSsp {
	*i = ImportSsp(oip)
	return i
}

func (i *ImportSsp) MarshalOscal() *oscalTypes_1_1_3.ImportSsp {
	p := oscalTypes_1_1_3.ImportSsp(*i)
	return &p
}

// Task can fall under an AssessmentPlan, AssessmentResult, or Response
type Task struct {
	UUIDModel

	Type        string // required: [ milestone | action ]
	Title       string // required
	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`

	Dependencies         []TaskDependency // Different struct, as each dependency can have additional remarks
	Tasks                []Task           `gorm:"many2many:task_tasks"` // Sub tasks
	AssociatedActivities []AssociatedActivity
	Subjects             []AssessmentSubject                              `gorm:"many2many:task_subjects"`
	ResponsibleRole      []ResponsibleRole                                `gorm:"many2many:task_responsible_roles"`
	Timing               datatypes.JSONType[oscalTypes_1_1_3.EventTiming] // Using Oscal types TODO have further discussion

	ParentID   *uuid.UUID
	ParentType string
}

func (i *Task) UnmarshalOscal(op oscalTypes_1_1_3.Task) *Task {
	*i = Task{}
	return i
}

func (i *Task) MarshalOscal() *oscalTypes_1_1_3.Task {
	ret := oscalTypes_1_1_3.Task{}
	return &ret
}

type TaskDependency struct {
	UUIDModel
	TaskID  uuid.UUID
	Task    Task
	Remarks *string
}

func (i *TaskDependency) UnmarshalOscal(op oscalTypes_1_1_3.TaskDependency) *TaskDependency {
	*i = TaskDependency{}
	return i
}

func (i *TaskDependency) MarshalOscal() *oscalTypes_1_1_3.TaskDependency {
	ret := oscalTypes_1_1_3.TaskDependency{}
	return &ret
}

type AssessmentAsset struct {
	UUIDModel

	Components          []SystemComponent    `gorm:"many2many:assessment_asset_components"`
	AssessmentPlatforms []AssessmentPlatform // required
}

func (i *AssessmentAsset) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentAssets) *AssessmentAsset {
	*i = AssessmentAsset{}
	return i
}

func (i *AssessmentAsset) MarshalOscal() *oscalTypes_1_1_3.AssessmentAssets {
	ret := oscalTypes_1_1_3.AssessmentAssets{}
	return &ret
}

type AssessmentPlatform struct {
	UUIDModel
	AssessmentAssetID uuid.UUID
	AssessmentAsset   AssessmentAsset
	Title             *string
	Remarks           *string
	Props             datatypes.JSONSlice[Prop]
	Links             datatypes.JSONSlice[Link]
	UsesComponents    []UsesComponent
}

func (i *AssessmentPlatform) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentPlatform) *AssessmentPlatform {
	*i = AssessmentPlatform{}
	return i
}

func (i *AssessmentPlatform) MarshalOscal() *oscalTypes_1_1_3.AssessmentPlatform {
	ret := oscalTypes_1_1_3.AssessmentPlatform{}
	return &ret
}

type UsesComponent struct {
	UUIDModel
	AssessmentPlatformID uuid.UUID
	AssessmentPlatform   *AssessmentPlatform // parent
	Remarks              *string
	Props                datatypes.JSONSlice[Prop]
	Links                datatypes.JSONSlice[Link]
	ComponentID          uuid.UUID
	Component            DefinedComponent   // child
	ResponsibleParties   []ResponsibleParty `gorm:"many2many:uses_component_responsible_parties"`
}

func (i *UsesComponent) UnmarshalOscal(op oscalTypes_1_1_3.UsesComponent) *UsesComponent {
	*i = UsesComponent{}
	return i
}

func (i *UsesComponent) MarshalOscal() *oscalTypes_1_1_3.UsesComponent {
	ret := oscalTypes_1_1_3.UsesComponent{}
	return &ret
}

type AssessmentSubject struct {
	// Assessment Subject is a loose reference to some subject.
	// A subject can be a Component, InventoryItem, Location, Party, User, Resource.
	// In our struct we don't store the type, but rather have relations to each of these, and when marhsalling and unmarshalling,
	// setting the type to what we know it is.
	UUIDModel

	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop]
	Links       datatypes.JSONSlice[Link]

	ComponentID     *uuid.UUID
	Component       *DefinedComponent
	InventoryItemID *uuid.UUID
	InventoryItem   *InventoryItem
	LocationID      *uuid.UUID
	Location        *Location
	PartyID         *uuid.UUID
	Party           *Party
	UserID          *uuid.UUID
	User            *SystemUser

	IncludeAll      datatypes.JSONType[*IncludeAll]
	IncludeSubjects []SelectSubjectById
	ExcludeSubjects []SelectSubjectById
}

func (i *AssessmentSubject) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentSubject) *AssessmentSubject {
	*i = AssessmentSubject{}
	return i
}

func (i *AssessmentSubject) MarshalOscal() *oscalTypes_1_1_3.AssessmentSubject {
	ret := oscalTypes_1_1_3.AssessmentSubject{}
	return &ret
}

type SelectSubjectById struct {
	UUIDModel
	AssessmentSubjectID uuid.UUID
	Remarks             *string
	SubjectID           uuid.UUID
	Subject             *AssessmentSubject
	Props               datatypes.JSONSlice[Prop]
	Links               datatypes.JSONSlice[Link]
}

func (i *SelectSubjectById) UnmarshalOscal(op oscalTypes_1_1_3.SelectSubjectById) *SelectSubjectById {
	*i = SelectSubjectById{}
	return i
}

func (i *SelectSubjectById) MarshalOscal() *oscalTypes_1_1_3.SelectSubjectById {
	ret := oscalTypes_1_1_3.SelectSubjectById{}
	return &ret
}

type AssociatedActivity struct {
	UUIDModel
	TaskID  uuid.UUID // Belongs to a task
	Remarks *string

	Activity         Activity `gorm:"many2many:associated_activity_activities"` // required
	Props            datatypes.JSONSlice[Prop]
	Links            datatypes.JSONSlice[Link]
	ResponsibleRoles []ResponsibleRole   `gorm:"polymorphic:Parent;"`
	Subjects         []AssessmentSubject `gorm:"many2many:associated_activity_subjects"` // required
}

func (i *AssociatedActivity) UnmarshalOscal(op oscalTypes_1_1_3.AssociatedActivity) *AssociatedActivity {
	*i = AssociatedActivity{}
	return i
}

func (i *AssociatedActivity) MarshalOscal() *oscalTypes_1_1_3.AssociatedActivity {
	ret := oscalTypes_1_1_3.AssociatedActivity{}
	return &ret
}

type Activity struct {
	UUIDModel
	Title       *string
	Description string  // required
	Remarks     *string // required

	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`
	Steps []Step

	RelatedControls  ReviewedControls  `gorm:"polymorphic:Parent"`
	ResponsibleRoles []ResponsibleRole `gorm:"polymorphic:Parent"`
}

func (i *Activity) UnmarshalOscal(op oscalTypes_1_1_3.Activity) *Activity {
	*i = Activity{}
	return i
}

func (i *Activity) MarshalOscal() *oscalTypes_1_1_3.Activity {
	ret := oscalTypes_1_1_3.Activity{}
	return &ret
}

type Step struct {
	UUIDModel
	ActivityID uuid.UUID

	Title       *string
	Description string // required
	Remarks     *string

	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`

	ResponsibleRoles []ResponsibleRole `gorm:"polymorphic:Parent;"`
	ReviewedControls ReviewedControls  `gorm:"polymorphic:Parent"`
}

func (i *Step) UnmarshalOscal(op oscalTypes_1_1_3.Step) *Step {
	*i = Step{}
	return i
}

func (i *Step) MarshalOscal() *oscalTypes_1_1_3.Step {
	ret := oscalTypes_1_1_3.Step{}
	return &ret
}

type ReviewedControls struct {
	UUIDModel
	Description                *string
	Remarks                    *string
	Props                      datatypes.JSONSlice[Prop]
	Links                      datatypes.JSONSlice[Link]
	ControlSelections          []ControlSelection // required
	ControlObjectiveSelections []ControlObjectiveSelection

	ParentID   uuid.UUID
	ParentType string
}

func (i *ReviewedControls) UnmarshalOscal(op oscalTypes_1_1_3.ReviewedControls) *ReviewedControls {
	*i = ReviewedControls{}
	return i
}

func (i *ReviewedControls) MarshalOscal() *oscalTypes_1_1_3.ReviewedControls {
	ret := oscalTypes_1_1_3.ReviewedControls{}
	return &ret
}

type ControlSelection struct {
	UUIDModel
	ReviewedControlsID uuid.UUID
	Description        *string
	Remarks            *string
	Props              datatypes.JSONSlice[Prop]
	Links              datatypes.JSONSlice[Link]

	IncludeAll      datatypes.JSONType[*IncludeAll]
	IncludeControls []SelectControlById `gorm:"Polymorphic:Parent;polymorphicValue:included"`
	ExcludeControls []SelectControlById `gorm:"Polymorphic:Parent;polymorphicValue:excluded"`
}

func (i *ControlSelection) UnmarshalOscal(op oscalTypes_1_1_3.AssessedControls) *ControlSelection {
	*i = ControlSelection{}
	return i
}

func (i *ControlSelection) MarshalOscal() *oscalTypes_1_1_3.AssessedControls {
	ret := oscalTypes_1_1_3.AssessedControls{}
	return &ret
}

type ControlObjectiveSelection struct {
	UUIDModel
	ReviewedControlsID uuid.UUID

	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop]
	Links       datatypes.JSONSlice[Link]

	IncludeAll        datatypes.JSONType[*IncludeAll]
	IncludeObjectives []SelectObjectiveById `gorm:"Polymorphic:Parent;polymorphicValue:included"`
	ExcludeObjectives []SelectObjectiveById `gorm:"Polymorphic:Parent;polymorphicValue:excluded"`
}

func (i *ControlObjectiveSelection) UnmarshalOscal(op oscalTypes_1_1_3.ReferencedControlObjectives) *ControlObjectiveSelection {
	*i = ControlObjectiveSelection{}
	return i
}

func (i *ControlObjectiveSelection) MarshalOscal() *oscalTypes_1_1_3.ReferencedControlObjectives {
	ret := oscalTypes_1_1_3.ReferencedControlObjectives{}
	return &ret
}

type SelectObjectiveById struct { // We should figure out what this looks like for real, because this references objectives hidden in `part`s of a control
	UUIDModel
	Objective string // required

	ParentID   uuid.UUID
	ParentType string
}

func (i *SelectObjectiveById) UnmarshalOscal(op oscalTypes_1_1_3.SelectObjectiveById) *SelectObjectiveById {
	*i = SelectObjectiveById{}
	return i
}

func (i *SelectObjectiveById) MarshalOscal() *oscalTypes_1_1_3.SelectObjectiveById {
	ret := oscalTypes_1_1_3.SelectObjectiveById{}
	return &ret
}
