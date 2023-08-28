package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/jsonschema"
	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// AssessedControls Identifies the controls being assessed. In the assessment plan, these are the planned controls. In the assessment results, these are the actual controls, and reflects any changes from the plan.
type AssessedControls struct {

	// A human-readable description of in-scope controls specified for assessment.
	Description     string                     `json:"description,omitempty"`
	ExcludeControls []*AssessmentSelectControl `json:"exclude-controls,omitempty"`
	IncludeAll      *IncludeAll                `json:"include-all,omitempty"`
	IncludeControls []*AssessmentSelectControl `json:"include-controls,omitempty"`
	Links           []*Link                    `json:"links,omitempty"`
	Props           []*Property                `json:"props,omitempty"`
	Remarks         string                     `json:"remarks,omitempty"`
}

// AssessmentAssets Identifies the assets used to perform this assessment, such as the assessment team, scanning tools, and assumptions.
type AssessmentAssets struct {
	AssessmentPlatforms []*AssessmentPlatform    `json:"assessment-platforms"`
	Components          []*CommonSystemComponent `json:"components,omitempty"`
}

// AssessmentPlanTermsAndConditions Used to define various terms and conditions under which an assessment, described by the plan, can be performed. Each child part defines a different type of term or condition.
type AssessmentPlanTermsAndConditions struct {
	Parts []*CommonAssessmentPart `json:"parts,omitempty"`
}

// AssessmentPlatform Used to represent the toolset used to perform aspects of the assessment.
type AssessmentPlatform struct {
	Links   []*Link     `json:"links,omitempty"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`

	// The title or name for the assessment platform.
	Title          string           `json:"title,omitempty"`
	UsesComponents []*UsesComponent `json:"uses-components,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this assessment platform elsewhere in this or other OSCAL instances. The locally defined UUID of the assessment platform can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// AssociatedActivity Identifies an individual activity to be performed as part of a task.
type AssociatedActivity struct {

	// A machine-oriented identifier reference to an activity defined in the list of activities.
	ActivityUuid     string               `json:"activity-uuid"`
	Links            []*Link              `json:"links,omitempty"`
	Props            []*Property          `json:"props,omitempty"`
	Remarks          string               `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole   `json:"responsible-roles,omitempty"`
	Subjects         []*AssessmentSubject `json:"subjects"`
}

// EventTiming The timing under which the task is intended to occur.
type EventTiming struct {

	// The task is intended to occur at the specified frequency.
	AtFrequency *FrequencyCondition `json:"at-frequency,omitempty"`

	// The task is intended to occur on the specified date.
	OnDate *OnDateCondition `json:"on-date,omitempty"`

	// The task is intended to occur within the specified date range.
	WithinDateRange *OnDateRangeCondition `json:"within-date-range,omitempty"`
}

// FrequencyCondition The task is intended to occur at the specified frequency.
type FrequencyCondition struct {

	// The task must occur after the specified period has elapsed.
	Period int `json:"period"`

	// The unit of time for the period.
	Unit string `json:"unit"`
}

// IdentifiedSubject Used to detail assessment subjects that were identfied by this task.
type IdentifiedSubject struct {

	// A machine-oriented identifier reference to a unique assessment subject placeholder defined by this task.
	SubjectPlaceholderUuid string               `json:"subject-placeholder-uuid"`
	Subjects               []*AssessmentSubject `json:"subjects"`
}

// IdentifiesTheSubject A human-oriented identifier reference to a resource. Use type to indicate whether the identified resource is a component, inventory item, location, user, or something else.
type IdentifiesTheSubject struct {
	Links   []*Link     `json:"links,omitempty"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`

	// A machine-oriented identifier reference to a component, inventory-item, location, party, user, or resource using it's UUID.
	SubjectUuid string `json:"subject-uuid"`

	// The title or name for the referenced subject.
	Title string `json:"title,omitempty"`

	// Used to indicate the type of object pointed to by the uuid-ref within a subject.
	Type interface{} `json:"type"`
}

// ImportSystemSecurityPlan Used by the assessment plan and POA&M to import information about the system.
type ImportSystemSecurityPlan struct {

	// A resolvable URL reference to the system security plan for the system being assessed.
	Href    string `json:"href"`
	Remarks string `json:"remarks,omitempty"`
}

// LocalDefinitions Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
type LocalDefinitions struct {
	Activities           []*CommonActivity        `json:"activities,omitempty"`
	Components           []*CommonSystemComponent `json:"components,omitempty"`
	InventoryItems       []*CommonInventoryItem   `json:"inventory-items,omitempty"`
	ObjectivesAndMethods []*CommonLocalObjective  `json:"objectives-and-methods,omitempty"`
	Remarks              string                   `json:"remarks,omitempty"`
	Users                []*CommonSystemUser      `json:"users,omitempty"`
}

// OnDateCondition The task is intended to occur on the specified date.
type OnDateCondition struct {

	// The task must occur on the specified date.
	Date string `json:"date"`
}

// OnDateRangeCondition The task is intended to occur within the specified date range.
type OnDateRangeCondition struct {

	// The task must occur on or before the specified date.
	End string `json:"end"`

	// The task must occur on or after the specified date.
	Start string `json:"start"`
}

// CommonActivity Identifies an assessment or related process that can be performed. In the assessment plan, this is an intended activity which may be associated with an assessment task. In the assessment results, this an activity that was actually performed as part of an assessment.
type CommonActivity struct {

	// A human-readable description of this included activity.
	Description      string                                `json:"description"`
	Links            []*Link                               `json:"links,omitempty"`
	Props            []*Property                           `json:"props,omitempty"`
	RelatedControls  *ReviewedControlsAndControlObjectives `json:"related-controls,omitempty"`
	Remarks          string                                `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole                    `json:"responsible-roles,omitempty"`
	Steps            []*Step                               `json:"steps,omitempty"`

	// The title for this included activity.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this assessment activity elsewhere in this or other OSCAL instances. The locally defined UUID of the activity can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// CommonAssessmentPart A partition of an assessment plan or results or a child of another part.
type CommonAssessmentPart struct {

	// A textual label that provides a sub-type or characterization of the part's name. This can be used to further distinguish or discriminate between the semantics of multiple parts of the same control with the same name and ns.
	Class string  `json:"class,omitempty"`
	Links []*Link `json:"links,omitempty"`

	// A textual label that uniquely identifies the part's semantic type.
	Name interface{} `json:"name"`

	// A namespace qualifying the part's name. This allows different organizations to associate distinct semantics with the same name.
	Ns    string                  `json:"ns,omitempty"`
	Parts []*CommonAssessmentPart `json:"parts,omitempty"`
	Props []*Property             `json:"props,omitempty"`

	// Permits multiple paragraphs, lists, tables etc.
	Prose string `json:"prose,omitempty"`

	// A name given to the part, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this part elsewhere in this or other OSCAL instances. The locally defined UUID of the part can be used to reference the data item locally or globally (e.g., in an ported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid,omitempty"`
}

// AssessmentSubject Identifies system elements being assessed, such as components, inventory items, and locations. In the assessment plan, this identifies a planned assessment subject. In the assessment results this is an actual assessment subject, and reflects any changes from the plan. exactly what will be the focus of this assessment. Any subjects not identified in this way are out-of-scope.
type AssessmentSubject struct {

	// A human-readable description of the collection of subjects being included in this assessment.
	Description     string                     `json:"description,omitempty"`
	ExcludeSubjects []*SelectAssessmentSubject `json:"exclude-subjects,omitempty"`
	IncludeAll      *IncludeAll                `json:"include-all,omitempty"`
	IncludeSubjects []*SelectAssessmentSubject `json:"include-subjects,omitempty"`
	Links           []*Link                    `json:"links,omitempty"`
	Props           []*Property                `json:"props,omitempty"`
	Remarks         string                     `json:"remarks,omitempty"`

	// Indicates the type of assessment subject, such as a component, inventory, item, location, or party represented by this selection statement.
	Type interface{} `json:"type"`
}

// CommonLocalObjective A local definition of a control objective for this assessment. Uses catalog syntax for control objective and assessment actions.
type CommonLocalObjective struct {

	// A reference to a control with a corresponding id value. When referencing an externally defined control, the Control Identifier Reference must be used in the context of the external / imported OSCAL instance (e.g., uri-reference).
	ControlId string `json:"control-id"`

	// A human-readable description of this control objective.
	Description string      `json:"description,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Parts       []*Part     `json:"parts"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
}

// CommonSelectObjectiveById Used to select a control objective for inclusion/exclusion based on the control objective's identifier.
type CommonSelectObjectiveById struct {

	// Points to an assessment objective.
	ObjectiveId string `json:"objective-id"`
}

// ImplementationCommonProtocol Information about the protocol used to provide a service.
type ImplementationCommonProtocol struct {

	// The common name of the protocol, which should be the appropriate "service name" from the IANA Service Name and Transport Protocol Port Number Registry.
	Name       string       `json:"name"`
	PortRanges []*PortRange `json:"port-ranges,omitempty"`

	// A human readable name for the protocol (e.g., Transport Layer Security).
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this service protocol information elsewhere in this or other OSCAL instances. The locally defined UUID of the service protocol can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid,omitempty"`
}

// CommonSystemComponent A defined component that can be part of an implemented system.
type CommonSystemComponent struct {

	// A description of the component, including information about its function.
	Description string                          `json:"description"`
	Links       []*Link                         `json:"links,omitempty"`
	Props       []*Property                     `json:"props,omitempty"`
	Protocols   []*ImplementationCommonProtocol `json:"protocols,omitempty"`

	// A summary of the technological or business purpose of the component.
	Purpose          string             `json:"purpose,omitempty"`
	Remarks          string             `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole `json:"responsible-roles,omitempty"`

	// Describes the operational status of the system component.
	Status *Status `json:"status"`

	// A human readable name for the system component.
	Title string `json:"title"`

	// A category describing the purpose of the component.
	Type interface{} `json:"type"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this component elsewhere in this or other OSCAL instances. The locally defined UUID of the component can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// PortRange Where applicable this is the IPv4 port range on which the service operates.
type PortRange struct {

	// Indicates the ending port number in a port range
	End interface{} `json:"end,omitempty"`

	// Indicates the starting port number in a port range
	Start interface{} `json:"start,omitempty"`

	// Indicates the transport type.
	Transport interface{} `json:"transport,omitempty"`
}

// ReferencedControlObjectives Identifies the control objectives of the assessment. In the assessment plan, these are the planned objectives. In the assessment results, these are the assessed objectives, and reflects any changes from the plan.
type ReferencedControlObjectives struct {

	// A human-readable description of this collection of control objectives.
	Description       string                       `json:"description,omitempty"`
	ExcludeObjectives []*CommonSelectObjectiveById `json:"exclude-objectives,omitempty"`
	IncludeAll        *IncludeAll                  `json:"include-all,omitempty"`
	IncludeObjectives []*CommonSelectObjectiveById `json:"include-objectives,omitempty"`
	Links             []*Link                      `json:"links,omitempty"`
	Props             []*Property                  `json:"props,omitempty"`
	Remarks           string                       `json:"remarks,omitempty"`
}

// ReviewedControlsAndControlObjectives Identifies the controls being assessed and their control objectives.
type ReviewedControlsAndControlObjectives struct {
	ControlObjectiveSelections []*ReferencedControlObjectives `json:"control-objective-selections,omitempty"`
	ControlSelections          []*AssessedControls            `json:"control-selections"`

	// A human-readable description of control objectives.
	Description string      `json:"description,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
}

// SelectAssessmentSubject Identifies a set of assessment subjects to include/exclude by UUID.
type SelectAssessmentSubject struct {
	Links   []*Link     `json:"links,omitempty"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`

	// A machine-oriented identifier reference to a component, inventory-item, location, party, user, or resource using it's UUID.
	SubjectUuid string `json:"subject-uuid"`

	// Used to indicate the type of object pointed to by the uuid-ref within a subject.
	Type interface{} `json:"type"`
}

// SelectControl Used to select a control for inclusion/exclusion based on one or more control identifiers. A set of statement identifiers can be used to target the inclusion/exclusion to only specific control statements providing more granularity over the specific statements that are within the asessment scope.
type AssessmentSelectControl struct {

	// A reference to a control with a corresponding id value. When referencing an externally defined control, the Control Identifier Reference must be used in the context of the external / imported OSCAL instance (e.g., uri-reference).
	ControlId    string   `json:"control-id"`
	StatementIds []string `json:"statement-ids,omitempty"`
}

// Step Identifies an individual step in a series of steps related to an activity, such as an assessment test or examination procedure.
type Step struct {

	// A human-readable description of this step.
	Description      string                                `json:"description"`
	Links            []*Link                               `json:"links,omitempty"`
	Props            []*Property                           `json:"props,omitempty"`
	Remarks          string                                `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole                    `json:"responsible-roles,omitempty"`
	ReviewedControls *ReviewedControlsAndControlObjectives `json:"reviewed-controls,omitempty"`

	// The title for this step.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this step elsewhere in this or other OSCAL instances. The locally defined UUID of the step (in a series of steps) can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// Task Represents a scheduled event or milestone, which may be associated with a series of assessment actions.
type Task struct {
	AssociatedActivities []*AssociatedActivity `json:"associated-activities,omitempty"`
	Dependencies         []*TaskDependency     `json:"dependencies,omitempty"`

	// A human-readable description of this task.
	Description      string               `json:"description,omitempty"`
	Links            []*Link              `json:"links,omitempty"`
	Props            []*Property          `json:"props,omitempty"`
	Remarks          string               `json:"remarks,omitempty"`
	ResponsibleRoles []*ResponsibleRole   `json:"responsible-roles,omitempty"`
	Subjects         []*AssessmentSubject `json:"subjects,omitempty"`
	Tasks            []*Task              `json:"tasks,omitempty"`

	// The timing under which the task is intended to occur.
	Timing *EventTiming `json:"timing,omitempty"`

	// The title for this task.
	Title string `json:"title"`

	// The type of task.
	Type interface{} `json:"type"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this task elsewhere in this or other OSCAL instances. The locally defined UUID of the task can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// TaskDependency Used to indicate that a task is dependent on another task.
type TaskDependency struct {
	Remarks string `json:"remarks,omitempty"`

	// A machine-oriented identifier reference to a unique task.
	TaskUuid string `json:"task-uuid"`
}

// UsesComponent The set of components that are used by the assessment platform.
type UsesComponent struct {

	// A machine-oriented identifier reference to a component that is implemented as part of an inventory item.
	ComponentUuid      string              `json:"component-uuid"`
	Links              []*Link             `json:"links,omitempty"`
	Props              []*Property         `json:"props,omitempty"`
	Remarks            string              `json:"remarks,omitempty"`
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`
}

// OscalApOscalApAssessmentPlan An assessment plan, such as those provided by a FedRAMP assessor.
type AssessmentPlan struct {
	AssessmentAssets   *AssessmentAssets         `json:"assessment-assets,omitempty"`
	AssessmentSubjects []*AssessmentSubject      `json:"assessment-subjects,omitempty"`
	BackMatter         *BackMatter               `json:"back-matter,omitempty"`
	ImportSsp          *ImportSystemSecurityPlan `json:"import-ssp"`

	// Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
	LocalDefinitions *LocalDefinitions                     `json:"local-definitions,omitempty"`
	Metadata         map[string]interface{}                `json:"metadata"`
	ReviewedControls *ReviewedControlsAndControlObjectives `json:"reviewed-controls"`
	Tasks            []*Task                               `json:"tasks,omitempty"`

	// Used to define various terms and conditions under which an assessment, described by the plan, can be performed. Each child part defines a different type of term or condition.
	TermsAndConditions *AssessmentPlanTermsAndConditions `json:"terms-and-conditions,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this assessment plan in this or other OSCAL instances. The locally defined UUID of the assessment plan can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *AssessmentPlan) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *AssessmentPlan) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *AssessmentPlan) DeepCopy() schema.BaseModel {
	d := &AssessmentPlan{}
	p, err := c.ToJSON()
	if err != nil {
		panic(err)
	}
	err = d.FromJSON(p)
	if err != nil {
		panic(err)
	}
	return d
}

func (c *AssessmentPlan) UUID() string {
	return c.Uuid
}

// TODO Add tests
func (c *AssessmentPlan) Validate() error {

	sch, err := jsonschema.Compile("https://github.com/usnistgov/OSCAL/releases/download/v1.1.0/oscal_assessment-plan_schema.json")
	if err != nil {
		return err
	}
	var p = map[string]interface{}{
		"assessment-plan": c,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = json.Unmarshal(d, &p)
	if err != nil {
		return err
	}
	return sch.Validate(p)
}

func init() {
	schema.MustRegister("assessment-plan", &AssessmentPlan{})
}
