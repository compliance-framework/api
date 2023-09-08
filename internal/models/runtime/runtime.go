package runtime

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

type PayloadEventType string

const (
	PayloadEventUpdated PayloadEventType = "updated"
	PayloadEventCreated PayloadEventType = "created"
	PayloadEventDeleted PayloadEventType = "deleted"
)

type RuntimeConfigurationJobPayload struct {
	Topic string `json:"topic"`
	RuntimeConfigurationEvent
}
type RuntimeConfigurationEvent struct {
	Uuid string                   `json:"uuid"`
	Type PayloadEventType         `json:"type"`
	Data *RuntimeConfigurationJob `json:"data"`
}

// RuntimeConfigurationJobRequest is the request payload for assignJobs
type RuntimeConfigurationJobRequest struct {
	RuntimeUuid string `json:"runtime-id"`
	Limit       int    `json:"limit"`
}

// RuntimeConfigurationJob defines the database representation of a runtime job. It is the source of information for the RuntimeConfigurationPayload
type RuntimeConfigurationJob struct {
	Uuid              string                   `json:"uuid" query:"uuid"`
	RuntimeUuid       string                   `json:"runtime-uuid"`
	TargetSubjects    []*TargetSubject         `json:"target-subjects"`
	TaskUuid          string                   `json:"task-uuid"`
	Schedule          string                   `json:"schedule"`
	Plugins           []*RuntimePluginSelector `json:"plugins"`
	ConfigurationUuid string                   `json:"configuration-uuid"`
	AssessmentId      string                   `json:"assessment-id"`
	ControlId         string                   `json:"control-id,omitempty"`
	ActivityId        string                   `json:"activity-id,omitempty"`
	Parameters        []*RuntimeParameters     `json:"parameters,omitempty"` // A copy-paste of Subject properties, control properties, task properties, etc.
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *RuntimeConfigurationJob) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *RuntimeConfigurationJob) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *RuntimeConfigurationJob) DeepCopy() schema.BaseModel {
	d := &RuntimeConfigurationJob{}
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

func (c *RuntimeConfigurationJob) UUID() string {
	return c.Uuid
}

func (c *RuntimeConfigurationJob) Validate() error {
	return nil
}

func (c *RuntimeConfigurationJob) Type() string {
	return "jobs"
}

// TargetSubject relates how to select a given subject for the runtime to create jobs
type TargetSubject struct {
	MatchQuery       string             `json:"match-query,omitempty"`
	MatchLabels      map[string]string  `json:"match-labels,omitempty"`
	MatchExpressions []*MatchExpression `json:"match-expressions,omitempty"`
	FromAssessment   *FromAssessment    `json:"direct-match,omitempty"`
}
type FromAssessment struct {
	Subjects []*Subject `json:"subjects"`
}

type Subject struct {
	SubjectUuid string `json:"subject-uuid,omitempty"`
	SubjectType string `json:"subject-type,omitempty"`
}

type MatchExpression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// RuntimeConfiguration defines that a given Task on an AssessmentPlan will be assessed by a plugin. It is a template because multiple subjects might be assessed.
type RuntimeConfiguration struct {
	Uuid               string           `json:"uuid" query:"uuid"`
	AssessmentPlanUuid string           `json:"assessment-plan-uuid"`
	RuntimeUuid        string           `json:"runtime-uuid"`
	TargetSubjects     []*TargetSubject `json:"target-subjects"`
	TaskUuid           string           `json:"task-uuid"`
	// For simplicity, all activities in a task are going to be assessed.
	//Activities         []*oscal.AssociatedActivity `json:"activities"`
	Schedule string                   `json:"schedule"`
	Plugins  []*RuntimePluginSelector `json:"plugins"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *RuntimeConfiguration) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *RuntimeConfiguration) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *RuntimeConfiguration) DeepCopy() schema.BaseModel {
	d := &RuntimeConfiguration{}
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

func (c *RuntimeConfiguration) UUID() string {
	return c.Uuid
}

func (c *RuntimeConfiguration) Validate() error {
	return nil
}

func (c *RuntimeConfiguration) Type() string {
	return "configurations"
}

// RuntimePluginSelector references a plugin uuid
type RuntimePluginSelector struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// RuntimePlugin defines a plugin configuration storage. TBD if authentication information would reside here or not.
type RuntimePlugin struct {
	Uuid          string               `json:"uuid"`
	Name          string               `json:"name"`
	Package       string               `json:"package"`
	Version       string               `json:"version"`
	Configuration []*RuntimeParameters `json:"configuration"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *RuntimePlugin) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *RuntimePlugin) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *RuntimePlugin) DeepCopy() schema.BaseModel {
	d := &RuntimePlugin{}
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

func (c *RuntimePlugin) UUID() string {
	return c.Uuid
}

func (c *RuntimePlugin) Validate() error {
	return nil
}

func (c *RuntimePlugin) Type() string {
	return "plugins"
}

// RuntimeParameters are the parameters related to Controls,Assessements,Subjects, etc. to run the assessment.
type RuntimeParameters struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Runtime struct {
	Uuid   string `json:"uuid"`
	Name   string `json:"name"`
	Key    string `json:"key"`
	Secret string `json:"secret"` //TODO Properly use authentication. this is just a placeholder and should not be used
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *Runtime) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *Runtime) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Runtime) DeepCopy() schema.BaseModel {
	d := &Runtime{}
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

func (c *Runtime) UUID() string {
	return c.Uuid
}

func (c *Runtime) Validate() error {
	return nil
}

func (c *Runtime) Type() string {
	return "runtimes"
}
