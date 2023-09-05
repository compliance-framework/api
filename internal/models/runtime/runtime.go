package runtime

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// RuntimeConfigurationJobPayload defines the payload sent to the runtime on calling initial_configuration API. It is a response model, rather than a database model.
type RuntimeConfigurationJobPayload struct {
	Uuid         string               `json:"uuid" query:"uuid"`
	RuntimeUuid  string               `json:"runtime-id"`
	SspId        string               `json:"ssp-id,omitempty"`
	AssessmentId string               `json:"assessment-id"`
	TaskId       string               `json:"task-id"`
	ActivityId   string               `json:"activity-id,omitempty"`
	SubjectId    string               `json:"subject-id,omitempty"`
	ControlId    string               `json:"control-id,omitempty"`
	Schedule     string               `json:"schedule"`
	Plugins      []*RuntimePlugin     `json:"plugins,omitempty"`
	Parameters   []*RuntimeParameters `json:"parameters,omitempty"` // A copy-paste of Subject properties, control properties, task properties, etc.
}

// RuntimeConfigurationJobRequest is the request payload for assignJobs
type RuntimeConfigurationJobRequest struct {
	RuntimeUuid string `json:"runtime-id"`
	Limit       int    `json:"limit"`
}

// RuntimeConfigurationJob defines the database representation of a runtime job. It is the source of information for the RuntimeConfigurationPayload
type RuntimeConfigurationJob struct {
	Uuid              string                   `json:"uuid"`
	ConfigurationUuid string                   `json:"configuration-uuid"`
	AssessmentId      string                   `json:"assessment-id"`
	TaskId            string                   `json:"task-id"`
	ControlId         string                   `json:"control-id,omitempty"`
	RuntimeUuid       string                   `json:"runtime-uuid,omitempty"`
	ActivityId        string                   `json:"activity-id,omitempty"`
	SubjectUuid       string                   `json:"subject-uuid,omitempty"`
	SubjectType       string                   `json:"subject-type,omitempty"`
	Schedule          string                   `json:"schedule,omitempty"`
	Plugins           []*RuntimePluginSelector `json:"plugins,omitempty"`
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

// RuntimeConfiguration defines that a given Task on an AssessmentPlan will be assessed by a plugin. It is a template because multiple subjects might be assessed.
type RuntimeConfiguration struct {
	Uuid               string `json:"uuid" query:"uuid"`
	AssessmentPlanUuid string `json:"assessment-plan-uuid"`
	TaskUuid           string `json:"task-uuid"`
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
