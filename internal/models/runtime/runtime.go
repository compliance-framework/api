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

type Activity struct {
	Id         string               `yaml:"id" json:"id"`
	Selector   *Selector            `json:"selector"`
	ControlId  string               `yaml:"control-id,omitempty" json:"control-id,omitempty"`
	Plugins    []*RuntimePlugin     `yaml:"plugins,omitempty" json:"plugins,omitempty"`
	Parameters []*RuntimeParameters `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type Selector struct {
	Query       string            `yaml:"query" json:"query"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Expressions []MatchExpression `yaml:"expressions,omitempty" json:"expressions,omitempty"`
	Ids         []string          `yaml:"ids,omitempty" json:"ids,omitempty"`
}
type RuntimeConfigurationJob struct {
	Uuid              string      `yaml:"uuid" json:"uuid" query:"uuid"`
	RuntimeUuid       string      `yaml:"runtime-id" json:"runtime-id"`
	ConfigurationUuid string      `json:"configuration-uuid"`
	SspId             string      `yaml:"ssp-id,omitempty" json:"ssp-id,omitempty"`
	AssessmentId      string      `yaml:"assessment-id" json:"assessment-id"`
	TaskId            string      `yaml:"task-id" json:"task-id"`
	Schedule          string      `yaml:"schedule" json:"schedule"`
	Activities        []*Activity `yaml:"activities,omitempty" json:"activities,omitempty"`
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

type MatchExpression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// RuntimeConfiguration defines that a given Task on an AssessmentPlan will be assessed by a plugin. It is a template because multiple subjects might be assessed.
type RuntimeConfiguration struct {
	Uuid               string    `json:"uuid" query:"uuid"`
	AssessmentPlanUuid string    `json:"assessment-plan-uuid"`
	RuntimeUuid        string    `json:"runtime-uuid"`
	TaskUuid           string    `json:"task-uuid"`
	PluginUuids        []string  `json:"plugin-uuids,omitempty"`
	Selector           *Selector `json:"selector"`
	Schedule           string    `json:"schedule"`
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
