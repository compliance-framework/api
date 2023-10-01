package process

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

type Observation struct {
	SubjectId   string `json:"subject-id"`
	Description string `json:"description"` // Holds the observation text (couldn't find a better name)
}

type Risk struct {
	SubjectId   string `json:"subject-id"`
	Description string `json:"description"` // Holds the risk text
	Impact      string `json:"impact"`      // Holds the impact text
}

type JobResult struct {
	Uuid         string `json:"uuid"`
	JobId        string `json:"id"`
	RuntimeId    string `json:"runtime-id"` // only if the control-plane doesn't listen to runtime specific topic
	AssessmentId string `json:"assessment-id"`
	ActivityId   string `json:"activity-id"`
	Observations []*Observation
	Risks        []*Risk
}

func (c *JobResult) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *JobResult) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *JobResult) DeepCopy() schema.BaseModel {
	d := &JobResult{}
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

func (c *JobResult) UUID() string {
	return c.Uuid
}

func (c *JobResult) Validate() error {
	return nil
}

func (c *JobResult) Type() string {
	return "job-result"
}
