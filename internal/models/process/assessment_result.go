package process

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

type ResultData struct {
	Message string `json:"message"`
}
type Output struct {
	ResultData ResultData `json:"ResultData"`
}

type AssessmentResult struct {
	Uuid         string            `json:"Uuid"`
	AssessmentId string            `json:"AssessmentId"`
	Outputs      map[string]Output `json:"Outputs"`
}

func (c *AssessmentResult) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *AssessmentResult) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *AssessmentResult) DeepCopy() schema.BaseModel {
	d := &AssessmentResult{}
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

func (c *AssessmentResult) UUID() string {
	return c.Uuid
}

func (c *AssessmentResult) Validate() error {
	return nil
}

func (c *AssessmentResult) Type() string {
	return "assessment-result"
}
