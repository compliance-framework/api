package runtime

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

type AssessmentResults struct {
	Id           string
	AssessmentId string            `json:"AssessmentId"`
	Outputs      map[string]Output `json:"Outputs"`
}

func (c *AssessmentResults) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *AssessmentResults) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *AssessmentResults) DeepCopy() schema.BaseModel {
	d := &AssessmentResults{}
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

func (c *AssessmentResults) UUID() string {
	return c.Id
}

func (c *AssessmentResults) Validate() error {
	return nil
}

func (c *AssessmentResults) Type() string {
	return "AssessmentResults"
}
