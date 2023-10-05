package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var aresult = &JobResult{
	Uuid:         "uuid-123",
	AssessmentId: "assId456",
	Observations: []*Observation{
		{
			SubjectId:   "123",
			Description: "456",
		},
	},
	Risks: []*Risk{{
		SubjectId:   "123",
		Description: "foo",
		Impact:      "HIGH",
	}},
}

func TestToAndFromJson(t *testing.T) {

	jsonData, err := aresult.ToJSON()
	assert.NoError(t, err)

	var deserialisedAssessmentResult JobResult
	err = deserialisedAssessmentResult.FromJSON(jsonData)
	assert.NoError(t, err)

	assert.Equal(t, aresult, &deserialisedAssessmentResult)

}

func TestDeepCopy(t *testing.T) {

	copy := aresult.DeepCopy().(*JobResult)

	assert.Equal(t, aresult, copy)

}

func TestUUID(t *testing.T) {

	assert.Equal(t, "uuid-123", aresult.UUID())

}

func TestValidate(t *testing.T) {

	assert.NoError(t, aresult.Validate())

}

func TestType(t *testing.T) {

	assert.Equal(t, "job-result", aresult.Type())

}
