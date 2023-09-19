package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var aresult = &AssessmentResult{
	Uuid:         "uuid-123",
	AssessmentId: "assId456",
	Outputs: map[string]Output{
		"output1": {
			ResultData: ResultData{
				Message: "Message1",
			},
		},
	},
}

func TestToAndFromJson(t *testing.T) {

	jsonData, err := aresult.ToJSON()
	assert.NoError(t, err)

	var deserialisedAssessmentResult AssessmentResult
	err = deserialisedAssessmentResult.FromJSON(jsonData)
	assert.NoError(t, err)

	assert.Equal(t, aresult, &deserialisedAssessmentResult)

}

func TestDeepCopy(t *testing.T) {

	copy := aresult.DeepCopy().(*AssessmentResult)

	assert.Equal(t, aresult, copy)

}

func TestUUID(t *testing.T) {

	assert.Equal(t, "uuid-123", aresult.UUID())

}

func TestValidate(t *testing.T) {

	assert.NoError(t, aresult.Validate())

}

func TestType(t *testing.T) {

	assert.Equal(t, "assessment-result", aresult.Type())

}
