package relational

import (
	"encoding/json"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestAssessmentResult_OscalMarshalling(t *testing.T) {
	// This test is commented as observations, findings and risks are not yet implemented
	t.Run("Full Assessment Result", func(t *testing.T) {
		f, err := os.Open("./testdata/full_ar.json")
		assert.NoError(t, err)
		defer f.Close()

		embed := struct {
			Results oscalTypes_1_1_3.AssessmentResults `json:"assessment-results"`
		}{}
		err = json.NewDecoder(f).Decode(&embed)
		assert.NoError(t, err)

		inputJson, err := json.Marshal(embed.Results)
		assert.NoError(t, err)

		ssp := &AssessmentResult{}
		// Use a random UUID for the catalogId parameter
		ssp.UnmarshalOscal(embed.Results)
		output := ssp.MarshalOscal()
		outputJson, err := json.Marshal(output)
		assert.NoError(t, err)
		assert.JSONEq(t, string(inputJson), string(outputJson))
	})
}
