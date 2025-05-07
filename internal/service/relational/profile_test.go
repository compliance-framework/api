package relational

import (
	"encoding/json"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestImport_MarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Import
	}{
		{
			name: "with include-all set",
			data: oscalTypes_1_1_3.Import{
				Href:       "#/definition/123456",
				IncludeAll: &oscalTypes_1_1_3.IncludeAll{},
			},
		},
		{
			name: "without include-all set",
			data: oscalTypes_1_1_3.Import{
				Href: "#/definition/123456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize the OSCAL type to JSON
			inputJSON, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			// Round-trip through internal model
			imp := Import{}
			imp.UnmarshalOscal(tt.data)
			output := imp.MarshalOscal()
			outputJSON, err := json.Marshal(output)
			assert.NoError(t, err)

			// Deep-compare JSON
			assert.JSONEq(t, string(inputJSON), string(outputJSON))
		})
	}
}
