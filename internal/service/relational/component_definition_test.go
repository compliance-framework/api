package relational

import (
	"encoding/json"
	"testing"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestControlStatementImplementationMarshalUnmarshal(t *testing.T) {
	data := oscalTypes_1_1_3.ControlStatementImplementation{
		UUID:        uuid.New().String(),
		StatementId: "statement-1",
		Description: "Test statement description",
		Remarks:     "Test statement remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "statement-prop-name",
				Value: "statement-prop-value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "http://statement-link",
				MediaType: "application/json",
				Text:      "Statement Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:     "role-1",
				Remarks:    "Test role remarks",
				PartyUuids: &[]string{uuid.New().String()},
				Links: &[]oscalTypes_1_1_3.Link{
					{
						Href:      "http://role-link",
						MediaType: "application/json",
						Text:      "Role Link",
					},
				},
				Props: &[]oscalTypes_1_1_3.Property{
					{
						Name:  "role-prop-name",
						Value: "role-prop-value",
					},
				},
			},
		},
	}

	inputJson, err := json.Marshal(data)
	assert.NoError(t, err)

	csi := &ControlStatementImplementation{}
	csi.UnmarshalOscal(data)
	output := csi.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)

	assert.JSONEq(t, string(inputJson), string(outputJson))
}
