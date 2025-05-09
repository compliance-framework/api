package relational

import (
	"encoding/json"
	"testing"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestControlStatementImplementationMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.ControlStatementImplementation
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.ControlStatementImplementation{
				UUID:        uuid.New().String(),
				StatementId: "statement-1",
				Description: "desc",
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.ControlStatementImplementation{
				UUID:        uuid.New().String(),
				StatementId: "statement-2",
				Description: "desc2",
				Remarks:     "remarks",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "p", Value: "v"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://link", MediaType: "application/json", Text: "Link"},
				},
				ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
					{
						RoleId:     "role-1",
						Remarks:    "role remarks",
						PartyUuids: &[]string{uuid.New().String()},
						Links: &[]oscalTypes_1_1_3.Link{
							{Href: "http://role-link", MediaType: "application/json", Text: "Role Link"},
						},
						Props: &[]oscalTypes_1_1_3.Property{
							{Name: "role-prop-name", Value: "role-prop-value"},
						},
					},
				},
			},
		},
		{
			name: "with only responsible roles",
			data: oscalTypes_1_1_3.ControlStatementImplementation{
				UUID:        uuid.New().String(),
				StatementId: "statement-3",
				Description: "desc3",
				ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
					{RoleId: "role-2"},
				},
			},
		},
		// Add more cases as needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			csi := &ControlStatementImplementation{}
			csi.UnmarshalOscal(tt.data)
			output := csi.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}
