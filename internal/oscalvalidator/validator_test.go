package oscalvalidator

import (
	"reflect"
	"testing"
	"time"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Factory function to create a basic test SSP
func createValidSSP() *oscalTypes_1_1_3.SystemSecurityPlan {
	sspUUID := uuid.New().String()
	now := time.Now()

	componentUUID := uuid.New().String()

	return &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspUUID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Test System Security Plan",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
			Parties: &[]oscalTypes_1_1_3.Party{
				{
					UUID: uuid.New().String(),
					Type: "organization",
					Name: "Test Organization",
				},
			},
			Locations: &[]oscalTypes_1_1_3.Location{
				{
					UUID: uuid.New().String(),
					EmailAddresses: &[]string{
						"test@test.com",
					},
				},
			},
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{
			Href: "nil",
		},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName:               "Test System",
			SystemNameShort:          "TESTSYS",
			Description:              "A test system for integration testing",
			SecuritySensitivityLevel: "high",
			SystemIds: []oscalTypes_1_1_3.SystemId{
				{
					IdentifierType: "https://ietf.org/rfc/rfc4122",
					ID:             uuid.New().String(),
				},
			},
			Status: oscalTypes_1_1_3.Status{
				State: "operational",
			},
			SystemInformation: oscalTypes_1_1_3.SystemInformation{
				InformationTypes: []oscalTypes_1_1_3.InformationType{
					{
						UUID:        uuid.New().String(),
						Title:       "Test Information Type",
						Description: "Test information type for testing",
					},
				},
			},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Users: []oscalTypes_1_1_3.SystemUser{
				{
					UUID:    uuid.New().String(),
					Title:   "System Administrator",
					RoleIds: &[]string{"system-admin", "security-admin"},
					AuthorizedPrivileges: &[]oscalTypes_1_1_3.AuthorizedPrivilege{
						{
							Title:              "Full Administrative Access",
							FunctionsPerformed: []string{"system-administration", "security-management"},
						},
					},
				},
			},
			Components: []oscalTypes_1_1_3.SystemComponent{
				{
					UUID:        componentUUID,
					Type:        "software",
					Title:       "Test Application",
					Description: "Test application component",
					Status: oscalTypes_1_1_3.SystemComponentStatus{
						State: "operational",
					},
				},
			},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "Control implementation for test system",
			ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
				{
					UUID:      uuid.New().String(),
					ControlId: "ac-1",
					Statements: &[]oscalTypes_1_1_3.Statement{
						{
							StatementId: "ac-1_stmt.a",
							UUID:        uuid.New().String(),
							Remarks:     "Test statement implementation",
						},
					},
				},
			},
		},
	}
}

func createInvalidSSP() *oscalTypes_1_1_3.SystemSecurityPlan {
	sspUUID := uuid.New().String()
	now := time.Now()

	componentUUID := uuid.New().String()

	return &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspUUID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Test System Security Plan",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
			Parties: &[]oscalTypes_1_1_3.Party{
				{
					UUID: uuid.New().String(),
					Type: "organization",
					Name: "Test Organization",
				},
			},
			Locations: &[]oscalTypes_1_1_3.Location{
				{
					UUID: uuid.New().String(),
					EmailAddresses: &[]string{
						"test@test.com",
						"wrong",
					},
				},
			},
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{
			Href: "nil",
		},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName:               "Test System",
			SystemNameShort:          "TESTSYS",
			Description:              "A test system for integration testing",
			SecuritySensitivityLevel: "high",
			SystemIds: []oscalTypes_1_1_3.SystemId{
				{
					IdentifierType: "https://ietf.org/rfc/rfc4122",
					ID:             uuid.New().String(),
				},
			},
			Status: oscalTypes_1_1_3.Status{
				State: "operational",
			},
			SystemInformation: oscalTypes_1_1_3.SystemInformation{
				InformationTypes: []oscalTypes_1_1_3.InformationType{
					{
						UUID:        uuid.New().String(),
						Title:       "Test Information Type",
						Description: "Test information type for testing",
					},
				},
			},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Users: []oscalTypes_1_1_3.SystemUser{
				{
					UUID:    uuid.New().String(),
					Title:   "System Administrator",
					RoleIds: &[]string{"system-admin", "security-admin"},
					AuthorizedPrivileges: &[]oscalTypes_1_1_3.AuthorizedPrivilege{
						{
							Title:              "Full Administrative Access",
							FunctionsPerformed: []string{"system-administration", "security-management"},
						},
					},
				},
			},
			Components: []oscalTypes_1_1_3.SystemComponent{
				{
					UUID:        componentUUID,
					Type:        "software",
					Title:       "Test Application",
					Description: "Test application component",
					Status: oscalTypes_1_1_3.SystemComponentStatus{
						State: "operational",
					},
				},
			},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "Control implementation for test system",
			ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
				{
					UUID:      uuid.New().String(),
					ControlId: "ac-1",
					Statements: &[]oscalTypes_1_1_3.Statement{
						{
							StatementId: "ac-1_stmt.a",
							UUID:        uuid.New().String(),
							Remarks:     "Test statement implementation",
						},
					},
				},
			},
		},
	}
}

func TestValidateOscal(t *testing.T) {
	t.Run("Valid SSP", func(t *testing.T) {
		errMap, err := ValidateOscalAgainstSchema(createValidSSP(), "oscal-complete-oscal-ssp", "system-security-plan")
		assert.NoError(t, err, "Failed to validate schema")
		assert.Empty(t, errMap, "expected empty errors")
	})

	t.Run("Invalid SSP due to email", func(t *testing.T) {
		errMap, err := ValidateOscalAgainstSchema(createInvalidSSP(), "oscal-complete-oscal-ssp", "system-security-plan")
		assert.NoError(t, err, "Failed to validate schema")
		assert.NotEmpty(t, errMap, "expected non-empty errors")
		assert.True(t, reflect.DeepEqual(errMap, map[string]any{"metadata.locations[0].email-addresses[1]": "Field validation for 'metadata.locations[0].email-addresses[1]' failed: does not match pattern \"^.+@.+$\""}))
	})

	t.Run("Invalid activity - UUID format", func(t *testing.T) {
		invalidObj := &oscalTypes_1_1_3.Activity{UUID: "incorrect"}
		errMap, err := ValidateOscalAgainstSchema(invalidObj, "oscal-complete-oscal-assessment-common", "activity")
		assert.NoError(t, err, "Failed to validate schema")
		assert.NotEmpty(t, errMap, "expected non-empty errors")
		assert.True(t, reflect.DeepEqual(errMap, map[string]any{"uuid": "Field validation for 'uuid' failed: does not match pattern \"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$\""}))
	})
}
