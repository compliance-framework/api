//go:build integration

package tests

import (
	"testing"
	"time"

	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/compliance-framework/configuration-service/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/datatypes"
)

func TestPlanOfActionAndMilestones(t *testing.T) {
	suite.Run(t, new(PlanOfActionAndMilestonesIntegrationSuite))
}

type PlanOfActionAndMilestonesIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMCreate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()

	// Create a basic POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "Test POAM",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		ImportSsp: datatypes.NewJSONType(relational.ImportSsp{
			Href:    "#test-ssp-reference",
			Remarks: "Test import SSP reference",
		}),
		SystemId: datatypes.NewJSONType(relational.SystemId{
			ID:             "TEST-SYSTEM-001",
			IdentifierType: "https://test.gov",
		}),
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Verify POAM was created
	var count int64
	suite.DB.Model(&relational.PlanOfActionAndMilestones{}).Count(&count)
	suite.Equal(int64(1), count)

	// Verify we can retrieve it
	var retrievedPoam relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").First(&retrievedPoam, "id = ?", poamId).Error
	suite.Require().NoError(err)
	suite.Equal("Test POAM", retrievedPoam.Metadata.Title)
	suite.Equal("TEST-SYSTEM-001", retrievedPoam.SystemId.Data().ID)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMWithObservations() {
	err := suite.Migrator.Up()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	obsId := uuid.New()

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM with Observations",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		Observations: []relational.Observation{
			{
				UUIDModel: relational.UUIDModel{
					ID: &obsId,
				},
				Collected:   now,
				Description: "Test observation for POAM",
				Methods:     datatypes.NewJSONSlice([]string{"AUTOMATED", "INTERVIEW"}),
				Title:       stringPtr("Test Security Observation"),
			},
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Verify the relationship
	var poamWithObs relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").Preload("Observations").First(&poamWithObs, "id = ?", poamId).Error
	suite.Require().NoError(err)

	suite.Equal(1, len(poamWithObs.Observations))
	suite.Equal("Test observation for POAM", poamWithObs.Observations[0].Description)
	suite.Equal("Test Security Observation", *poamWithObs.Observations[0].Title)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMWithRisks() {
	err := suite.Migrator.Up()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	riskId := uuid.New()

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM with Risks",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		Risks: []relational.Risk{
			{
				UUIDModel: relational.UUIDModel{
					ID: &riskId,
				},
				Title:       "Critical Security Risk",
				Description: "A high-impact security vulnerability requiring immediate attention",
				Statement:   "This risk poses a significant threat to system security",
				Status:      "open",
				Deadline:    &now,
			},
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Verify the relationship
	var poamWithRisk relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").Preload("Risks").First(&poamWithRisk, "id = ?", poamId).Error
	suite.Require().NoError(err)

	suite.Equal(1, len(poamWithRisk.Risks))
	suite.Equal("Critical Security Risk", poamWithRisk.Risks[0].Title)
	suite.Equal("open", poamWithRisk.Risks[0].Status)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMWithFindings() {
	err := suite.Migrator.Up()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	findingId := uuid.New()

	finding := &relational.Finding{
		UUIDModel: relational.UUIDModel{
			ID: &findingId,
		},
		Title:       "Configuration Compliance Finding",
		Description: "System configuration does not meet security baseline requirements",
		Target: datatypes.NewJSONType(oscalTypes_1_1_3.FindingTarget{
			Type:        "statement-id",
			TargetId:    "ac-2_smt.a",
			Description: "Access Control Implementation Statement",
		}),
	}

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM with Findings",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		Findings: []relational.Finding{
			*finding,
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Verify the relationship
	var poamWithFinding relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").Preload("Findings").First(&poamWithFinding, "id = ?", poamId).Error
	suite.Require().NoError(err)

	suite.Equal(1, len(poamWithFinding.Findings))
	suite.Equal("Configuration Compliance Finding", poamWithFinding.Findings[0].Title)
	suite.Equal("ac-2_smt.a", poamWithFinding.Findings[0].Target.Data().TargetId)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMWithPoamItems() {
	err := suite.Migrator.Up()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	itemUUID := "test-poam-item-001"

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM with Items",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Create POAM Item linked to POAM
	poamItem := &relational.PoamItem{
		PlanOfActionAndMilestonesID: poamId,
		UUID:                        itemUUID,
		Title:                       "Implement Multi-Factor Authentication",
		Description:                 "Deploy MFA solution for all user accounts to enhance authentication security",
		Props: datatypes.NewJSONSlice([]relational.Prop{
			{
				Name:  "POAM-ID",
				Ns:    "https://fedramp.gov/ns/oscal",
				Value: "V-001",
			},
			{
				Name:  "priority",
				Value: "high",
			},
		}),
		Remarks: stringPtr("Critical security enhancement required for compliance"),
	}

	err = suite.DB.Create(poamItem).Error
	suite.Require().NoError(err)

	// Verify the relationship
	var poamWithItems relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").Preload("PoamItems").First(&poamWithItems, "id = ?", poamId).Error
	suite.Require().NoError(err)

	suite.Equal(1, len(poamWithItems.PoamItems))
	suite.Equal("Implement Multi-Factor Authentication", poamWithItems.PoamItems[0].Title)
	suite.Equal(itemUUID, poamWithItems.PoamItems[0].UUID)
	suite.Equal("V-001", poamWithItems.PoamItems[0].Props[0].Value)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMCompleteStructure() {
	err := suite.Migrator.Up()
	suite.Require().NoError(err)

	now := time.Now()
	// Add observations, risks, findings, and POAM items
	observation := &relational.Observation{
		UUIDModel: relational.UUIDModel{
			ID: func() *uuid.UUID { id := uuid.New(); return &id }(),
		},
		Collected:   now,
		Description: "Security compliance observation",
		Methods:     datatypes.NewJSONSlice([]string{"AUTOMATED"}),
	}

	risk := &relational.Risk{
		UUIDModel: relational.UUIDModel{
			ID: func() *uuid.UUID { id := uuid.New(); return &id }(),
		},
		Title:       "Data Breach Risk",
		Description: "Risk of unauthorized data access",
		Statement:   "Vulnerability in access controls",
		Status:      "open",
	}

	finding := &relational.Finding{
		UUIDModel: relational.UUIDModel{
			ID: func() *uuid.UUID { id := uuid.New(); return &id }(),
		},
		Title:       "Access Control Finding",
		Description: "Inadequate access control implementation",
		Target: datatypes.NewJSONType(oscalTypes_1_1_3.FindingTarget{
			Type:     "statement-id",
			TargetId: "ac-2_smt.a",
		}),
	}

	poamId := uuid.New()

	poamItem := &relational.PoamItem{
		PlanOfActionAndMilestonesID: poamId,
		UUID:                        "complete-test-item",
		Title:                       "Complete Security Enhancement",
		Description:                 "Comprehensive security improvement plan",
	}
	// Create a complete POAM with all relationships
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "Complete POAM Test",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		ImportSsp: datatypes.NewJSONType(relational.ImportSsp{
			Href:    "#system-ssp-reference",
			Remarks: "Reference to the system security plan",
		}),
		SystemId: datatypes.NewJSONType(relational.SystemId{
			ID:             "SYS-001",
			IdentifierType: "https://organization.gov",
		}),
		LocalDefinitions: datatypes.NewJSONType(relational.PlanOfActionAndMilestonesLocalDefinitions{
			Remarks: "Local definitions for POAM-specific components and assets",
		}),
		PoamItems: []relational.PoamItem{
			*poamItem,
		},
		Observations: []relational.Observation{
			*observation,
		},
		Findings: []relational.Finding{
			*finding,
		},
		Risks: []relational.Risk{
			*risk,
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Retrieve complete POAM with all relationships
	var completePoam relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").
		Preload("Observations").
		Preload("Risks").
		Preload("Findings").
		Preload("PoamItems").
		First(&completePoam, "id = ?", poamId).Error
	suite.Require().NoError(err)

	// Verify all relationships
	suite.Equal("Complete POAM Test", completePoam.Metadata.Title)
	suite.Equal("SYS-001", completePoam.SystemId.Data().ID)
	suite.Equal(1, len(completePoam.Observations))
	suite.Equal(1, len(completePoam.Risks))
	suite.Equal(1, len(completePoam.Findings))
	suite.Equal(1, len(completePoam.PoamItems))

	// Test OSCAL marshaling
	oscalPoam := completePoam.MarshalOscal()
	suite.NotNil(oscalPoam)
	suite.Equal(poamId.String(), oscalPoam.UUID)
	suite.Equal("Complete POAM Test", oscalPoam.Metadata.Title)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMOSCALRoundTrip() {
	err := suite.Migrator.Up()
	suite.Require().NoError(err)

	// Create OSCAL POAM structure
	now := time.Now()
	oscalPoam := oscalTypes_1_1_3.PlanOfActionAndMilestones{
		UUID: uuid.New().String(),
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "OSCAL Round Trip Test",
			LastModified: now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		SystemId: &oscalTypes_1_1_3.SystemId{
			ID:             "ROUNDTRIP-001",
			IdentifierType: "https://test.gov",
		},
		ImportSsp: &oscalTypes_1_1_3.ImportSsp{
			Href:    "#test-ssp",
			Remarks: "Test SSP reference",
		},
		PoamItems: []oscalTypes_1_1_3.PoamItem{
			{
				UUID:        "test-item-001",
				Title:       "Test POAM Item",
				Description: "Test description for POAM item",
			},
		},
	}

	// Convert to relational and save
	relPoam := &relational.PlanOfActionAndMilestones{}
	relPoam.UnmarshalOscal(oscalPoam)

	err = suite.DB.Create(relPoam).Error
	suite.Require().NoError(err)

	// Retrieve and convert back to OSCAL
	var retrievedPoam relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").Preload("PoamItems").First(&retrievedPoam, "id = ?", relPoam.ID).Error
	suite.Require().NoError(err)

	marshaledOscal := retrievedPoam.MarshalOscal()

	// Verify round trip conversion
	suite.Equal(oscalPoam.UUID, marshaledOscal.UUID)
	suite.Equal(oscalPoam.Metadata.Title, marshaledOscal.Metadata.Title)
	suite.Equal(oscalPoam.SystemId.ID, marshaledOscal.SystemId.ID)
	suite.Equal(len(oscalPoam.PoamItems), len(marshaledOscal.PoamItems))
	suite.Equal(oscalPoam.PoamItems[0].Title, marshaledOscal.PoamItems[0].Title)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPOAMUpdate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()

	// Create initial POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "Initial POAM Title",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		SystemId: datatypes.NewJSONType(relational.SystemId{
			ID:             "INITIAL-SYSTEM-001",
			IdentifierType: "https://initial.gov",
		}),
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Update POAM
	laterTime := now.Add(time.Hour)
	poam.Metadata.Title = "Updated POAM Title"
	poam.Metadata.LastModified = &laterTime
	poam.Metadata.Version = "1.1.0"
	poam.SystemId = datatypes.NewJSONType(relational.SystemId{
		ID:             "UPDATED-SYSTEM-001",
		IdentifierType: "https://updated.gov",
	})

	// Update metadata separately since it's a nested struct
	err = suite.DB.Save(&poam.Metadata).Error
	suite.Require().NoError(err)

	err = suite.DB.Save(poam).Error
	suite.Require().NoError(err)

	// Verify update
	var updatedPoam relational.PlanOfActionAndMilestones
	err = suite.DB.Preload("Metadata").First(&updatedPoam, "id = ?", poamId).Error
	suite.Require().NoError(err)

	suite.Equal("Updated POAM Title", updatedPoam.Metadata.Title)
	suite.Equal("1.1.0", updatedPoam.Metadata.Version)
	suite.Equal("UPDATED-SYSTEM-001", updatedPoam.SystemId.Data().ID)
	suite.Equal("https://updated.gov", updatedPoam.SystemId.Data().IdentifierType)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestObservationUpdate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	obsId := uuid.New()

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM for Observation Update",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Create initial observation
	observation := &relational.Observation{
		UUIDModel: relational.UUIDModel{
			ID: &obsId,
		},
		Collected:   now,
		Description: "Initial observation description",
		Methods:     datatypes.NewJSONSlice([]string{"AUTOMATED"}),
		Title:       stringPtr("Initial Observation Title"),
	}

	err = suite.DB.Create(observation).Error
	suite.Require().NoError(err)

	// Update observation
	laterTime := now.Add(time.Hour)
	observation.Collected = laterTime
	observation.Description = "Updated observation description"
	observation.Methods = datatypes.NewJSONSlice([]string{"AUTOMATED", "INTERVIEW", "TESTING"})
	observation.Title = stringPtr("Updated Observation Title")

	err = suite.DB.Save(observation).Error
	suite.Require().NoError(err)

	// Verify update
	var updatedObs relational.Observation
	err = suite.DB.First(&updatedObs, "id = ?", obsId).Error
	suite.Require().NoError(err)

	suite.Equal("Updated observation description", updatedObs.Description)
	suite.Equal("Updated Observation Title", *updatedObs.Title)
	suite.Equal(3, len(updatedObs.Methods))
	suite.Contains(updatedObs.Methods, "TESTING")
	suite.Equal(laterTime.Unix(), updatedObs.Collected.Unix())
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestRiskUpdate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	riskId := uuid.New()

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM for Risk Update",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Create initial risk
	risk := &relational.Risk{
		UUIDModel: relational.UUIDModel{
			ID: &riskId,
		},
		Title:       "Initial Risk Title",
		Description: "Initial risk description",
		Statement:   "Initial risk statement",
		Status:      "open",
		Deadline:    &now,
	}

	err = suite.DB.Create(risk).Error
	suite.Require().NoError(err)

	// Update risk
	laterTime := now.Add(24 * time.Hour) // 1 day later
	risk.Title = "Updated Risk Title"
	risk.Description = "Updated risk description with more detail"
	risk.Statement = "Updated risk statement"
	risk.Status = "investigating"
	risk.Deadline = &laterTime

	err = suite.DB.Save(risk).Error
	suite.Require().NoError(err)

	// Verify update
	var updatedRisk relational.Risk
	err = suite.DB.First(&updatedRisk, "id = ?", riskId).Error
	suite.Require().NoError(err)

	suite.Equal("Updated Risk Title", updatedRisk.Title)
	suite.Equal("Updated risk description with more detail", updatedRisk.Description)
	suite.Equal("investigating", updatedRisk.Status)
	suite.Equal(laterTime.Unix(), updatedRisk.Deadline.Unix())
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestFindingUpdate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	findingId := uuid.New()

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM for Finding Update",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
		Findings: []relational.Finding{
			{
				UUIDModel: relational.UUIDModel{
					ID: &findingId,
				},
				Title:       "Initial Finding Title",
				Description: "Initial finding description",
				Target: datatypes.NewJSONType(oscalTypes_1_1_3.FindingTarget{
					Type:        "statement-id",
					TargetId:    "ac-2_smt.a",
					Description: "Initial target description",
				}),
			},
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Update finding
	updatedTarget := oscalTypes_1_1_3.FindingTarget{
		Type:        "objective-id",
		TargetId:    "ac-2_obj.1",
		Description: "Updated target description with more detail",
	}

	poam.Findings[0].Title = "Updated Finding Title"
	poam.Findings[0].Description = "Updated finding description with comprehensive detail"
	poam.Findings[0].Target = datatypes.NewJSONType(updatedTarget)

	err = suite.DB.Save(poam.Findings[0]).Error
	suite.Require().NoError(err)

	// Verify update
	var updatedFinding relational.Finding
	err = suite.DB.First(&updatedFinding, "id = ?", findingId).Error
	suite.Require().NoError(err)

	suite.Equal("Updated Finding Title", updatedFinding.Title)
	suite.Equal("Updated finding description with comprehensive detail", updatedFinding.Description)
	suite.Equal("objective-id", updatedFinding.Target.Data().Type)
	suite.Equal("ac-2_obj.1", updatedFinding.Target.Data().TargetId)
	suite.Equal("Updated target description with more detail", updatedFinding.Target.Data().Description)
}

func (suite *PlanOfActionAndMilestonesIntegrationSuite) TestPoamItemUpdate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now()
	poamId := uuid.New()
	itemUUID := "test-update-item-001"

	// Create POAM
	poam := &relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamId,
		},
		Metadata: relational.Metadata{
			Title:        "POAM for Item Update",
			LastModified: &now,
			OscalVersion: "1.0.4",
			Published:    &now,
			Version:      "1.0.0",
		},
	}

	err = suite.DB.Create(poam).Error
	suite.Require().NoError(err)

	// Create initial POAM item
	poamItem := &relational.PoamItem{
		PlanOfActionAndMilestonesID: poamId,
		UUID:                        itemUUID,
		Title:                       "Initial POAM Item Title",
		Description:                 "Initial POAM item description",
		Props: datatypes.NewJSONSlice([]relational.Prop{
			{
				Name:  "priority",
				Value: "medium",
			},
		}),
		Remarks: stringPtr("Initial remarks"),
	}

	err = suite.DB.Create(poamItem).Error
	suite.Require().NoError(err)

	// Update POAM item
	poamItem.Title = "Updated POAM Item Title"
	poamItem.Description = "Updated POAM item description with enhanced detail"
	poamItem.Props = datatypes.NewJSONSlice([]relational.Prop{
		{
			Name:  "priority",
			Value: "high",
		},
		{
			Name:  "status",
			Value: "in-progress",
		},
		{
			Name:  "POAM-ID",
			Ns:    "https://fedramp.gov/ns/oscal",
			Value: "V-002",
		},
	})
	poamItem.Remarks = stringPtr("Updated remarks with additional context")

	err = suite.DB.Save(poamItem).Error
	suite.Require().NoError(err)

	// Verify update
	var updatedItem relational.PoamItem
	err = suite.DB.First(&updatedItem, "uuid = ? AND plan_of_action_and_milestones_id = ?", itemUUID, poamId).Error
	suite.Require().NoError(err)

	suite.Equal("Updated POAM Item Title", updatedItem.Title)
	suite.Equal("Updated POAM item description with enhanced detail", updatedItem.Description)
	suite.Equal(3, len(updatedItem.Props))
	suite.Equal("Updated remarks with additional context", *updatedItem.Remarks)

	// Verify specific prop values
	foundHighPriority := false
	foundStatus := false
	foundPoamId := false
	for _, prop := range updatedItem.Props {
		if prop.Name == "priority" && prop.Value == "high" {
			foundHighPriority = true
		}
		if prop.Name == "status" && prop.Value == "in-progress" {
			foundStatus = true
		}
		if prop.Name == "POAM-ID" && prop.Value == "V-002" {
			foundPoamId = true
		}
	}
	suite.True(foundHighPriority, "Should find high priority prop")
	suite.True(foundStatus, "Should find status prop")
	suite.True(foundPoamId, "Should find POAM-ID prop")
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
