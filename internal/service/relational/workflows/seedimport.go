package workflows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SeedDefinition struct {
	Key                  string                    `json:"key"`
	Name                 string                    `json:"name"`
	Description          string                    `json:"description"`
	Version              string                    `json:"version"`
	SuggestedCadence     string                    `json:"suggested-cadence"`
	GracePeriodDays      *int                      `json:"grace-period-days"`
	EvidenceRequired     string                    `json:"evidence-required"`
	Steps                []SeedStep                `json:"steps"`
	ControlRelationships []SeedControlRelationship `json:"control-relationships"`
	Instances            []SeedInstance            `json:"instances"`
}

type SeedStep struct {
	Name              string                `json:"name"`
	Description       string                `json:"description"`
	Order             int                   `json:"order"`
	ResponsibleRole   string                `json:"responsible-role"`
	EvidenceRequired  []EvidenceRequirement `json:"evidence-required"`
	EstimatedDuration int                   `json:"estimated-duration"`
	GracePeriodDays   *int                  `json:"grace-period-days"`
	DependsOn         []string              `json:"depends-on"`
}

type SeedControlRelationship struct {
	ControlID        string `json:"control-id"`
	CatalogID        string `json:"catalog-id"`
	RelationshipType string `json:"relationship-type"`
	Strength         string `json:"strength"`
	IsActive         *bool  `json:"is-active"`
	Title            string `json:"_title"`
}

type SeedInstance struct {
	Name            string               `json:"name"`
	Description     string               `json:"description"`
	SystemID        string               `json:"system-id"`
	Cadence         string               `json:"cadence"`
	IsActive        *bool                `json:"is-active"`
	GracePeriodDays *int                 `json:"grace-period-days"`
	RoleAssignments []SeedRoleAssignment `json:"role-assignments"`
}

type SeedRoleAssignment struct {
	RoleName       string `json:"role-name"`
	AssignedToType string `json:"assigned-to-type"`
	AssignedToID   string `json:"assigned-to-id"`
	IsActive       *bool  `json:"is-active"`
}

type SeedSummary struct {
	DefinitionsCreated   int `json:"definitions_created"`
	DefinitionsUpdated   int `json:"definitions_updated"`
	Steps                int `json:"steps"`
	Dependencies         int `json:"dependencies"`
	ControlRelationships int `json:"control_relationships"`
	Instances            int `json:"instances"`
	RoleAssignments      int `json:"role_assignments"`
	Failed               int `json:"failed"`
	Skipped              int `json:"skipped"`
}

func DecodeSeedDefinitions(r io.Reader) ([]SeedDefinition, error) {
	var definitions []SeedDefinition
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&definitions); err != nil {
		return nil, err
	}
	var extra struct{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON after workflow seed definitions")
		}
		return nil, fmt.Errorf("invalid trailing content after workflow seed definitions: %w", err)
	}
	return definitions, nil
}

func ImportSeedDefinitions(ctx context.Context, db *gorm.DB, sugar *zap.SugaredLogger, definitions []SeedDefinition) SeedSummary {
	var summary SeedSummary
	seenKeys := make(map[string]struct{}, len(definitions))

	for _, seedDef := range definitions {
		key := strings.TrimSpace(seedDef.Key)
		if key == "" {
			summary.Skipped++
			if sugar != nil {
				sugar.Errorw("Skipping workflow definition with empty key", "name", seedDef.Name)
			}
			continue
		}
		if _, exists := seenKeys[key]; exists {
			summary.Failed++
			if sugar != nil {
				sugar.Errorw("Duplicate workflow definition key in seed input", "key", key, "name", seedDef.Name)
			}
			continue
		}
		seedDef.Key = key
		seenKeys[key] = struct{}{}

		var defSummary SeedSummary
		err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var err error
			defSummary, err = importSeedDefinition(tx, seedDef)
			return err
		})
		if err != nil {
			summary.Failed++
			if sugar != nil {
				sugar.Errorw("Failed to import workflow definition", "key", seedDef.Key, "name", seedDef.Name, "error", err)
			}
			continue
		}

		MergeSeedSummary(&summary, defSummary)
	}

	return summary
}

func importSeedDefinition(tx *gorm.DB, seedDef SeedDefinition) (SeedSummary, error) {
	var summary SeedSummary

	if seedDef.SuggestedCadence != "" && !CadenceType(seedDef.SuggestedCadence).IsValid() {
		return summary, fmt.Errorf("invalid suggested-cadence %q for workflow definition %q", seedDef.SuggestedCadence, seedDef.Key)
	}

	defID := deterministicSeedUUID("workflow-definition", seedDef.Key)
	definition := &WorkflowDefinition{
		UUIDModel: relational.UUIDModel{
			ID: &defID,
		},
		Name:             seedDef.Name,
		Description:      seedDef.Description,
		Version:          seedDef.Version,
		SuggestedCadence: seedDef.SuggestedCadence,
		GracePeriodDays:  seedDef.GracePeriodDays,
		EvidenceRequired: seedDef.EvidenceRequired,
	}

	definitionSvc := NewWorkflowDefinitionService(tx)
	if err := definitionSvc.ValidateDefinition(definition); err != nil {
		return summary, err
	}
	created, err := upsertSeed(tx, definition)
	if err != nil {
		return summary, fmt.Errorf("upsert workflow definition %q: %w", seedDef.Key, err)
	}
	if created {
		summary.DefinitionsCreated++
	} else {
		summary.DefinitionsUpdated++
	}

	stepSummary, err := importSeedSteps(tx, seedDef, &defID)
	if err != nil {
		return summary, err
	}
	summary.Steps += stepSummary.Steps
	summary.Dependencies += stepSummary.Dependencies

	relationshipSummary, err := importSeedControlRelationships(tx, seedDef, &defID)
	if err != nil {
		return summary, err
	}
	summary.ControlRelationships += relationshipSummary.ControlRelationships

	if err := NewFilterSyncService(tx, nil).SyncFilterForDefinition(defID); err != nil {
		return summary, fmt.Errorf("sync workflow filter for seed definition %q: %w", seedDef.Key, err)
	}

	instanceSummary, err := importSeedInstances(tx, seedDef, &defID)
	if err != nil {
		return summary, err
	}
	summary.Instances += instanceSummary.Instances
	summary.RoleAssignments += instanceSummary.RoleAssignments

	return summary, nil
}

func importSeedSteps(tx *gorm.DB, seedDef SeedDefinition, defID *uuid.UUID) (SeedSummary, error) {
	var summary SeedSummary
	stepSvc := NewWorkflowStepDefinitionService(tx)
	stepIDsByName := make(map[string]*uuid.UUID, len(seedDef.Steps))

	for _, seedStep := range seedDef.Steps {
		if _, exists := stepIDsByName[seedStep.Name]; exists {
			return summary, fmt.Errorf("duplicate step name %q in workflow definition %q", seedStep.Name, seedDef.Key)
		}

		stepID := deterministicSeedUUID("workflow-step-definition", seedDef.Key, seedStep.Name)
		step := &WorkflowStepDefinition{
			UUIDModel: relational.UUIDModel{
				ID: &stepID,
			},
			WorkflowDefinitionID: defID,
			Name:                 seedStep.Name,
			Description:          seedStep.Description,
			Order:                seedStep.Order,
			ResponsibleRole:      seedStep.ResponsibleRole,
			EvidenceRequired:     datatypes.NewJSONSlice(seedStep.EvidenceRequired),
			EstimatedDuration:    seedStep.EstimatedDuration,
			GracePeriodDays:      seedStep.GracePeriodDays,
		}
		if err := stepSvc.ValidateStep(step); err != nil {
			return summary, fmt.Errorf("validate step %q: %w", seedStep.Name, err)
		}
		if _, err := upsertSeed(tx, step); err != nil {
			return summary, fmt.Errorf("upsert step %q: %w", seedStep.Name, err)
		}
		stepIDCopy := stepID
		stepIDsByName[seedStep.Name] = &stepIDCopy
		summary.Steps++
	}

	for _, seedStep := range seedDef.Steps {
		stepID := stepIDsByName[seedStep.Name]
		for _, dependsOnName := range seedStep.DependsOn {
			dependsOnStepID := stepIDsByName[dependsOnName]
			if dependsOnStepID == nil {
				return summary, fmt.Errorf("step %q depends on unknown step %q", seedStep.Name, dependsOnName)
			}
			if err := addSeedDependency(tx, stepSvc, stepID, dependsOnStepID); err != nil {
				return summary, fmt.Errorf("add dependency %q -> %q: %w", seedStep.Name, dependsOnName, err)
			}
			summary.Dependencies++
		}
	}

	return summary, nil
}

func addSeedDependency(tx *gorm.DB, stepSvc *WorkflowStepDefinitionService, stepID, dependsOnStepID *uuid.UUID) error {
	if stepID == nil || dependsOnStepID == nil {
		return errors.New("step dependency IDs are required")
	}

	var existing StepDependency
	err := tx.Where("workflow_step_definition_id = ? AND depends_on_step_id = ?", stepID, dependsOnStepID).First(&existing).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	return stepSvc.AddDependency(stepID, dependsOnStepID)
}

func importSeedControlRelationships(tx *gorm.DB, seedDef SeedDefinition, defID *uuid.UUID) (SeedSummary, error) {
	var summary SeedSummary
	relationshipSvc := NewControlRelationshipService(tx)

	for _, seedRelationship := range seedDef.ControlRelationships {
		relationshipType := seedRelationship.RelationshipType
		if relationshipType == "" {
			relationshipType = RelationshipSatisfies.String()
		}
		strength := seedRelationship.Strength
		if strength == "" {
			strength = StrengthPrimary.String()
		}
		isActive := true
		if seedRelationship.IsActive != nil {
			isActive = *seedRelationship.IsActive
		}

		relationshipID := deterministicSeedUUID("workflow-control-relationship", seedDef.Key, seedRelationship.CatalogID, seedRelationship.ControlID)
		relationship := &ControlRelationship{
			UUIDModel: relational.UUIDModel{
				ID: &relationshipID,
			},
			WorkflowDefinitionID: defID,
			ControlID:            seedRelationship.ControlID,
			ControlSource:        seedRelationship.CatalogID,
			CatalogID:            seedRelationship.CatalogID,
			RelationshipType:     relationshipType,
			Strength:             strength,
			IsActive:             isActive,
		}

		if err := relationshipSvc.ValidateRelationship(relationship); err != nil {
			return summary, fmt.Errorf("validate control relationship %q: %w", seedRelationship.ControlID, err)
		}
		if _, err := upsertSeed(tx, relationship); err != nil {
			return summary, fmt.Errorf("upsert control relationship %q: %w", seedRelationship.ControlID, err)
		}
		summary.ControlRelationships++
	}

	return summary, nil
}

func importSeedInstances(tx *gorm.DB, seedDef SeedDefinition, defID *uuid.UUID) (SeedSummary, error) {
	var summary SeedSummary
	instanceSvc := NewWorkflowInstanceService(tx)
	assignmentSvc := NewRoleAssignmentService(tx)
	seenInstanceNames := make(map[string]struct{}, len(seedDef.Instances))

	for _, seedInstance := range seedDef.Instances {
		if _, exists := seenInstanceNames[seedInstance.Name]; exists {
			return summary, fmt.Errorf("duplicate instance name %q in workflow definition %q", seedInstance.Name, seedDef.Key)
		}
		seenInstanceNames[seedInstance.Name] = struct{}{}

		if seedInstance.Cadence != "" && !CadenceType(seedInstance.Cadence).IsValid() {
			return summary, fmt.Errorf("invalid cadence %q for workflow instance %q", seedInstance.Cadence, seedInstance.Name)
		}

		systemID, err := uuid.Parse(seedInstance.SystemID)
		if err != nil {
			return summary, fmt.Errorf("invalid system-id %q for workflow instance %q: %w", seedInstance.SystemID, seedInstance.Name, err)
		}

		isActive := true
		if seedInstance.IsActive != nil {
			isActive = *seedInstance.IsActive
		}

		instanceID := deterministicSeedUUID("workflow-instance", seedDef.Key, seedInstance.Name)
		instance := &WorkflowInstance{
			UUIDModel: relational.UUIDModel{
				ID: &instanceID,
			},
			WorkflowDefinitionID: defID,
			Name:                 seedInstance.Name,
			Description:          seedInstance.Description,
			SystemSecurityPlanID: &systemID,
			Cadence:              seedInstance.Cadence,
			IsActive:             isActive,
			GracePeriodDays:      seedInstance.GracePeriodDays,
		}
		if err := preserveSeedInstanceSchedule(tx, instanceSvc, instance); err != nil {
			return summary, fmt.Errorf("preserve instance schedule %q: %w", seedInstance.Name, err)
		}

		if err := instanceSvc.ValidateInstance(instance); err != nil {
			return summary, fmt.Errorf("validate instance %q: %w", seedInstance.Name, err)
		}
		if _, err := upsertSeed(tx, instance); err != nil {
			return summary, fmt.Errorf("upsert instance %q: %w", seedInstance.Name, err)
		}
		summary.Instances++

		for _, seedAssignment := range seedInstance.RoleAssignments {
			if !AssignmentType(seedAssignment.AssignedToType).IsValid() {
				return summary, fmt.Errorf("invalid assigned-to-type %q for role assignment %q", seedAssignment.AssignedToType, seedAssignment.RoleName)
			}

			assignmentActive := true
			if seedAssignment.IsActive != nil {
				assignmentActive = *seedAssignment.IsActive
			}
			assignmentID := deterministicSeedUUID("workflow-role-assignment", seedDef.Key, seedInstance.Name, seedAssignment.RoleName, seedAssignment.AssignedToType, seedAssignment.AssignedToID)
			assignment := &RoleAssignment{
				UUIDModel: relational.UUIDModel{
					ID: &assignmentID,
				},
				WorkflowInstanceID: &instanceID,
				RoleName:           seedAssignment.RoleName,
				AssignedToType:     seedAssignment.AssignedToType,
				AssignedToID:       seedAssignment.AssignedToID,
				IsActive:           assignmentActive,
			}
			if err := assignmentSvc.ValidateAssignment(assignment); err != nil {
				return summary, fmt.Errorf("validate role assignment %q: %w", seedAssignment.RoleName, err)
			}
			if _, err := upsertSeed(tx, assignment); err != nil {
				return summary, fmt.Errorf("upsert role assignment %q: %w", seedAssignment.RoleName, err)
			}
			summary.RoleAssignments++
		}
	}

	return summary, nil
}

func preserveSeedInstanceSchedule(tx *gorm.DB, instanceSvc *WorkflowInstanceService, instance *WorkflowInstance) error {
	var existing WorkflowInstance
	err := tx.Unscoped().Select("next_scheduled_at", "last_executed_at").First(&existing, "id = ?", instance.ID).Error
	if err == nil {
		instance.NextScheduledAt = existing.NextScheduledAt
		instance.LastExecutedAt = existing.LastExecutedAt
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	if instance.Cadence != "" {
		nextSchedule := instanceSvc.CalculateNextSchedule(time.Now(), instance.Cadence)
		instance.NextScheduledAt = &nextSchedule
	}
	return nil
}

func upsertSeed(tx *gorm.DB, value interface{}) (bool, error) {
	id, err := seedID(value)
	if err != nil {
		return false, err
	}
	if id == nil {
		return false, fmt.Errorf("workflow seed ID is required for %T", value)
	}

	var count int64
	if err := tx.Unscoped().Model(value).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, err
	}

	columns, err := seedUpdateColumns(value)
	if err != nil {
		return false, err
	}

	if err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(columns),
	}).Create(value).Error; err != nil {
		return false, err
	}

	return count == 0, nil
}

func seedID(value interface{}) (*uuid.UUID, error) {
	switch v := value.(type) {
	case *WorkflowDefinition:
		return v.ID, nil
	case *WorkflowStepDefinition:
		return v.ID, nil
	case *ControlRelationship:
		return v.ID, nil
	case *WorkflowInstance:
		return v.ID, nil
	case *RoleAssignment:
		return v.ID, nil
	default:
		return nil, fmt.Errorf("unsupported workflow seed type %T", value)
	}
}

func seedUpdateColumns(value interface{}) ([]string, error) {
	switch value.(type) {
	case *WorkflowDefinition:
		return []string{
			"name",
			"description",
			"version",
			"suggested_cadence",
			"evidence_required",
			"grace_period_days",
			"updated_at",
			"deleted_at",
		}, nil
	case *WorkflowStepDefinition:
		return []string{
			"workflow_definition_id",
			"name",
			"description",
			"order",
			"responsible_role",
			"evidence_required",
			"estimated_duration",
			"grace_period_days",
			"updated_at",
			"deleted_at",
		}, nil
	case *ControlRelationship:
		return []string{
			"workflow_definition_id",
			"control_id",
			"control_source",
			"catalog_id",
			"relationship_type",
			"strength",
			"is_active",
			"updated_at",
			"deleted_at",
		}, nil
	case *WorkflowInstance:
		return []string{
			"workflow_definition_id",
			"name",
			"description",
			"system_security_plan_id",
			"cadence",
			"is_active",
			"grace_period_days",
			"next_scheduled_at",
			"last_executed_at",
			"updated_at",
			"deleted_at",
		}, nil
	case *RoleAssignment:
		return []string{
			"workflow_instance_id",
			"role_name",
			"assigned_to_type",
			"assigned_to_id",
			"is_active",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported workflow seed type %T", value)
	}
}

func deterministicSeedUUID(parts ...string) uuid.UUID {
	seedValue := strings.Join(append(parts, "v1"), ":")
	hash := sha256.Sum256([]byte(seedValue))
	hashStr := hex.EncodeToString(hash[:16])
	id, _ := uuid.Parse(hashStr[:8] + "-" + hashStr[8:12] + "-" + hashStr[12:16] + "-" + hashStr[16:20] + "-" + hashStr[20:32])
	return id
}

func MergeSeedSummary(dst *SeedSummary, src SeedSummary) {
	dst.DefinitionsCreated += src.DefinitionsCreated
	dst.DefinitionsUpdated += src.DefinitionsUpdated
	dst.Steps += src.Steps
	dst.Dependencies += src.Dependencies
	dst.ControlRelationships += src.ControlRelationships
	dst.Instances += src.Instances
	dst.RoleAssignments += src.RoleAssignments
	dst.Failed += src.Failed
	dst.Skipped += src.Skipped
}
