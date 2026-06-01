package seed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type workflowSeedDefinition struct {
	Key                  string                            `json:"key"`
	Name                 string                            `json:"name"`
	Description          string                            `json:"description"`
	Version              string                            `json:"version"`
	SuggestedCadence     string                            `json:"suggested-cadence"`
	GracePeriodDays      *int                              `json:"grace-period-days"`
	EvidenceRequired     string                            `json:"evidence-required"`
	Steps                []workflowSeedStep                `json:"steps"`
	ControlRelationships []workflowSeedControlRelationship `json:"control-relationships"`
	Instances            []workflowSeedInstance            `json:"instances"`
}

type workflowSeedStep struct {
	Name              string                          `json:"name"`
	Description       string                          `json:"description"`
	Order             int                             `json:"order"`
	ResponsibleRole   string                          `json:"responsible-role"`
	EvidenceRequired  []workflows.EvidenceRequirement `json:"evidence-required"`
	EstimatedDuration int                             `json:"estimated-duration"`
	DependsOn         []string                        `json:"depends-on"`
}

type workflowSeedControlRelationship struct {
	ControlID        string `json:"control-id"`
	CatalogID        string `json:"catalog-id"`
	RelationshipType string `json:"relationship-type"`
	Strength         string `json:"strength"`
	IsActive         *bool  `json:"is-active"`
	Title            string `json:"_title"`
}

type workflowSeedInstance struct {
	Name            string                       `json:"name"`
	Description     string                       `json:"description"`
	SystemID        string                       `json:"system-id"`
	Cadence         string                       `json:"cadence"`
	IsActive        *bool                        `json:"is-active"`
	GracePeriodDays *int                         `json:"grace-period-days"`
	RoleAssignments []workflowSeedRoleAssignment `json:"role-assignments"`
}

type workflowSeedRoleAssignment struct {
	RoleName       string `json:"role-name"`
	AssignedToType string `json:"assigned-to-type"`
	AssignedToID   string `json:"assigned-to-id"`
	IsActive       *bool  `json:"is-active"`
}

type workflowSeedSummary struct {
	DefinitionsCreated   int
	DefinitionsUpdated   int
	Steps                int
	Dependencies         int
	ControlRelationships int
	Instances            int
	RoleAssignments      int
	Failed               int
	Skipped              int
}

func newWorkflowsCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflows",
		Short: "Import workflow definitions from JSON",
		Run:   importSeedWorkflows,
	}

	cmd.Flags().StringP("file", "f", "", "Input JSON file containing workflow definitions")
	if err := cmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	return cmd
}

func importSeedWorkflows(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer func() {
		_ = zapLogger.Sync()
	}()

	inputFile, err := cmd.Flags().GetString("file")
	if err != nil {
		sugar.Fatalf("failed to get input file flag: %v", err)
	}

	cfg := config.NewConfig(sugar)
	db, err := service.ConnectSQLDb(context.Background(), cfg, sugar)
	if err != nil {
		sugar.Fatalf("failed to connect database: %v", err)
	}

	summary, err := importWorkflowsFromFile(context.Background(), db, sugar, inputFile)
	if err != nil {
		sugar.Fatalf("failed to import workflow seed: %v", err)
	}

	sugar.Infow("Workflow seed import completed",
		"definitions_created", summary.DefinitionsCreated,
		"definitions_updated", summary.DefinitionsUpdated,
		"steps", summary.Steps,
		"dependencies", summary.Dependencies,
		"control_relationships", summary.ControlRelationships,
		"instances", summary.Instances,
		"role_assignments", summary.RoleAssignments,
		"skipped", summary.Skipped,
		"failed", summary.Failed,
	)
	if summary.Failed > 0 {
		sugar.Fatalf("workflow seed import completed with %d failed definitions", summary.Failed)
	}
}

func importWorkflowsFromFile(ctx context.Context, db *gorm.DB, sugar *zap.SugaredLogger, path string) (workflowSeedSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return workflowSeedSummary{}, fmt.Errorf("failed to open input file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && sugar != nil {
			sugar.Errorw("failed to close input file", "error", closeErr)
		}
	}()

	var definitions []workflowSeedDefinition
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&definitions); err != nil {
		return workflowSeedSummary{}, fmt.Errorf("failed to decode input JSON: %w", err)
	}

	return importWorkflowSeeds(ctx, db, sugar, definitions), nil
}

func importWorkflowSeeds(ctx context.Context, db *gorm.DB, sugar *zap.SugaredLogger, definitions []workflowSeedDefinition) workflowSeedSummary {
	var summary workflowSeedSummary
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

		var defSummary workflowSeedSummary
		err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var err error
			defSummary, err = importWorkflowSeedDefinition(tx, seedDef)
			return err
		})
		if err != nil {
			summary.Failed++
			if sugar != nil {
				sugar.Errorw("Failed to import workflow definition", "key", seedDef.Key, "name", seedDef.Name, "error", err)
			}
			continue
		}

		mergeWorkflowSeedSummary(&summary, defSummary)
	}

	return summary
}

func importWorkflowSeedDefinition(tx *gorm.DB, seedDef workflowSeedDefinition) (workflowSeedSummary, error) {
	var summary workflowSeedSummary

	if seedDef.SuggestedCadence != "" && !workflows.CadenceType(seedDef.SuggestedCadence).IsValid() {
		return summary, fmt.Errorf("invalid suggested-cadence %q for workflow definition %q", seedDef.SuggestedCadence, seedDef.Key)
	}

	defID := deterministicWorkflowSeedUUID("workflow-definition", seedDef.Key)
	definition := &workflows.WorkflowDefinition{
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

	definitionSvc := workflows.NewWorkflowDefinitionService(tx)
	if err := definitionSvc.ValidateDefinition(definition); err != nil {
		return summary, err
	}
	created, err := upsertWorkflowSeed(tx, definition)
	if err != nil {
		return summary, fmt.Errorf("upsert workflow definition %q: %w", seedDef.Key, err)
	}
	if created {
		summary.DefinitionsCreated++
	} else {
		summary.DefinitionsUpdated++
	}

	stepSummary, err := importWorkflowSeedSteps(tx, seedDef, &defID)
	if err != nil {
		return summary, err
	}
	summary.Steps += stepSummary.Steps
	summary.Dependencies += stepSummary.Dependencies

	relationshipSummary, err := importWorkflowSeedControlRelationships(tx, seedDef, &defID)
	if err != nil {
		return summary, err
	}
	summary.ControlRelationships += relationshipSummary.ControlRelationships

	instanceSummary, err := importWorkflowSeedInstances(tx, seedDef, &defID)
	if err != nil {
		return summary, err
	}
	summary.Instances += instanceSummary.Instances
	summary.RoleAssignments += instanceSummary.RoleAssignments

	return summary, nil
}

func importWorkflowSeedSteps(tx *gorm.DB, seedDef workflowSeedDefinition, defID *uuid.UUID) (workflowSeedSummary, error) {
	var summary workflowSeedSummary
	stepSvc := workflows.NewWorkflowStepDefinitionService(tx)
	stepIDsByName := make(map[string]*uuid.UUID, len(seedDef.Steps))

	for _, seedStep := range seedDef.Steps {
		if _, exists := stepIDsByName[seedStep.Name]; exists {
			return summary, fmt.Errorf("duplicate step name %q in workflow definition %q", seedStep.Name, seedDef.Key)
		}

		stepID := deterministicWorkflowSeedUUID("workflow-step-definition", seedDef.Key, seedStep.Name)
		step := &workflows.WorkflowStepDefinition{
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
		}
		if err := stepSvc.ValidateStep(step); err != nil {
			return summary, fmt.Errorf("validate step %q: %w", seedStep.Name, err)
		}
		if _, err := upsertWorkflowSeed(tx, step); err != nil {
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
			if err := addWorkflowSeedDependency(tx, stepSvc, stepID, dependsOnStepID); err != nil {
				return summary, fmt.Errorf("add dependency %q -> %q: %w", seedStep.Name, dependsOnName, err)
			}
			summary.Dependencies++
		}
	}

	return summary, nil
}

func addWorkflowSeedDependency(tx *gorm.DB, stepSvc *workflows.WorkflowStepDefinitionService, stepID, dependsOnStepID *uuid.UUID) error {
	if stepID == nil || dependsOnStepID == nil {
		return errors.New("step dependency IDs are required")
	}

	var existing workflows.StepDependency
	err := tx.Where("workflow_step_definition_id = ? AND depends_on_step_id = ?", stepID, dependsOnStepID).First(&existing).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	return stepSvc.AddDependency(stepID, dependsOnStepID)
}

func importWorkflowSeedControlRelationships(tx *gorm.DB, seedDef workflowSeedDefinition, defID *uuid.UUID) (workflowSeedSummary, error) {
	var summary workflowSeedSummary
	relationshipSvc := workflows.NewControlRelationshipService(tx)

	for _, seedRelationship := range seedDef.ControlRelationships {
		relationshipType := seedRelationship.RelationshipType
		if relationshipType == "" {
			relationshipType = workflows.RelationshipSatisfies.String()
		}
		strength := seedRelationship.Strength
		if strength == "" {
			strength = workflows.StrengthPrimary.String()
		}
		isActive := true
		if seedRelationship.IsActive != nil {
			isActive = *seedRelationship.IsActive
		}

		relationshipID := deterministicWorkflowSeedUUID("workflow-control-relationship", seedDef.Key, seedRelationship.CatalogID, seedRelationship.ControlID)
		relationship := &workflows.ControlRelationship{
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
		if _, err := upsertWorkflowSeed(tx, relationship); err != nil {
			return summary, fmt.Errorf("upsert control relationship %q: %w", seedRelationship.ControlID, err)
		}
		summary.ControlRelationships++
	}

	return summary, nil
}

func importWorkflowSeedInstances(tx *gorm.DB, seedDef workflowSeedDefinition, defID *uuid.UUID) (workflowSeedSummary, error) {
	var summary workflowSeedSummary
	instanceSvc := workflows.NewWorkflowInstanceService(tx)
	assignmentSvc := workflows.NewRoleAssignmentService(tx)

	for _, seedInstance := range seedDef.Instances {
		if seedInstance.Cadence != "" && !workflows.CadenceType(seedInstance.Cadence).IsValid() {
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

		instanceID := deterministicWorkflowSeedUUID("workflow-instance", seedDef.Key, seedInstance.Name)
		instance := &workflows.WorkflowInstance{
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
		if err := preserveWorkflowInstanceSchedule(tx, instanceSvc, instance); err != nil {
			return summary, fmt.Errorf("preserve instance schedule %q: %w", seedInstance.Name, err)
		}

		if err := instanceSvc.ValidateInstance(instance); err != nil {
			return summary, fmt.Errorf("validate instance %q: %w", seedInstance.Name, err)
		}
		if _, err := upsertWorkflowSeed(tx, instance); err != nil {
			return summary, fmt.Errorf("upsert instance %q: %w", seedInstance.Name, err)
		}
		summary.Instances++

		for _, seedAssignment := range seedInstance.RoleAssignments {
			if !workflows.AssignmentType(seedAssignment.AssignedToType).IsValid() {
				return summary, fmt.Errorf("invalid assigned-to-type %q for role assignment %q", seedAssignment.AssignedToType, seedAssignment.RoleName)
			}

			assignmentActive := true
			if seedAssignment.IsActive != nil {
				assignmentActive = *seedAssignment.IsActive
			}
			assignmentID := deterministicWorkflowSeedUUID("workflow-role-assignment", seedDef.Key, seedInstance.Name, seedAssignment.RoleName, seedAssignment.AssignedToType, seedAssignment.AssignedToID)
			assignment := &workflows.RoleAssignment{
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
			if _, err := upsertWorkflowSeed(tx, assignment); err != nil {
				return summary, fmt.Errorf("upsert role assignment %q: %w", seedAssignment.RoleName, err)
			}
			summary.RoleAssignments++
		}
	}

	return summary, nil
}

func preserveWorkflowInstanceSchedule(tx *gorm.DB, instanceSvc *workflows.WorkflowInstanceService, instance *workflows.WorkflowInstance) error {
	var existing workflows.WorkflowInstance
	err := tx.Select("next_scheduled_at", "last_executed_at").First(&existing, "id = ?", instance.ID).Error
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

func upsertWorkflowSeed(tx *gorm.DB, value interface{}) (bool, error) {
	id, err := workflowSeedID(value)
	if err != nil {
		return false, err
	}
	if id == nil {
		return false, fmt.Errorf("workflow seed ID is required for %T", value)
	}

	var count int64
	if err := tx.Model(value).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, err
	}

	columns, err := workflowSeedUpdateColumns(value)
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

func workflowSeedID(value interface{}) (*uuid.UUID, error) {
	switch v := value.(type) {
	case *workflows.WorkflowDefinition:
		return v.ID, nil
	case *workflows.WorkflowStepDefinition:
		return v.ID, nil
	case *workflows.ControlRelationship:
		return v.ID, nil
	case *workflows.WorkflowInstance:
		return v.ID, nil
	case *workflows.RoleAssignment:
		return v.ID, nil
	default:
		return nil, fmt.Errorf("unsupported workflow seed type %T", value)
	}
}

func workflowSeedUpdateColumns(value interface{}) ([]string, error) {
	switch value.(type) {
	case *workflows.WorkflowDefinition:
		return []string{
			"name",
			"description",
			"version",
			"suggested_cadence",
			"evidence_required",
			"grace_period_days",
			"updated_at",
		}, nil
	case *workflows.WorkflowStepDefinition:
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
		}, nil
	case *workflows.ControlRelationship:
		return []string{
			"workflow_definition_id",
			"control_id",
			"control_source",
			"catalog_id",
			"relationship_type",
			"strength",
			"is_active",
			"updated_at",
		}, nil
	case *workflows.WorkflowInstance:
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
		}, nil
	case *workflows.RoleAssignment:
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

func deterministicWorkflowSeedUUID(parts ...string) uuid.UUID {
	seedValue := strings.Join(append(parts, "v1"), ":")
	hash := sha256.Sum256([]byte(seedValue))
	hashStr := hex.EncodeToString(hash[:16])
	id, _ := uuid.Parse(hashStr[:8] + "-" + hashStr[8:12] + "-" + hashStr[12:16] + "-" + hashStr[16:20] + "-" + hashStr[20:32])
	return id
}

func mergeWorkflowSeedSummary(dst *workflowSeedSummary, src workflowSeedSummary) {
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
