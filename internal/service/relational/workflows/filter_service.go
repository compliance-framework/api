package workflows

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type FilterSyncService struct {
	db                     *gorm.DB
	logger                 *zap.SugaredLogger
	controlRelationshipSvc *ControlRelationshipService
	workflowDefinitionSvc  *WorkflowDefinitionService
}

func NewFilterSyncService(db *gorm.DB, logger *zap.SugaredLogger) *FilterSyncService {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &FilterSyncService{
		db:                     db,
		logger:                 logger,
		controlRelationshipSvc: NewControlRelationshipService(db),
		workflowDefinitionSvc:  NewWorkflowDefinitionService(db),
	}
}

func (s *FilterSyncService) SyncFilterForDefinition(definitionID uuid.UUID) error {
	definition, err := s.workflowDefinitionSvc.GetByID(&definitionID)
	if err != nil {
		return fmt.Errorf("failed to load workflow definition: %w", err)
	}

	relationships, err := s.controlRelationshipSvc.GetByWorkflowDefinitionID(&definitionID)
	if err != nil {
		return fmt.Errorf("failed to load control relationships: %w", err)
	}

	controls := make([]relational.Control, 0, len(relationships))
	seenControls := make(map[string]struct{}, len(relationships))
	for _, relationship := range relationships {
		if !relationship.IsActive {
			continue
		}

		if relationship.CatalogID == "" {
			s.logger.Warnw("Skipping workflow control relationship with empty catalog ID",
				"workflow_definition_id", definitionID,
				"control_id", relationship.ControlID,
			)
			continue
		}

		catalogID, parseErr := uuid.Parse(relationship.CatalogID)
		if parseErr != nil {
			s.logger.Warnw("Skipping workflow control relationship with invalid catalog ID",
				"workflow_definition_id", definitionID,
				"catalog_id", relationship.CatalogID,
				"control_id", relationship.ControlID,
				"error", parseErr,
			)
			continue
		}

		key := catalogID.String() + ":" + relationship.ControlID
		if _, ok := seenControls[key]; ok {
			continue
		}

		var control relational.Control
		if err := s.db.Where("catalog_id = ? AND id = ?", catalogID, relationship.ControlID).First(&control).Error; err != nil {
			s.logger.Warnw("Skipping workflow control relationship for unresolved control",
				"workflow_definition_id", definitionID,
				"catalog_id", catalogID,
				"control_id", relationship.ControlID,
				"error", err,
			)
			continue
		}

		seenControls[key] = struct{}{}
		controls = append(controls, control)
	}

	filterID := generateWorkflowFilterUUID(definitionID)
	filter := relational.Filter{
		UUIDModel: relational.UUIDModel{ID: &filterID},
		Name:      "Workflow: " + definition.Name,
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    WorkflowEvidencePolicyLabel,
					Operator: "=",
					Value:    WorkflowPolicyValue(definitionID),
				},
			},
		}),
	}

	var existing relational.Filter
	err = s.db.First(&existing, "id = ?", filterID).Error
	switch {
	case err == nil:
		filter.ID = existing.ID
		if err := s.db.Model(&existing).Updates(map[string]interface{}{
			"name":   filter.Name,
			"filter": filter.Filter,
		}).Error; err != nil {
			return fmt.Errorf("failed to update workflow filter: %w", err)
		}
		filter = existing
	case errors.Is(err, gorm.ErrRecordNotFound):
		if err := s.db.Create(&filter).Error; err != nil {
			return fmt.Errorf("failed to create workflow filter: %w", err)
		}
	default:
		return fmt.Errorf("failed to load workflow filter: %w", err)
	}

	if err := s.db.Model(&filter).Association("Controls").Replace(controls); err != nil {
		return fmt.Errorf("failed to sync workflow filter controls: %w", err)
	}

	return nil
}

func (s *FilterSyncService) DeleteFilterForDefinition(definitionID uuid.UUID) error {
	filterID := generateWorkflowFilterUUID(definitionID)

	var filter relational.Filter
	err := s.db.First(&filter, "id = ?", filterID).Error
	switch {
	case err == nil:
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil
	default:
		return fmt.Errorf("failed to load workflow filter: %w", err)
	}

	if err := s.db.Model(&filter).Association("Controls").Clear(); err != nil {
		return fmt.Errorf("failed to clear workflow filter controls: %w", err)
	}
	if err := s.db.Delete(&filter).Error; err != nil {
		return fmt.Errorf("failed to delete workflow filter: %w", err)
	}

	return nil
}

func generateWorkflowFilterUUID(definitionID uuid.UUID) uuid.UUID {
	seed := fmt.Sprintf("workflow-filter:%s:%s", definitionID.String(), "v1")
	hash := sha256.Sum256([]byte(seed))
	hashStr := hex.EncodeToString(hash[:16])
	filterID, _ := uuid.Parse(hashStr[:8] + "-" + hashStr[8:12] + "-" + hashStr[12:16] + "-" + hashStr[16:20] + "-" + hashStr[20:32])
	return filterID
}
