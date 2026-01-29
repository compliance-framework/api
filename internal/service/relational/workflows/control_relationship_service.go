package workflows

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ControlRelationshipService provides CRUD operations for ControlRelationship
type ControlRelationshipService struct {
	db   *gorm.DB
	base *BaseService
}

// NewControlRelationshipService creates a new ControlRelationshipService
func NewControlRelationshipService(db *gorm.DB) *ControlRelationshipService {
	return &ControlRelationshipService{
		db:   db,
		base: NewBaseService(db),
	}
}

// Create creates a new control relationship
func (s *ControlRelationshipService) Create(relationship *ControlRelationship) error {
	if relationship == nil {
		return errors.New("control relationship cannot be nil")
	}

	if err := s.ValidateRelationship(relationship); err != nil {
		return err
	}

	return s.db.Create(relationship).Error
}

// GetByID retrieves a control relationship by ID
func (s *ControlRelationshipService) GetByID(id *uuid.UUID) (*ControlRelationship, error) {
	var relationship ControlRelationship
	err := s.base.GetByIDWithPreload(&relationship, id, "control relationship", "WorkflowDefinition")
	if err != nil {
		return nil, err
	}
	return &relationship, nil
}

// GetByWorkflowDefinitionID retrieves all control relationships for a workflow definition
func (s *ControlRelationshipService) GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]ControlRelationship, error) {
	var relationships []ControlRelationship
	err := s.db.Where("workflow_definition_id = ?", workflowDefID).
		Find(&relationships).Error

	return relationships, err
}

// GetByControlID retrieves all control relationships for a specific control
func (s *ControlRelationshipService) GetByControlID(controlID string) ([]ControlRelationship, error) {
	var relationships []ControlRelationship
	err := s.db.Where("control_id = ?", controlID).
		Preload("WorkflowDefinition").
		Find(&relationships).Error

	return relationships, err
}

// GetByControlSource retrieves all control relationships for a specific control source
func (s *ControlRelationshipService) GetByControlSource(controlSource string) ([]ControlRelationship, error) {
	var relationships []ControlRelationship
	err := s.db.Where("control_source = ?", controlSource).
		Preload("WorkflowDefinition").
		Find(&relationships).Error

	return relationships, err
}

// Update updates an existing control relationship
func (s *ControlRelationshipService) Update(id *uuid.UUID, updates *ControlRelationship) error {
	if updates == nil {
		return errors.New("updates cannot be nil")
	}
	if err := s.base.ValidateUpdatesNotNil(updates); err != nil {
		return err
	}

	if err := s.ValidateRelationship(updates); err != nil {
		return err
	}

	var existing ControlRelationship
	updates.ID = id
	return s.base.UpdateEntity(&existing, updates, id, "control relationship")
}

// Delete soft deletes a control relationship
func (s *ControlRelationshipService) Delete(id *uuid.UUID) error {
	return s.base.DeleteEntity(&ControlRelationship{}, id, "control relationship")
}

// Activate activates a control relationship
func (s *ControlRelationshipService) Activate(id *uuid.UUID) error {
	return s.base.ActivateEntity(&ControlRelationship{}, id)
}

// Deactivate deactivates a control relationship
func (s *ControlRelationshipService) Deactivate(id *uuid.UUID) error {
	return s.base.DeactivateEntity(&ControlRelationship{}, id)
}

// ValidateRelationship validates a control relationship
func (s *ControlRelationshipService) ValidateRelationship(relationship *ControlRelationship) error {
	if err := ValidateNotNil(relationship, "control relationship"); err != nil {
		return err
	}

	var errs []error
	if err := ValidateUUIDRequired(relationship.WorkflowDefinitionID, "workflow definition ID"); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringRequired(relationship.ControlID, "control ID"); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringLength(relationship.ControlID, "control ID", MaxControlIDLength); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringRequired(relationship.ControlSource, "control source"); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringLength(relationship.ControlSource, "control source", MaxControlSourceLength); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateRelationshipType(relationship.RelationshipType); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateRelationshipStrength(relationship.Strength); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return CombineErrors(errs...)
	}

	return nil
}

// BulkCreate creates multiple control relationships at once
func (s *ControlRelationshipService) BulkCreate(relationships []ControlRelationship) error {
	if len(relationships) == 0 {
		return errors.New("no relationships provided")
	}

	// Validate all relationships
	for i, relationship := range relationships {
		if err := s.ValidateRelationship(&relationship); err != nil {
			return fmt.Errorf("relationship %d validation failed: %w", i, err)
		}
	}

	return s.db.Create(&relationships).Error
}

// GetActiveRelationships retrieves all active control relationships for a workflow definition
func (s *ControlRelationshipService) GetActiveRelationships(workflowDefID *uuid.UUID) ([]ControlRelationship, error) {
	var relationships []ControlRelationship
	err := s.db.Where("workflow_definition_id = ? AND is_active = ?", workflowDefID, true).
		Find(&relationships).Error

	return relationships, err
}

// FindByControlAndSource finds a control relationship by control ID and source
func (s *ControlRelationshipService) FindByControlAndSource(workflowDefID *uuid.UUID, controlID, controlSource string) (*ControlRelationship, error) {
	var relationship ControlRelationship
	err := s.db.Where("workflow_definition_id = ? AND control_id = ? AND control_source = ?",
		workflowDefID, controlID, controlSource).
		First(&relationship).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("control relationship not found for control %s from %s", controlID, controlSource)
		}
		return nil, err
	}

	return &relationship, nil
}

// GetPrimaryControls retrieves all primary control relationships for a workflow definition
func (s *ControlRelationshipService) GetPrimaryControls(workflowDefID *uuid.UUID) ([]ControlRelationship, error) {
	var relationships []ControlRelationship
	err := s.db.Where("workflow_definition_id = ? AND strength = ? AND is_active = ?",
		workflowDefID, "primary", true).
		Find(&relationships).Error

	return relationships, err
}

// CountControlsBySource counts control relationships grouped by control source
func (s *ControlRelationshipService) CountControlsBySource(workflowDefID *uuid.UUID) (map[string]int64, error) {
	type SourceCount struct {
		ControlSource string
		Count         int64
	}

	var results []SourceCount
	err := s.db.Model(&ControlRelationship{}).
		Select("control_source, COUNT(*) as count").
		Where("workflow_definition_id = ? AND is_active = ?", workflowDefID, true).
		Group("control_source").
		Scan(&results).Error

	if err != nil {
		return nil, err
	}

	counts := make(map[string]int64)
	for _, result := range results {
		counts[result.ControlSource] = result.Count
	}

	return counts, nil
}
