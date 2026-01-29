package workflows

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkflowDefinition represents a template for recurring compliance activities
// Created centrally by Compliance teams and maps to multiple controls across catalogs
type WorkflowDefinition struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Basic Information
	Name        string `gorm:"not null;size:255" json:"name"`
	Description string `gorm:"type:text" json:"description"`
	Version     string `gorm:"size:50" json:"version"`

	// Workflow Configuration
	SuggestedCadence string `gorm:"size:50" json:"suggested_cadence"`   // daily, weekly, monthly, quarterly, annually
	EvidenceRequired string `gorm:"type:text" json:"evidence_required"` // JSON array of required evidence types

	// Audit Fields
	CreatedByID *uuid.UUID `gorm:"index" json:"created_by_id,omitempty"`
	UpdatedByID *uuid.UUID `gorm:"index" json:"updated_by_id,omitempty"`

	// Relationships
	Steps                []WorkflowStepDefinition `gorm:"foreignKey:WorkflowDefinitionID;constraint:OnDelete:CASCADE" json:"steps,omitempty"`
	ControlRelationships []ControlRelationship    `gorm:"foreignKey:WorkflowDefinitionID;constraint:OnDelete:CASCADE" json:"control_relationships,omitempty"`
	Instances            []WorkflowInstance       `gorm:"foreignKey:WorkflowDefinitionID;constraint:OnDelete:CASCADE" json:"instances,omitempty"`
}

// TableName specifies the table name for WorkflowDefinition
func (WorkflowDefinition) TableName() string {
	return "workflow_definitions"
}

// BeforeCreate hook to set default values
func (w *WorkflowDefinition) BeforeCreate(tx *gorm.DB) error {
	if w.ID == nil {
		id := uuid.New()
		w.ID = &id
	}
	if w.Version == "" {
		w.Version = "1.0"
	}
	return nil
}
