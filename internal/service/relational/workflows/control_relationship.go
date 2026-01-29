package workflows

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ControlRelationship represents the mapping between workflow definitions and compliance controls
// Replaces the original ControlMapping to better reflect the relationship nature
type ControlRelationship struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Control Information
	ControlID     string `gorm:"not null;size:255;index;index:idx_control_rel_workflow_control,priority:2" json:"control_id"` // e.g., "AC-2", "A.9.2.5"
	ControlSource string `gorm:"not null;size:100" json:"control_source"`                                                     // e.g., "NIST 800-53 Rev 5", "ISO 27001"
	CatalogID     string `gorm:"size:255;index" json:"catalog_id"`                                                            // Link to catalog if available

	// Relationship Information
	RelationshipType string `gorm:"size:50" json:"relationship_type"` // satisfies, partially_satisfies, supports
	Strength         string `gorm:"size:20" json:"strength"`          // primary, secondary, supporting
	IsActive         bool   `gorm:"default:true" json:"is_active"`

	// Foreign Keys
	WorkflowDefinitionID *uuid.UUID `gorm:"not null;index;index:idx_control_rel_workflow_control,priority:1" json:"workflow_definition_id"`

	// Relationships
	WorkflowDefinition *WorkflowDefinition `gorm:"foreignKey:WorkflowDefinitionID" json:"workflow_definition,omitempty"`
}

// TableName specifies the table name for ControlRelationship
func (ControlRelationship) TableName() string {
	return "control_relationships"
}
