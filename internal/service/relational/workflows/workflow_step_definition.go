package workflows

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// WorkflowStepDefinition represents a discrete piece of work within a workflow
// Contains dependencies on other steps and defines evidence requirements
type WorkflowStepDefinition struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created-at"`
	UpdatedAt time.Time      `json:"updated-at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Basic Information
	Name        string `gorm:"not null;size:255" json:"name"`
	Description string `gorm:"type:text" json:"description"`

	// Step Configuration
	Order             int                                      `gorm:"not null;default:0;index:idx_workflow_order" json:"order"` // Display order within workflow
	ResponsibleRole   string                                   `gorm:"not null;size:255" json:"responsible_role"`                // Role responsible for this step
	EvidenceRequired  datatypes.JSONSlice[EvidenceRequirement] `json:"evidence_required"`                                        // JSON array of required evidence types
	EstimatedDuration int                                      `gorm:"default:0" json:"estimated_duration"`                      // Estimated duration in minutes

	// Foreign Keys
	WorkflowDefinitionID *uuid.UUID `gorm:"not null;index" json:"workflow_definition_id"`

	// Relationships
	WorkflowDefinition *WorkflowDefinition `gorm:"foreignKey:WorkflowDefinitionID" json:"workflow_definition,omitempty"`
	DependsOn          []StepDependency    `gorm:"foreignKey:WorkflowStepDefinitionID;constraint:OnDelete:CASCADE" json:"depends_on,omitempty"`
	DependentSteps     []StepDependency    `gorm:"foreignKey:DependsOnStepID;constraint:OnDelete:CASCADE" json:"dependent_steps,omitempty"`
	StepExecutions     []StepExecution     `gorm:"foreignKey:WorkflowStepDefinitionID;constraint:OnDelete:CASCADE" json:"step_executions,omitempty"`
	Triggers           []StepTrigger       `gorm:"foreignKey:WorkflowStepDefinitionID;constraint:OnDelete:CASCADE" json:"triggers,omitempty"`
}

type EvidenceRequirement struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// TableName specifies the table name for WorkflowStepDefinition
func (WorkflowStepDefinition) TableName() string {
	return "workflow_step_definitions"
}

// StepDependency represents the dependency relationship between workflow steps
type StepDependency struct {
	relational.UUIDModel
	WorkflowStepDefinitionID *uuid.UUID `gorm:"not null;index" json:"workflow_step_definition_id"`
	DependsOnStepID          *uuid.UUID `gorm:"not null;index" json:"depends_on_step_id"`

	// Relationships
	WorkflowStepDefinition *WorkflowStepDefinition `gorm:"foreignKey:WorkflowStepDefinitionID" json:"workflow_step_definition,omitempty"`
	DependsOnStep          *WorkflowStepDefinition `gorm:"foreignKey:DependsOnStepID" json:"depends_on_step,omitempty"`
}

// TableName specifies the table name for StepDependency
func (StepDependency) TableName() string {
	return "step_dependencies"
}

// StepTrigger represents automatic step transition conditions (for future Phase 5)
type StepTrigger struct {
	relational.UUIDModel
	WorkflowStepDefinitionID *uuid.UUID `gorm:"not null;index" json:"workflow_step_definition_id"`
	TriggerType              string     `gorm:"size:50" json:"trigger_type"`        // evidence_stream, time_based, external_event
	TriggerCondition         string     `gorm:"type:text" json:"trigger_condition"` // JSON condition expression
	IsActive                 bool       `gorm:"default:false" json:"is_active"`

	// Relationships
	WorkflowStepDefinition *WorkflowStepDefinition `gorm:"foreignKey:WorkflowStepDefinitionID" json:"workflow_step_definition,omitempty"`
}

// TableName specifies the table name for StepTrigger
func (StepTrigger) TableName() string {
	return "step_triggers"
}
