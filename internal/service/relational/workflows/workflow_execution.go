package workflows

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkflowExecution represents a specific run of a workflow instance
type WorkflowExecution struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created-at"`
	UpdatedAt time.Time      `json:"updated-at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Execution Information
	Status        string     `gorm:"size:50;index:idx_workflow_exec_instance_status,priority:2;index:idx_workflow_exec_status_created" json:"status"` // pending, in_progress, completed, failed, cancelled
	StartedAt     *time.Time `json:"started-at,omitempty"`
	OverdueAt     *time.Time `json:"overdue-at,omitempty"`
	CompletedAt   *time.Time `json:"completed-at,omitempty"`
	FailedAt      *time.Time `json:"failed-at,omitempty"`
	FailureReason string     `gorm:"type:text" json:"failure_reason,omitempty"`

	// Execution Context
	TriggeredBy   string `gorm:"size:50;uniqueIndex:uidx_workflow_exec_scheduled_instance_period,priority:2,where:triggered_by = 'scheduled'" json:"triggered_by"` // manual, scheduled, automatic
	TriggeredByID string `gorm:"size:255" json:"triggered_by_id"`                                                                                                  // User ID or system identifier

	// Scheduling Context
	PeriodLabel string     `gorm:"size:50;index;uniqueIndex:uidx_workflow_exec_scheduled_instance_period,priority:3,where:triggered_by = 'scheduled'" json:"period_label,omitempty"` // e.g., "2023-10", "2023-W42"
	DueDate     *time.Time `gorm:"index" json:"due_date,omitempty"`

	// Audit Fields
	CreatedByID *uuid.UUID `gorm:"index" json:"created_by_id,omitempty"`
	UpdatedByID *uuid.UUID `gorm:"index" json:"updated_by_id,omitempty"`

	// Foreign Keys
	WorkflowInstanceID *uuid.UUID `gorm:"not null;index;index:idx_workflow_exec_instance_status,priority:1;uniqueIndex:uidx_workflow_exec_scheduled_instance_period,priority:1,where:triggered_by = 'scheduled'" json:"workflow_instance_id"`

	// Relationships
	WorkflowInstance *WorkflowInstance `gorm:"foreignKey:WorkflowInstanceID" json:"workflow_instance,omitempty"`
	StepExecutions   []StepExecution   `gorm:"foreignKey:WorkflowExecutionID;constraint:OnDelete:CASCADE" json:"step_executions,omitempty"`
}

// TableName specifies the table name for WorkflowExecution
func (WorkflowExecution) TableName() string {
	return "workflow_executions"
}

// StepExecution represents the execution of a specific step within a workflow execution
type StepExecution struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created-at"`
	UpdatedAt time.Time      `json:"updated-at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Execution Information
	Status        string     `gorm:"size:50;index:idx_step_exec_workflow_status,priority:2;index:idx_step_exec_step_status,priority:2" json:"status"` // pending, blocked, in_progress, completed, failed, skipped
	StartedAt     *time.Time `json:"started-at,omitempty"`
	OverdueAt     *time.Time `json:"overdue-at,omitempty"`
	DueDate       *time.Time `gorm:"index" json:"due_date,omitempty"`
	CompletedAt   *time.Time `json:"completed-at,omitempty"`
	FailedAt      *time.Time `json:"failed-at,omitempty"`
	FailureReason string     `gorm:"type:text" json:"failure_reason,omitempty"`

	// Assignment Information
	AssignedToType string     `gorm:"size:20" json:"assigned_to_type"` // user, group, email
	AssignedToID   string     `gorm:"size:255" json:"assigned_to_id"`  // User ID, group ID, or email
	AssignedAt     *time.Time `json:"assigned-at,omitempty"`

	// Foreign Keys
	WorkflowExecutionID      *uuid.UUID `gorm:"not null;index;index:idx_step_exec_workflow_status,priority:1;uniqueIndex:uidx_step_exec_workflow_step,priority:1" json:"workflow_execution_id"`
	WorkflowStepDefinitionID *uuid.UUID `gorm:"not null;index;index:idx_step_exec_step_status,priority:1;uniqueIndex:uidx_step_exec_workflow_step,priority:2" json:"workflow_step_definition_id"`

	// Relationships
	WorkflowExecution      *WorkflowExecution        `gorm:"foreignKey:WorkflowExecutionID" json:"workflow_execution,omitempty"`
	WorkflowStepDefinition *WorkflowStepDefinition   `gorm:"foreignKey:WorkflowStepDefinitionID" json:"workflow_step_definition,omitempty"`
	StepEvidence           []StepEvidence            `gorm:"foreignKey:StepExecutionID;constraint:OnDelete:CASCADE" json:"step_evidence,omitempty"`
	ReassignmentHistory    []StepReassignmentHistory `gorm:"foreignKey:StepExecutionID;constraint:OnDelete:CASCADE" json:"reassignment_history,omitempty"`
}

// TableName specifies the table name for StepExecution
func (StepExecution) TableName() string {
	return "step_executions"
}

// StepEvidence represents evidence submitted for a specific step execution
type StepEvidence struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created-at"`
	UpdatedAt time.Time      `json:"updated-at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Evidence Information
	Name         string `gorm:"not null;size:255" json:"name"`
	Description  string `gorm:"type:text" json:"description"`
	EvidenceType string `gorm:"size:50" json:"evidence_type"` // document, attestation, screenshot, log
	FilePath     string `gorm:"size:500" json:"file_path"`    // Path to stored file
	FileSize     int64  `json:"file-size"`                    // File size in bytes
	FileHash     string `gorm:"size:64" json:"file_hash"`     // SHA-256 hash of file
	Metadata     string `gorm:"type:text" json:"metadata"`    // JSON metadata

	// Foreign Keys
	StepExecutionID *uuid.UUID `gorm:"not null;index" json:"step_execution_id"`
	EvidenceID      *uuid.UUID `gorm:"index" json:"evidence_id,omitempty"` // Link to main evidence table

	// Relationships
	StepExecution *StepExecution       `gorm:"foreignKey:StepExecutionID" json:"step_execution,omitempty"`
	Evidence      *relational.Evidence `gorm:"foreignKey:EvidenceID" json:"evidence,omitempty"`
}

// TableName specifies the table name for StepEvidence
func (StepEvidence) TableName() string {
	return "step_evidence"
}
