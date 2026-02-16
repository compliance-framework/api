package workflows

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// StepReassignmentHistory tracks reassignment events for step executions.
type StepReassignmentHistory struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created-at"`
	UpdatedAt time.Time      `json:"updated-at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	StepExecutionID     *uuid.UUID `gorm:"not null;index" json:"step_execution_id"`
	WorkflowExecutionID *uuid.UUID `gorm:"not null;index" json:"workflow_execution_id"`

	PreviousAssignedToType string `gorm:"size:20" json:"previous_assigned_to_type"`
	PreviousAssignedToID   string `gorm:"size:255" json:"previous_assigned_to_id"`
	NewAssignedToType      string `gorm:"size:20" json:"new_assigned_to_type"`
	NewAssignedToID        string `gorm:"size:255" json:"new_assigned_to_id"`

	Reason             string     `gorm:"type:text" json:"reason,omitempty"`
	ReassignedByUserID *uuid.UUID `gorm:"index" json:"reassigned_by_user_id,omitempty"`
	ReassignedByEmail  string     `gorm:"size:255" json:"reassigned_by_email,omitempty"`

	StepExecution *StepExecution `gorm:"foreignKey:StepExecutionID" json:"step_execution,omitempty"`
}

func (StepReassignmentHistory) TableName() string {
	return "step_reassignment_history"
}
