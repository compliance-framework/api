package workflows

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkflowInstance represents a specific implementation of a workflow definition
// Created by Business Units when implementing controls for specific systems
type WorkflowInstance struct {
	relational.UUIDModel
	CreatedAt time.Time      `json:"created-at"`
	UpdatedAt time.Time      `json:"updated-at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Basic Information
	Name        string `gorm:"not null;size:255" json:"name"`
	Description string `gorm:"type:text" json:"description"`

	// Instance Configuration
	Cadence  string `gorm:"size:50" json:"cadence"` // daily, weekly, monthly, quarterly, annually
	IsActive bool   `gorm:"default:true" json:"is_active"`

	// Scheduling
	NextScheduledAt *time.Time `json:"next-scheduled-at,omitempty"`
	LastExecutedAt  *time.Time `json:"last-executed-at,omitempty"`

	// Audit Fields
	CreatedByID *uuid.UUID `gorm:"index" json:"created_by_id,omitempty"`
	UpdatedByID *uuid.UUID `gorm:"index" json:"updated_by_id,omitempty"`

	// Foreign Keys
	WorkflowDefinitionID *uuid.UUID `gorm:"not null;index" json:"workflow_definition_id"`
	SystemSecurityPlanID *uuid.UUID `gorm:"not null;index" json:"system_id"`
	// Relationships
	SystemSecurityPlan *relational.SystemSecurityPlan `gorm:"foreignKey:SystemSecurityPlanID" json:"system_security_plan,omitempty"`
	WorkflowDefinition *WorkflowDefinition            `gorm:"foreignKey:WorkflowDefinitionID" json:"workflow_definition,omitempty"`
	RoleAssignments    []RoleAssignment               `gorm:"foreignKey:WorkflowInstanceID;constraint:OnDelete:CASCADE" json:"role_assignments,omitempty"`
	Executions         []WorkflowExecution            `gorm:"foreignKey:WorkflowInstanceID;constraint:OnDelete:CASCADE" json:"executions,omitempty"`
}

// TableName specifies the table name for WorkflowInstance
func (WorkflowInstance) TableName() string {
	return "workflow_instances"
}

// RoleAssignment represents the assignment of roles to specific users or groups for a workflow instance
type RoleAssignment struct {
	relational.UUIDModel
	WorkflowInstanceID *uuid.UUID `gorm:"not null;index" json:"workflow_instance_id"`
	RoleName           string     `gorm:"not null;size:255" json:"role_name"`
	AssignedToType     string     `gorm:"size:20" json:"assigned_to_type"` // user, group, email
	AssignedToID       string     `gorm:"size:255" json:"assigned_to_id"`  // User ID, group ID, or email
	IsActive           bool       `gorm:"default:true" json:"is_active"`

	// Relationships
	WorkflowInstance *WorkflowInstance `gorm:"foreignKey:WorkflowInstanceID" json:"workflow_instance,omitempty"`
}

// TableName specifies the table name for RoleAssignment
func (RoleAssignment) TableName() string {
	return "role_assignments"
}
