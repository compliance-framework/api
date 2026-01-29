package workflows

import (
	"gorm.io/gorm"
)

// ServiceManager provides a unified interface to all workflow services
type ServiceManager struct {
	WorkflowDefinition  *WorkflowDefinitionService
	WorkflowStep        *WorkflowStepDefinitionService
	WorkflowInstance    *WorkflowInstanceService
	WorkflowExecution   *WorkflowExecutionService
	StepExecution       *StepExecutionService
	RoleAssignment      *RoleAssignmentService
	ControlRelationship *ControlRelationshipService
	db                  *gorm.DB
}

// NewServiceManager creates a new ServiceManager with all workflow services
func NewServiceManager(db *gorm.DB) *ServiceManager {
	return &ServiceManager{
		WorkflowDefinition:  NewWorkflowDefinitionService(db),
		WorkflowStep:        NewWorkflowStepDefinitionService(db),
		WorkflowInstance:    NewWorkflowInstanceService(db),
		WorkflowExecution:   NewWorkflowExecutionService(db),
		StepExecution:       NewStepExecutionService(db),
		RoleAssignment:      NewRoleAssignmentService(db),
		ControlRelationship: NewControlRelationshipService(db),
		db:                  db,
	}
}

// DB returns the underlying database connection
func (sm *ServiceManager) DB() *gorm.DB {
	return sm.db
}

// Transaction executes a function within a database transaction
func (sm *ServiceManager) Transaction(fn func(*ServiceManager) error) error {
	return sm.db.Transaction(func(tx *gorm.DB) error {
		txManager := NewServiceManager(tx)
		return fn(txManager)
	})
}
