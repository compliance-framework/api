package handler

import (
	"log"

	"github.com/compliance-framework/api/internal/api"
	templatehandlers "github.com/compliance-framework/api/internal/api/handler/templates"
	"github.com/compliance-framework/api/internal/api/handler/workflows"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/digest"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	workflowsvc "github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// APIServices contains all services needed by API handlers
type APIServices struct {
	EvidenceService      *evidencesvc.EvidenceService
	WorkerService        evidencesvc.RiskJobEnqueuer
	DigestService        *digest.Service
	WorkflowManager      *workflow.Manager
	NotificationEnqueuer workflow.NotificationEnqueuer
	DAGExecutor          *workflow.DAGExecutor
}

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, services *APIServices) {
	healthHandler := NewHealthHandler(logger, db)
	healthHandler.Register(server.API().Group("/health"))

	filterHandler := NewFilterHandler(logger, db)
	filterHandler.Register(server.API().Group("/filters"))

	heartbeatHandler := NewHeartbeatHandler(logger, db)
	heartbeatHandler.Register(server.API().Group("/agent/heartbeat"))

	evidenceHandler := NewEvidenceHandler(logger, services.EvidenceService, config)
	evidenceHandler.Register(server.API().Group("/evidence"))

	riskHandler := NewRiskHandler(logger, db)
	riskGroup := server.API().Group("/risks")
	riskGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskHandler.Register(riskGroup)

	riskTemplateHandler := templatehandlers.NewRiskTemplateHandler(logger, db)
	riskTemplateGroup := server.API().Group("/risk-templates")
	riskTemplateGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskTemplateHandler.Register(riskTemplateGroup)

	subjectTemplateHandler := templatehandlers.NewSubjectTemplateHandler(logger, db)
	subjectTemplateGroup := server.API().Group("/subject-templates")
	subjectTemplateGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	subjectTemplateHandler.Register(subjectTemplateGroup)

	evidenceTemplateHandler := templatehandlers.NewEvidenceTemplateHandler(logger, db)
	evidenceTemplateGroup := server.API().Group("/evidence-templates")
	evidenceTemplateGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	evidenceTemplateHandler.Register(evidenceTemplateGroup)

	userHandler := NewUserHandler(logger, db)

	adminGroup := server.API().Group("/admin/users")
	adminGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	adminGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	userHandler.Register(adminGroup)

	userGroup := server.API().Group("/users")
	userGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler.RegisterSelfRoutes(userGroup)

	// Digest handler (admin only)
	if services.DigestService != nil {
		digestHandler := NewDigestHandler(services.DigestService, logger)
		digestGroup := server.API().Group("/admin/digest")
		digestGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
		digestGroup.Use(middleware.RequireAdminGroups(db, config, logger))
		digestHandler.Register(digestGroup)
	}

	// Register workflow handlers
	registerWorkflowHandlers(server, logger, db, config, services.WorkflowManager, services.NotificationEnqueuer, services.DAGExecutor)
}

// registerWorkflowHandlers registers all workflow-related HTTP handlers with authentication
func registerWorkflowHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, workflowManager *workflow.Manager, notificationEnqueuer workflow.NotificationEnqueuer, dagExecutor *workflow.DAGExecutor) {
	// Create workflow group with authentication middleware
	workflowGroup := server.API().Group("/workflows")
	workflowGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))

	// Basic workflow handlers (no manager dependency)
	workflowDefinitionHandler := workflows.NewWorkflowDefinitionHandler(logger, db)
	workflowDefinitionHandler.Register(workflowGroup.Group("/definitions"))

	workflowStepDefinitionHandler := workflows.NewWorkflowStepDefinitionHandler(logger, db)
	workflowStepDefinitionHandler.Register(workflowGroup.Group("/steps"))

	workflowInstanceHandler := workflows.NewWorkflowInstanceHandler(logger, db)
	workflowInstanceHandler.Register(workflowGroup.Group("/instances"))

	controlRelationshipHandler := workflows.NewControlRelationshipHandler(logger, db)
	controlRelationshipHandler.Register(workflowGroup.Group("/control-relationships"))

	roleAssignmentHandler := workflows.NewRoleAssignmentHandler(logger, db)
	roleAssignmentHandler.Register(workflowGroup.Group("/role-assignments"))

	// Handlers that require workflow manager
	if workflowManager != nil {
		registerWorkflowExecutionHandlers(workflowGroup, logger, db, workflowManager, notificationEnqueuer, dagExecutor)
	}
}

// registerWorkflowExecutionHandlers registers execution-related handlers that require the workflow manager
func registerWorkflowExecutionHandlers(workflowGroup *echo.Group, logger *zap.SugaredLogger, db *gorm.DB, workflowManager *workflow.Manager, notificationEnqueuer workflow.NotificationEnqueuer, dagExecutor *workflow.DAGExecutor) {
	roleAssignmentService := workflowsvc.NewRoleAssignmentService(db)
	stepExecService := workflowsvc.NewStepExecutionService(db, nil)
	assignmentService := workflow.NewAssignmentService(roleAssignmentService, stepExecService, db, logger, notificationEnqueuer)

	// Workflow execution handler
	workflowExecutionHandler := workflows.NewWorkflowExecutionHandler(logger, db, workflowManager, assignmentService)
	workflowExecutionHandler.Register(workflowGroup.Group("/executions"))

	// Step execution handler with transition service
	transitionService := createStepTransitionService(db, logger, notificationEnqueuer, dagExecutor)
	stepExecutionHandler := workflows.NewStepExecutionHandler(logger, db, transitionService, assignmentService)
	stepExecutionHandler.Register(workflowGroup.Group("/step-executions"))
}

// createStepTransitionService creates and configures the step transition service with all dependencies
func createStepTransitionService(db *gorm.DB, logger *zap.SugaredLogger, notificationEnqueuer workflow.NotificationEnqueuer, executor *workflow.DAGExecutor) *workflow.StepTransitionService {
	// Create services needed for step transition
	stepExecService := workflowsvc.NewStepExecutionService(db, nil)
	stepDefService := workflowsvc.NewWorkflowStepDefinitionService(db)
	workflowExecService := workflowsvc.NewWorkflowExecutionService(db)
	workflowInstanceService := workflowsvc.NewWorkflowInstanceService(db)
	workflowDefinitionService := workflowsvc.NewWorkflowDefinitionService(db)
	roleAssignmentService := workflowsvc.NewRoleAssignmentService(db)

	// Create assignment service
	assignmentService := workflow.NewAssignmentService(roleAssignmentService, stepExecService, db, logger, notificationEnqueuer)

	// Create evidence integration for step evidence storage
	evidenceIntegration := workflow.NewEvidenceIntegration(db, logger)

	// Set evidence creator on services
	stepExecService.SetEvidenceCreator(evidenceIntegration)
	workflowExecService.SetEvidenceCreator(evidenceIntegration)

	// Use the shared executor from the worker service when available so that there is exactly
	// one DAGExecutor instance (consistent logger, notifications, and evidence integration).
	// Fall back to constructing a local executor when the worker is disabled (executor == nil).
	if executor == nil {
		executor = workflow.NewDAGExecutor(
			stepExecService,
			workflowExecService,
			stepDefService,
			assignmentService,
			log.Default(),
			notificationEnqueuer,
		)
	}

	// Create and return step transition service
	return workflow.NewStepTransitionService(
		stepExecService,
		stepDefService,
		workflowExecService,
		roleAssignmentService,
		workflowInstanceService,
		workflowDefinitionService,
		executor,
		db,
		evidenceIntegration,
	)
}
