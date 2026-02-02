package handler

import (
	"log"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler/workflows"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/digest"
	workflowsvc "github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/service/scheduler"
	"github.com/compliance-framework/api/internal/workflow"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, digestService *digest.Service, sched scheduler.Scheduler, workflowManager *workflow.Manager) {
	healthHandler := NewHealthHandler(logger, db)
	healthHandler.Register(server.API().Group("/health"))

	filterHandler := NewFilterHandler(logger, db)
	filterHandler.Register(server.API().Group("/filters"))

	heartbeatHandler := NewHeartbeatHandler(logger, db)
	heartbeatHandler.Register(server.API().Group("/agent/heartbeat"))

	evidenceHandler := NewEvidenceHandler(logger, db, config)
	evidenceHandler.Register(server.API().Group("/evidence"))

	userHandler := NewUserHandler(logger, db)

	adminGroup := server.API().Group("/admin/users")
	adminGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	adminGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	userHandler.Register(adminGroup)

	userGroup := server.API().Group("/users")
	userGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler.RegisterSelfRoutes(userGroup)

	// Digest handler (admin only)
	if digestService != nil && sched != nil {
		digestHandler := NewDigestHandler(digestService, sched, logger)
		digestGroup := server.API().Group("/admin/digest")
		digestGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
		digestGroup.Use(middleware.RequireAdminGroups(db, config, logger))
		digestHandler.Register(digestGroup)
	}

	// Workflow handlers
	workflowDefinitionHandler := workflows.NewWorkflowDefinitionHandler(logger, db)
	workflowDefinitionHandler.Register(server.API().Group("/workflows/definitions"))

	workflowStepDefinitionHandler := workflows.NewWorkflowStepDefinitionHandler(logger, db)
	workflowStepDefinitionHandler.Register(server.API().Group("/workflows/steps"))

	workflowInstanceHandler := workflows.NewWorkflowInstanceHandler(logger, db)
	workflowInstanceHandler.Register(server.API().Group("/workflows/instances"))

	// Workflow execution handler requires the manager
	if workflowManager != nil {
		workflowExecutionHandler := workflows.NewWorkflowExecutionHandler(logger, db, workflowManager)
		workflowExecutionHandler.Register(server.API().Group("/workflows/executions"))
	}

	// Step execution handler with transition service
	if workflowManager != nil {
		// Create services needed for step transition
		stepExecService := workflowsvc.NewStepExecutionService(db, nil)
		stepDefService := workflowsvc.NewWorkflowStepDefinitionService(db)
		workflowExecService := workflowsvc.NewWorkflowExecutionService(db)
		workflowInstanceService := workflowsvc.NewWorkflowInstanceService(db)
		workflowDefinitionService := workflowsvc.NewWorkflowDefinitionService(db)
		roleAssignmentService := workflowsvc.NewRoleAssignmentService(db)

		// Create executor for step transition coordination
		stdLogger := log.Default()
		executor := workflow.NewDAGExecutor(
			stepExecService,
			workflowExecService,
			stepDefService,
			stdLogger,
		)

		// Create evidence integration for step evidence storage
		evidenceIntegration := workflow.NewEvidenceIntegration(db, logger)

		// Set evidence creator on step execution service
		stepExecService.SetEvidenceCreator(evidenceIntegration)

		// Set evidence creator on workflow execution service
		workflowExecService.SetEvidenceCreator(evidenceIntegration)

		// Create step transition service
		transitionService := workflow.NewStepTransitionService(
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

		stepExecutionHandler := workflows.NewStepExecutionHandler(logger, db, transitionService)
		stepExecutionHandler.Register(server.API().Group("/workflows/step-executions"))
	}

	// Control relationship handler
	controlRelationshipHandler := workflows.NewControlRelationshipHandler(logger, db)
	controlRelationshipHandler.Register(server.API().Group("/workflows/control-relationships"))

	// Role assignment handler
	roleAssignmentHandler := workflows.NewRoleAssignmentHandler(logger, db)
	roleAssignmentHandler.Register(server.API().Group("/workflows/role-assignments"))
}
