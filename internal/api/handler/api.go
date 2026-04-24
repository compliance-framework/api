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
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	workflowsvc "github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// APIServices contains all services needed by API handlers
type APIServices struct {
	EvidenceService      *evidencesvc.EvidenceService
	RiskEnqueuer         evidencesvc.RiskJobEnqueuer
	DigestService        *digest.Service
	WorkflowManager      *workflow.Manager
	NotificationEnqueuer workflow.NotificationEnqueuer
	DAGExecutor          *workflow.DAGExecutor
}

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, services *APIServices) {
	if services == nil {
		services = &APIServices{}
	}
	// Default EvidenceService when callers (e.g. test suites) don't provide one.
	if services.EvidenceService == nil {
		services.EvidenceService = evidencesvc.NewEvidenceService(db, logger, config, services.RiskEnqueuer)
	}

	healthHandler := NewHealthHandler(logger, db)
	healthHandler.Register(server.API().Group("/health"))

	filterHandler := NewFilterHandler(logger, db)
	filterHandler.Register(server.API().Group("/filters"))

	heartbeatHandler := NewHeartbeatHandler(logger, db)
	agentIngestMiddleware := middleware.AgentJWTOrPublicMiddleware(db, config.JWTPublicKey, !config.StrictDisablePublicAgentEndpoints)
	heartbeatHandler.RegisterCreate(server.API().Group("/agent/heartbeat"), agentIngestMiddleware)
	// Keep the legacy operator-facing metrics route stable while protecting it with user auth.
	heartbeatHandler.RegisterOverTime(server.API().Group("/agent/heartbeat"), middleware.JWTMiddleware(config.JWTPublicKey))

	evidenceHandler := NewEvidenceHandler(logger, services.EvidenceService)
	evidenceGroup := server.API().Group("/evidence")
	evidenceHandler.RegisterCreate(
		evidenceGroup,
		middleware.OptionalUserOrAgentJWTMiddleware(db, config.JWTPublicKey, !config.StrictDisablePublicAgentEndpoints),
	)
	evidenceHandler.RegisterReadRoutes(evidenceGroup)
	evidenceSignatureGroup := server.API().Group("/evidence")
	evidenceSignatureGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	evidenceHandler.RegisterSignatureRoutes(evidenceSignatureGroup)

	poamService := poamsvc.NewPoamService(db)
	riskService := riskrel.NewRiskService(db)
	poamHandler := NewPoamItemsHandler(poamService, riskService, logger)
	// Flat route: /api/poam-items (supports ?sspId= query filter)
	poamGroup := server.API().Group("/poam-items")
	poamGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	poamHandler.Register(poamGroup)
	// SSP-scoped route: /api/system-security-plans/:sspId/poam-items
	// The :sspId path param is automatically injected into list/create filters.
	sspPoamGroup := server.API().Group("/system-security-plans/:sspId/poam-items")
	sspPoamGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	poamHandler.RegisterSSPScoped(sspPoamGroup)

	riskHandler := NewRiskHandler(logger, db, poamService, riskService)
	riskGroup := server.API().Group("/risks")
	riskGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskHandler.Register(riskGroup)

	sspRiskGroup := server.API().Group("/oscal/system-security-plans/:sspId/risks")
	sspRiskGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskHandler.RegisterSSPScoped(sspRiskGroup)
	riskTemplateHandler := templatehandlers.NewRiskTemplateHandler(logger, db)
	riskTemplateGroup := server.API().Group("/admin/risk-templates")
	riskTemplateGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskTemplateGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	riskTemplateHandler.Register(riskTemplateGroup)

	agentRiskTemplateGroup := server.API().Group("/agent/risk-templates")
	riskTemplateHandler.RegisterAgent(agentRiskTemplateGroup, agentIngestMiddleware)

	subjectTemplateHandler := templatehandlers.NewSubjectTemplateHandler(logger, db)
	subjectTemplateGroup := server.API().Group("/admin/subject-templates")
	subjectTemplateGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	subjectTemplateGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	subjectTemplateHandler.Register(subjectTemplateGroup)

	agentSubjectTemplateGroup := server.API().Group("/agent/subject-templates")
	subjectTemplateHandler.RegisterAgent(agentSubjectTemplateGroup, agentIngestMiddleware)

	agentHandler := NewAgentHandler(logger, db)
	agentsGroup := server.API().Group("/admin/agents")
	agentsGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	agentsGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	agentHandler.Register(agentsGroup)

	userHandler := NewUserHandler(logger, db)

	adminGroup := server.API().Group("/admin/users")
	adminGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	adminGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	userHandler.Register(adminGroup)

	selfGroup := server.API().Group("/users/me")
	selfGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler.RegisterSelfRoutes(selfGroup)

	userGroup := server.API().Group("/users")
	userGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler.RegisterPublicRoutes(userGroup)

	notificationsHandler := NewNotificationsHandler(logger, db, config)
	notificationsGroup := server.API().Group("/admin/notifications")
	notificationsGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	notificationsGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	notificationsHandler.Register(notificationsGroup)

	// Digest handler (admin only)
	if services.DigestService != nil {
		digestHandler := NewDigestHandler(services.DigestService, logger)
		digestGroup := server.API().Group("/admin/digest")
		digestGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
		digestGroup.Use(middleware.RequireAdminGroups(db, config, logger))
		digestHandler.Register(digestGroup)
	}

	// Register workflow handlers
	registerWorkflowHandlers(server, logger, db, config, services, services.WorkflowManager, services.NotificationEnqueuer, services.DAGExecutor)
}

// registerWorkflowHandlers registers all workflow-related HTTP handlers with authentication
func registerWorkflowHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, services *APIServices, workflowManager *workflow.Manager, notificationEnqueuer workflow.NotificationEnqueuer, dagExecutor *workflow.DAGExecutor) {
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
		registerWorkflowExecutionHandlers(workflowGroup, logger, db, config, services.EvidenceService, workflowManager, notificationEnqueuer, dagExecutor)
	}
}

// registerWorkflowExecutionHandlers registers execution-related handlers that require the workflow manager
func registerWorkflowExecutionHandlers(workflowGroup *echo.Group, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, evidenceService *evidencesvc.EvidenceService, workflowManager *workflow.Manager, notificationEnqueuer workflow.NotificationEnqueuer, dagExecutor *workflow.DAGExecutor) {
	roleAssignmentService := workflowsvc.NewRoleAssignmentService(db)
	stepExecService := workflowsvc.NewStepExecutionService(db, nil)
	assignmentService := workflow.NewAssignmentService(roleAssignmentService, stepExecService, db, logger, notificationEnqueuer)

	// Workflow execution handler
	workflowExecutionHandler := workflows.NewWorkflowExecutionHandler(logger, db, workflowManager, assignmentService)
	workflowExecutionHandler.Register(workflowGroup.Group("/executions"))

	// Step execution handler with transition service
	transitionService := createStepTransitionService(db, logger, config, evidenceService, notificationEnqueuer, dagExecutor)
	stepExecutionHandler := workflows.NewStepExecutionHandler(logger, db, transitionService, assignmentService)
	stepExecutionHandler.Register(workflowGroup.Group("/step-executions"))
}

// createStepTransitionService creates and configures the step transition service with all dependencies
func createStepTransitionService(db *gorm.DB, logger *zap.SugaredLogger, config *config.Config, evidenceService *evidencesvc.EvidenceService, notificationEnqueuer workflow.NotificationEnqueuer, executor *workflow.DAGExecutor) *workflow.StepTransitionService {
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
	if evidenceService == nil {
		evidenceService = evidencesvc.NewEvidenceService(db, logger, config, nil)
	}

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
		evidenceService,
		evidenceIntegration,
	)
}
