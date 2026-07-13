package handler

import (
	"log"

	"github.com/compliance-framework/api/internal/api"
	templatehandlers "github.com/compliance-framework/api/internal/api/handler/templates"
	"github.com/compliance-framework/api/internal/api/handler/workflows"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/notification"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	workflowsvc "github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// APIServices contains all services needed by API handlers
type APIServices struct {
	EvidenceService            *evidencesvc.EvidenceService
	RiskEnqueuer               evidencesvc.RiskJobEnqueuer
	DigestService              *digest.Service
	WorkflowManager            *workflow.Manager
	NotificationEnqueuer       workflow.NotificationEnqueuer
	NotificationWorkerEnqueuer notification.WorkerEnqueuer
	DAGExecutor                *workflow.DAGExecutor
	// PEP is the shared, config-selected Policy Enforcement Point used by every guarded
	// route. cmd/run.go builds it once (around the configured PDP) and passes it in; when
	// nil (e.g. test suites) RegisterHandlers falls back to a builtin-backed PEP, which
	// reproduces the prior access rules with no behavior change.
	PEP *middleware.PEP
}

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, services *APIServices) {
	if services == nil {
		services = &APIServices{}
	}
	// Default EvidenceService when callers (e.g. test suites) don't provide one.
	if services.EvidenceService == nil {
		services.EvidenceService = evidencesvc.NewEvidenceService(db, logger, config, services.RiskEnqueuer)
	}

	// Central authorization: every guarded route enforces via the shared, config-selected
	// PEP (built once in cmd/run.go). Routes call pep.Authorize(resource, action) — or a
	// resource-bound guard, pep.For(resource) — instead of ad-hoc checks. When no PEP is
	// supplied (test suites), fall back to a builtin-backed PEP, which reproduces the prior
	// access rules with no behavior change.
	pep := services.PEP
	if pep == nil {
		failMode := authz.FailClosed
		if config.Authz != nil {
			failMode = authz.ParseFailMode(config.Authz.FailMode)
		}
		pep = middleware.NewPEP(authz.NewBuiltin(db, config, logger), failMode, logger)
	}
	pdp := pep.PDP()
	failMode := pep.FailMode()
	authzManifest, err := authz.DefaultManifest()
	if err != nil {
		logger.Fatalw("Failed to load authorization manifest", "error", err)
	}

	healthHandler := NewHealthHandler(logger, db).WithPDP(pdp)
	healthHandler.Register(server.API().Group("/health"))

	// /me/permissions: the authenticated subject's allowed (resource, action) pairs via a
	// single batch PDP call, so the UI can hide actions the user can't perform (BCH-1318).
	permissionsHandler := NewPermissionsHandler(pdp, authzManifest, failMode, logger)
	meGroup := server.API().Group("/me")
	meGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	permissionsHandler.Register(meGroup, pep.For(authz.ResourceUser))

	filterHandler := NewFilterHandler(logger, db)
	filterGroup := server.API().Group("/filters")
	filterGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	filterHandler.Register(filterGroup, pep.For(authz.ResourceFilter))

	// Policies & Procedures + Compliance Lineage.
	controlLinkHandler := NewControlLinkHandler(logger, db)
	controlLinkGroup := server.API().Group("/control-links")
	controlLinkGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	controlLinkHandler.Register(controlLinkGroup, pep.For(authz.ResourceControlLink))

	lineageHandler := NewLineageHandler(logger, db)
	lineageGroup := server.API().Group("/lineage")
	lineageGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	lineageHandler.Register(lineageGroup, pep.For(authz.ResourceLineage))

	heartbeatHandler := NewHeartbeatHandler(logger, db)
	heartbeatGuard := pep.For(authz.ResourceHeartbeat)
	agentIngestMiddleware := middleware.AgentJWTOrPublicMiddleware(db, config.JWTPublicKey, !config.StrictDisablePublicAgentEndpoints)
	heartbeatHandler.RegisterCreate(server.API().Group("/agent/heartbeat"), agentIngestMiddleware, heartbeatGuard.Do(authz.ActionIngest))
	// Keep the legacy operator-facing metrics route stable while protecting it with user auth.
	heartbeatHandler.RegisterOverTime(server.API().Group("/agent/heartbeat"), middleware.JWTMiddleware(config.JWTPublicKey), heartbeatGuard.Read())

	riskService := riskrel.NewRiskService(db)
	riskGuard := pep.For(authz.ResourceRisk)

	evidenceHandler := NewEvidenceHandler(logger, services.EvidenceService, riskService)
	evidenceGuard := pep.For(authz.ResourceEvidence)
	evidenceGroup := server.API().Group("/evidence")
	evidenceHandler.RegisterCreate(
		evidenceGroup,
		middleware.OptionalUserOrAgentJWTMiddleware(db, config.JWTPublicKey, !config.StrictDisablePublicAgentEndpoints),
		evidenceGuard.Create(),
	)
	// Read routes carry no group auth (intentionally public); attach optional auth so a token,
	// when present, identifies the subject for cedar while builtin still allows anonymous reads.
	evidenceHandler.RegisterReadRoutes(
		evidenceGroup,
		middleware.OptionalUserOrAgentJWTMiddleware(db, config.JWTPublicKey, !config.StrictDisablePublicAgentEndpoints),
		evidenceGuard.Read(),
	)
	evidenceSignatureGroup := server.API().Group("/evidence")
	evidenceSignatureGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	evidenceHandler.RegisterSignatureRoutes(evidenceSignatureGroup, evidenceGuard.Read())

	// Evidence→risk lookups return risk register data, so they need auth and the risk
	// read guard rather than joining the intentionally anonymous evidence read routes.
	evidenceRiskGroup := server.API().Group("/evidence")
	evidenceRiskGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	evidenceHandler.RegisterRiskRoutes(evidenceRiskGroup, riskGuard.Read())

	poamService := poamsvc.NewPoamService(db)
	poamHandler := NewPoamItemsHandler(poamService, riskService, logger)
	// Flat route: /api/poam-items (supports ?sspId= query filter)
	poamGroup := server.API().Group("/poam-items")
	poamGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	poamGuard := pep.For(authz.ResourcePoamItem)
	poamHandler.Register(poamGroup, poamGuard)
	// SSP-scoped route: /api/system-security-plans/:sspId/poam-items
	// The :sspId path param is automatically injected into list/create filters.
	sspPoamGroup := server.API().Group("/system-security-plans/:sspId/poam-items")
	sspPoamGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	poamHandler.RegisterSSPScoped(sspPoamGroup, poamGuard)

	riskHandler := NewRiskHandler(logger, db, poamService, riskService)
	riskGroup := server.API().Group("/risks")
	riskGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskHandler.Register(riskGroup, riskGuard)

	sspRiskGroup := server.API().Group("/oscal/system-security-plans/:sspId/risks")
	sspRiskGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskHandler.RegisterSSPScoped(sspRiskGroup, riskGuard)
	riskTemplateHandler := templatehandlers.NewRiskTemplateHandler(logger, db)
	riskTemplateGroup := server.API().Group("/admin/risk-templates")
	riskTemplateGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	riskTemplateGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
	riskTemplateHandler.Register(riskTemplateGroup)

	agentRiskTemplateGroup := server.API().Group("/agent/risk-templates")
	// Agent-facing batch upsert reconciles the template set → update of risk-template.
	riskTemplateHandler.RegisterAgent(agentRiskTemplateGroup, agentIngestMiddleware, pep.For(authz.ResourceRiskTemplate).Update())

	subjectTemplateHandler := templatehandlers.NewSubjectTemplateHandler(logger, db)
	subjectTemplateGroup := server.API().Group("/admin/subject-templates")
	subjectTemplateGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	subjectTemplateGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
	subjectTemplateHandler.Register(subjectTemplateGroup)

	agentSubjectTemplateGroup := server.API().Group("/agent/subject-templates")
	subjectTemplateHandler.RegisterAgent(agentSubjectTemplateGroup, agentIngestMiddleware, pep.For(authz.ResourceSubjectTemplate).Update())

	agentHandler := NewAgentHandler(logger, db)
	agentsGroup := server.API().Group("/admin/agents")
	agentsGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	agentsGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
	agentHandler.Register(agentsGroup)

	userHandler := NewUserHandler(logger, db)

	adminGroup := server.API().Group("/admin/users")
	adminGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	adminGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
	userHandler.Register(adminGroup)

	userGuard := pep.For(authz.ResourceUser)
	selfGroup := server.API().Group("/users/me")
	selfGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler.RegisterSelfRoutes(selfGroup, userGuard)

	userGroup := server.API().Group("/users")
	userGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler.RegisterPublicRoutes(userGroup, userGuard)

	groupsHandler := NewGroupsHandler(logger, db)
	groupsGroup := server.API().Group("/admin/groups")
	groupsGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	groupsGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
	groupsHandler.Register(groupsGroup)

	// System-level role assignments (BCH-1333). Gated on the role-assignment resource (like the
	// workflow role-assignment handler), not the admin umbrella, so the manifest's role-assignment
	// grants govern it. The effective-role reads hang off the existing admin user/group trees.
	roleAssignmentsHandler := NewRoleAssignmentsHandler(logger, db)
	roleAssignmentsGuard := pep.For(authz.ResourceRoleAssignment)

	roleAssignmentsGroup := server.API().Group("/admin/role-assignments")
	roleAssignmentsGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	roleAssignmentsHandler.Register(roleAssignmentsGroup, roleAssignmentsGuard)

	adminUserRolesGroup := server.API().Group("/admin/users")
	adminUserRolesGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	roleAssignmentsHandler.RegisterUserRoles(adminUserRolesGroup, roleAssignmentsGuard)

	adminGroupRolesGroup := server.API().Group("/admin/groups")
	adminGroupRolesGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	roleAssignmentsHandler.RegisterGroupRoles(adminGroupRolesGroup, roleAssignmentsGuard)

	notificationsHandler := NewNotificationsHandler(logger, db, config, services.NotificationWorkerEnqueuer)
	notificationsPublicGroup := server.API().Group("/notifications")
	notificationsPublicGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	notificationsHandler.RegisterPublic(notificationsPublicGroup, pep.For(authz.ResourceNotification))

	notificationsGroup := server.API().Group("/admin/notifications")
	notificationsGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	notificationsGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
	notificationsHandler.Register(notificationsGroup)

	// Digest handler (admin only)
	if services.DigestService != nil {
		digestHandler := NewDigestHandler(services.DigestService, logger)
		digestGroup := server.API().Group("/admin/digest")
		digestGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
		digestGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
		digestHandler.Register(digestGroup)
	}

	// Register workflow handlers
	registerWorkflowHandlers(server, logger, db, config, pep, services, services.WorkflowManager, services.NotificationEnqueuer, services.DAGExecutor)
}

// registerWorkflowHandlers registers all workflow-related HTTP handlers with authentication
func registerWorkflowHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, pep *middleware.PEP, services *APIServices, workflowManager *workflow.Manager, notificationEnqueuer workflow.NotificationEnqueuer, dagExecutor *workflow.DAGExecutor) {
	// Create workflow group with authentication middleware
	workflowGroup := server.API().Group("/workflows")
	workflowGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))

	// Basic workflow handlers (no manager dependency)
	workflowDefinitionHandler := workflows.NewWorkflowDefinitionHandler(logger, db)
	workflowDefinitionHandler.Register(workflowGroup.Group("/definitions"), pep.For(authz.ResourceWorkflowDefinition))

	workflowImportHandler := workflows.NewWorkflowImportHandler(logger, db)
	// Bulk workflow import stays admin-gated (was RequireAdminGroups) — map to admin/manage so
	// builtin behavior is unchanged and cedar gates it on the admin role rather than import.
	workflowGroup.POST(
		"/import",
		workflowImportHandler.Import,
		pep.Authorize(authz.ResourceAdmin, authz.ActionManage),
		echomiddleware.BodyLimit(workflows.WorkflowImportBodyLimit),
	)

	workflowStepDefinitionHandler := workflows.NewWorkflowStepDefinitionHandler(logger, db)
	workflowStepDefinitionHandler.Register(workflowGroup.Group("/steps"), pep.For(authz.ResourceWorkflowStepDefinition))

	workflowInstanceHandler := workflows.NewWorkflowInstanceHandler(logger, db)
	workflowInstanceHandler.Register(workflowGroup.Group("/instances"), pep.For(authz.ResourceWorkflowInstance))

	controlRelationshipHandler := workflows.NewControlRelationshipHandler(logger, db)
	controlRelationshipHandler.Register(workflowGroup.Group("/control-relationships"), pep.For(authz.ResourceControlRelationship))

	roleAssignmentHandler := workflows.NewRoleAssignmentHandler(logger, db)
	roleAssignmentHandler.Register(workflowGroup.Group("/role-assignments"), pep.For(authz.ResourceRoleAssignment))

	// Handlers that require workflow manager
	if workflowManager != nil {
		registerWorkflowExecutionHandlers(workflowGroup, logger, db, config, pep, services.EvidenceService, workflowManager, notificationEnqueuer, dagExecutor)
	}
}

// registerWorkflowExecutionHandlers registers execution-related handlers that require the workflow manager
func registerWorkflowExecutionHandlers(workflowGroup *echo.Group, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, pep *middleware.PEP, evidenceService *evidencesvc.EvidenceService, workflowManager *workflow.Manager, notificationEnqueuer workflow.NotificationEnqueuer, dagExecutor *workflow.DAGExecutor) {
	roleAssignmentService := workflowsvc.NewRoleAssignmentService(db)
	stepExecService := workflowsvc.NewStepExecutionService(db, nil)
	assignmentService := workflow.NewAssignmentService(roleAssignmentService, stepExecService, db, logger, notificationEnqueuer)

	// Workflow execution handler
	workflowExecutionHandler := workflows.NewWorkflowExecutionHandler(logger, db, workflowManager, assignmentService)
	workflowExecutionHandler.Register(workflowGroup.Group("/executions"), pep.For(authz.ResourceWorkflowExecution))

	// Step execution handler with transition service
	transitionService := createStepTransitionService(db, logger, config, evidenceService, notificationEnqueuer, dagExecutor)
	stepExecutionHandler := workflows.NewStepExecutionHandler(logger, db, transitionService, assignmentService)
	stepExecutionHandler.Register(workflowGroup.Group("/step-executions"), pep.For(authz.ResourceStepExecution))
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
