package oscal

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RegisterHandlers mounts the OSCAL route groups. pep is the shared, config-selected Policy
// Enforcement Point (cmd/run.go builds it once); callers that pass nil (e.g. test suites) get a
// builtin-backed PEP, reproducing the prior access rules with no behavior change.
func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, evidenceSvc *evidencesvc.EvidenceService, jobEnqueuer SSPJobEnqueuer, pep *middleware.PEP) {
	if pep == nil {
		failMode := authz.FailClosed
		if config.Authz != nil {
			failMode = authz.ParseFailMode(config.Authz.FailMode)
		}
		pep = middleware.NewPEP(authz.NewBuiltin(db, config, logger), failMode, logger)
	}

	oscalGroup := server.API().Group("/oscal")
	oscalGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	jwtMiddleware := middleware.JWTMiddleware(config.JWTPublicKey)

	dashboardSuggestionHandler := NewDashboardSuggestionHandler(logger, db, config.AI, jobEnqueuer)
	dashboardGuard := pep.For(authz.ResourceDashboardSuggestion)
	// /dashboard-suggestions/config carries no group auth (intentionally public); attach
	// optional auth so a token, when present, identifies the subject for cedar.
	dashboardSuggestionHandler.RegisterConfig(
		server.API().Group("/dashboard-suggestions"),
		middleware.OptionalUserOrAgentJWTMiddleware(db, config.JWTPublicKey, !config.StrictDisablePublicAgentEndpoints),
		dashboardGuard.Read(),
	)

	catalogHandler := NewCatalogHandler(logger, db)
	catalogHandler.Register(oscalGroup.Group("/catalogs"), pep.For(authz.ResourceCatalog))

	profileHandler := NewProfileHandler(logger, db)
	profileHandler.Register(oscalGroup.Group("/profiles"), pep.For(authz.ResourceProfile))

	sspHandler := NewSystemSecurityPlanHandler(logger, db, evidenceSvc, jobEnqueuer)
	sspHandler.Register(oscalGroup.Group("/system-security-plans"), pep.For(authz.ResourceSSP))
	if config.AI != nil && config.AI.Enabled {
		dashboardSuggestionHandler.Register(oscalGroup.Group("/system-security-plans"), jwtMiddleware, dashboardGuard)

		diagGroup := server.API().Group("/admin/ai-diagnostics")
		diagGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
		diagGroup.Use(pep.Authorize(authz.ResourceAdmin, authz.ActionManage))
		NewAiDiagnosticsHandler(logger, db, config.AI).Register(diagGroup)
	}

	partyHandler := NewPartyHandler(logger, db)
	partyHandler.Register(oscalGroup.Group("/parties"), pep.For(authz.ResourceParty))

	roleHandler := NewRoleHandler(logger, db)
	roleHandler.Register(oscalGroup.Group("/roles"), pep.For(authz.ResourceRole))

	componentDefinitionHandler := NewComponentDefinitionHandler(logger, db)
	componentDefinitionHandler.Register(oscalGroup.Group("/component-definitions"), pep.For(authz.ResourceComponentDefinition))

	poamHandler := NewPlanOfActionAndMilestonesHandler(logger, db)
	poamHandler.Register(oscalGroup.Group("/plan-of-action-and-milestones"), pep.For(authz.ResourcePoamOSCAL))

	assessmentPlanHandler := NewAssessmentPlanHandler(logger, db)
	assessmentPlanHandler.Register(oscalGroup.Group("/assessment-plans"), pep.For(authz.ResourceAssessmentPlan))

	activityHandler := NewActivityHandler(logger, db)
	activityHandler.Register(oscalGroup.Group("/activities"), pep.For(authz.ResourceActivity))

	assessmentResultsHandler := NewAssessmentResultsHandler(logger, db)
	assessmentResultsHandler.Register(oscalGroup.Group("/assessment-results"), pep.For(authz.ResourceAssessmentResults))

	inventoryHandler := NewInventoryHandler(logger, db)
	inventoryHandler.Register(oscalGroup.Group("/inventory"), pep.For(authz.ResourceInventory))

	importHandler := NewImportHandler(logger, db)
	importHandler.Register(oscalGroup.Group("/import"), pep.For(authz.ResourceImport))
}
