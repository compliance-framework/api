package oscal

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, evidenceSvc *evidencesvc.EvidenceService, jobEnqueuer SSPJobEnqueuer) {
	oscalGroup := server.API().Group("/oscal")
	oscalGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	jwtMiddleware := middleware.JWTMiddleware(config.JWTPublicKey)

	dashboardSuggestionHandler := NewDashboardSuggestionHandler(logger, db, config.AI, jobEnqueuer)
	dashboardSuggestionHandler.RegisterConfig(server.API().Group("/dashboard-suggestions"))

	catalogHandler := NewCatalogHandler(logger, db)
	catalogHandler.Register(oscalGroup.Group("/catalogs"))

	profileHandler := NewProfileHandler(logger, db)
	profileHandler.Register(oscalGroup.Group("/profiles"))

	sspHandler := NewSystemSecurityPlanHandler(logger, db, evidenceSvc, jobEnqueuer)
	sspHandler.Register(oscalGroup.Group("/system-security-plans"))
	if config.AI != nil && config.AI.Enabled {
		dashboardSuggestionHandler.Register(oscalGroup.Group("/system-security-plans"), jwtMiddleware)
	}

	partyHandler := NewPartyHandler(logger, db)
	partyHandler.Register(oscalGroup.Group("/parties"))

	roleHandler := NewRoleHandler(logger, db)
	roleHandler.Register(oscalGroup.Group("/roles"))

	componentDefinitionHandler := NewComponentDefinitionHandler(logger, db)
	componentDefinitionHandler.Register(oscalGroup.Group("/component-definitions"))

	poamHandler := NewPlanOfActionAndMilestonesHandler(logger, db)
	poamHandler.Register(oscalGroup.Group("/plan-of-action-and-milestones"))

	assessmentPlanHandler := NewAssessmentPlanHandler(logger, db)
	assessmentPlanHandler.Register(oscalGroup.Group("/assessment-plans"))

	activityHandler := NewActivityHandler(logger, db)
	activityHandler.Register(oscalGroup.Group("/activities"))

	assessmentResultsHandler := NewAssessmentResultsHandler(logger, db)
	assessmentResultsHandler.Register(oscalGroup.Group("/assessment-results"))

	inventoryHandler := NewInventoryHandler(logger, db)
	inventoryHandler.Register(oscalGroup.Group("/inventory"))

	importHandler := NewImportHandler(logger, db)
	importHandler.Register(oscalGroup.Group("/import"))
}
