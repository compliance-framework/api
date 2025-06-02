package oscal

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB) {
	oscalGroup := server.API().Group("/oscal")

	catalogHandler := NewCatalogHandler(logger, db)
	catalogHandler.Register(oscalGroup.Group("/catalogs"))

	profileHandler := NewProfileHandler(logger, db)
	profileHandler.Register(oscalGroup.Group("/profiles"))

	sspHandler := NewSystemSecurityPlanHandler(logger, db)
	sspHandler.Register(oscalGroup.Group("/system-security-plans"))

	partyHandler := NewPartyHandler(logger, db)
	partyHandler.Register(oscalGroup.Group("/parties"))

	roleHandler := NewRoleHandler(logger, db)
	roleHandler.Register(oscalGroup.Group("/roles"))

	componentDefinitionHandler := NewComponentDefinitionHandler(logger, db)
	componentDefinitionHandler.Register(oscalGroup.Group("/component-definitions"))

	poamHandler := NewPlanOfActionAndMilestonesHandler(logger, db)
	poamHandler.Register(oscalGroup.Group("/plan-of-action-and-milestones"))
}
