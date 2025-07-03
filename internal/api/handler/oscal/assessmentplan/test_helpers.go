//go:build integration

package assessmentplan

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/middleware"
	"github.com/compliance-framework/configuration-service/internal/config"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RegisterHandlers registers only the assessment plan handlers for testing
func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config) {
	oscalGroup := server.API().Group("/oscal")
	oscalGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))

	assessmentPlanHandler := NewAssessmentPlanHandler(logger, db)
	assessmentPlanHandler.Register(oscalGroup.Group("/assessment-plans"))
}
