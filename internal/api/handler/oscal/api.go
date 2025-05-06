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
}
