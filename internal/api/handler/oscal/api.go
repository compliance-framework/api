package oscal

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB) {
	oscalGroup := server.API().Group("/oscal")
	catalogService := relational.NewCatalogService(db, logger)

	catalogHandler := NewCatalogHandler(logger, catalogService)
	catalogHandler.Register(oscalGroup.Group("/catalogs"))
}
