package handler

import (
	"github.com/compliance-framework/configuration-service/internal/service"
	"go.uber.org/zap"
)

// ComponentDefinitionHandler handles CRUD operations for ComponentDefinitions.
type ComponentDefinitionHandler struct {
	service *service.ComponentDefinitionService
	sugar   *zap.SugaredLogger
}
