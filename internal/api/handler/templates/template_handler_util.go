package templates

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func handleTemplateServiceError(ctx echo.Context, sugar *zap.SugaredLogger, message string, err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}
	if templaterel.IsValidationError(err) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return templateInternalServerError(ctx, sugar, message, err)
}

func templateInternalServerError(ctx echo.Context, sugar *zap.SugaredLogger, message string, err error) error {
	if sugar != nil {
		sugar.Errorw(message, "error", err)
	}
	return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("internal server error")))
}
