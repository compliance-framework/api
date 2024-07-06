package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/api"
	//"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type PlansHandler struct {
	service *service.PlansService
	sugar   *zap.SugaredLogger
}

func (h *PlansHandler) Register(api *echo.Group) {
	api.GET("", h.GetPlans)
}

func NewPlansHandler(l *zap.SugaredLogger, s *service.PlansService) *PlansHandler {
	return &PlansHandler{
		sugar:   l,
		service: s,
	}
}

// GetPlans godoc
//
//	@Summary		Gets plan summaries
//	@Description	Returns id and title of all the plans in the system
//	@Tags			Plan
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	[]domain.PlanPrecis
//	@Failure		500	{object}	api.Error
//	@Router			/plans [get]
func (h *PlansHandler) GetPlans(c echo.Context) error {
	results, err := h.service.GetPlans()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, results)
}
