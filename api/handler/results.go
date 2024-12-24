package handler

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"

	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type ResultsHandler struct {
	service *service.ResultsService
	sugar   *zap.SugaredLogger
}

func (h *ResultsHandler) Register(api *echo.Group) {
	api.GET("/:plan", h.GetResults)
}

func NewResultsHandler(l *zap.SugaredLogger, s *service.ResultsService) *ResultsHandler {
	return &ResultsHandler{
		sugar:   l,
		service: s,
	}
}

// GetResults godoc
//
//	@Summary		Gets a plan's results
//	@Description	Returns data of all the latest results for a plan
//	@Tags			Result
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[domain.Result]
//	@Failure		500	{object}	api.Error
//	@Router			/results/:plan [get]
func (h *ResultsHandler) GetResults(c echo.Context) error {
	planId, err := primitive.ObjectIDFromHex(c.Param("plan"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	savedResults, err := h.service.GetLatestResultsForPlan(c.Request().Context(), &planId)
	if err != nil {
		h.sugar.Error(err)
	}

	response := map[string]interface{}{
		"data": savedResults,
	}

	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, response)
}
