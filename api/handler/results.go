package handler

import (
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/google/uuid"
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
	api.GET("/:id", h.GetResult)
	api.GET("/plan/:plan", h.GetPlanResults)
	api.GET("/stream/:stream", h.GetStreamResults)
}

func NewResultsHandler(l *zap.SugaredLogger, s *service.ResultsService) *ResultsHandler {
	return &ResultsHandler{
		sugar:   l,
		service: s,
	}
}

// GetPlanResults godoc
//
//	@Summary		Gets a plan's results
//	@Description	Returns data of all the latest results for a plan
//	@Tags			Result
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[domain.Result]
//	@Failure		500	{object}	api.Error
//	@Router			/results/plan/:plan [get]
func (h *ResultsHandler) GetPlanResults(c echo.Context) error {
	planId, err := primitive.ObjectIDFromHex(c.Param("plan"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	results, err := h.service.GetLatestResultsForPlan(c.Request().Context(), &planId)
	if err != nil {
		h.sugar.Error(err)
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return c.JSON(http.StatusOK, GenericDataListResponse[*domain.Result]{
		Data: results,
	})
}

// GetStreamResults godoc
//
//	@Summary		Gets a plan's results
//	@Description	Returns a list of all the results for a strea,data of all the latest results for a plan
//	@Tags			Result
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[domain.Result]
//	@Failure		500	{object}	api.Error
//	@Router			/results/stream/:stream [get]
func (h *ResultsHandler) GetStreamResults(c echo.Context) error {
	streamId := uuid.MustParse(c.Param("stream"))
	results, err := h.service.GetAllForStream(c.Request().Context(), streamId)
	if err != nil {
		h.sugar.Error(err)
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return c.JSON(http.StatusOK, GenericDataListResponse[*domain.Result]{
		Data: results,
	})
}

// GetResult godoc
//
//	@Summary		Get a result
//	@Description	Returns singular result
//	@Tags			Result
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[domain.Result]
//	@Failure		500	{object}	api.Error
//	@Router			/results/:id [get]
func (h *ResultsHandler) GetResult(c echo.Context) error {
	resultId, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	result, err := h.service.Get(c.Request().Context(), &resultId)
	if err != nil {
		h.sugar.Error(err)
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return c.JSON(http.StatusOK, GenericDataResponse[*domain.Result]{
		Data: result,
	})
}
