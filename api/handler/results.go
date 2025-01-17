package handler

import (
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
)

type ResultsHandler struct {
	service     *service.ResultsService
	planService *service.PlanService
	sugar       *zap.SugaredLogger
}

func (h *ResultsHandler) Register(api *echo.Group) {
	api.GET("/:id", h.GetResult)
	api.GET("/plan/:plan", h.GetPlanResults)
	api.GET("/stream/:stream", h.GetStreamResults)
	api.POST("/search", h.SearchResults)
	api.POST("/compliance-by-search", h.ComplianceOverTimeBySearch)
	api.POST("/compliance-by-stream", h.ComplianceOverTimeByStream)
}

func NewResultsHandler(l *zap.SugaredLogger, s *service.ResultsService, planService *service.PlanService) *ResultsHandler {
	return &ResultsHandler{
		sugar:       l,
		service:     s,
		planService: planService,
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

	plan, err := h.planService.GetById(c.Request().Context(), planId.Hex())
	if err != nil {
		return c.JSON(http.StatusNotFound, api.NewError(err))
	}

	results, err := h.service.GetLatestResultsForPlan(c.Request().Context(), plan)
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

// SearchResults godoc
//
//	@Summary		Search results using labels
//	@Description	Returns singular result
//	@Tags			Result
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[domain.Result]
//	@Failure		500	{object}	api.Error
//	@Router			/results/search [POST]
func (h *ResultsHandler) SearchResults(ctx echo.Context) error {
	// Initialize a new plan object
	filter := &labelfilter.Filter{}

	req := filteredSearchRequest{}

	// Bind the incoming request to the plan object
	// If there's an error, return a 422 status code with the error message
	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	// Attempt to create the plan in the service
	// If there's an error, return a 500 status code with the error message
	results, err := h.service.Search(ctx.Request().Context(), filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// If everything went well, return a 201 status code with the ID of the created plan
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[*domain.Result]{
		Data: results,
	})
}

// ComplianceOverTimeBySearch godoc
//
//	@Summary		Get Compliance Over Time for Search query
//	@Description	Returns the compliance over time records for a particular search query
//	@Tags			Result
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[service.StreamRecords]
//	@Failure		500	{object}	api.Error
//	@Router			/results/search [POST]
func (h *ResultsHandler) ComplianceOverTimeBySearch(ctx echo.Context) error {
	// Initialize a new plan object
	filter := &labelfilter.Filter{}

	// Initialize a new createPlanRequest object
	req := filteredSearchRequest{}

	// Bind the incoming request to the plan object
	// If there's an error, return a 422 status code with the error message
	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	// Attempt to create the plan in the service
	// If there's an error, return a 500 status code with the error message
	results, err := h.service.GetIntervalledComplianceReportForFilter(ctx.Request().Context(), filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// If everything went well, return a 201 status code with the ID of the created plan
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[*service.StreamRecords]{
		Data: results,
	})
}

// ComplianceOverTimeByStream godoc
//
//	@Summary		Get Compliance Over Time for stream
//	@Description	Returns the compliance over time records for a particular streamId
//	@Tags			Result
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[service.StreamRecords]
//	@Failure		500	{object}	api.Error
//	@Router			/results/search [POST]
func (h *ResultsHandler) ComplianceOverTimeByStream(ctx echo.Context) error {
	// Initialize a new plan object
	req := &struct {
		Stream uuid.UUID `json:"streamId,omitempty"`
	}{}
	err := ctx.Bind(req)
	if err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	// Attempt to create the plan in the service
	// If there's an error, return a 500 status code with the error message
	results, err := h.service.GetIntervalledComplianceReportForStream(ctx.Request().Context(), req.Stream)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	//// If everything went well, return a 201 status code with the ID of the created plan
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[*service.StreamRecords]{
		Data: results,
	})
}
