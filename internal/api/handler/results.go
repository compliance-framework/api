package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type ResultsHandler struct {
	resultService *service.ResultsService
	planService   *service.PlansService
	sugar         *zap.SugaredLogger
}

func (h *ResultsHandler) Register(api *echo.Group) {
	api.GET("/:id", h.GetResult)
	api.GET("/plan/:plan", h.GetPlanResults)
	api.GET("/stream/:stream", h.GetStreamResults)
	api.POST("", h.CreateResult)
	api.POST("/search", h.SearchResults)
	api.POST("/compliance-by-search", h.ComplianceOverTimeBySearch)
	api.POST("/compliance-by-stream", h.ComplianceOverTimeByStream)
}

func NewResultsHandler(l *zap.SugaredLogger, s *service.ResultsService, planService *service.PlansService) *ResultsHandler {
	return &ResultsHandler{
		sugar:         l,
		resultService: s,
		planService:   planService,
	}
}

// GetPlanResults godoc
//
//	@Summary		Fetch all assessment results for an assessment plan
//	@Description	Fetches the latest result for each stream associated in an assessment plan
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[domain.Result]
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/assessment-results/plan/:plan [get]
func (h *ResultsHandler) GetPlanResults(c echo.Context) error {
	planId, err := uuid.Parse(c.Param("plan"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	plan, err := h.planService.GetById(c.Request().Context(), planId)
	if err != nil {
		return c.JSON(http.StatusNotFound, api.NewError(err))
	}

	results, err := h.resultService.GetLatestResultsForPlan(c.Request().Context(), plan)
	if err != nil {
		h.sugar.Error(err)
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return c.JSON(http.StatusOK, GenericDataListResponse[*sdk.Result]{
		Data: results,
	})
}

// GetStreamResults godoc
//
//	@Summary	Fetch all assessment results for a result stream
//	@Tags		Assessment Results
//	@Accept		json
//	@Produce	json
//	@Success	200	{object}	handler.GenericDataListResponse[domain.Result]
//	@Failure	401	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Router		/assessment-results/stream/:stream [get]
func (h *ResultsHandler) GetStreamResults(c echo.Context) error {
	streamId := uuid.MustParse(c.Param("stream"))
	results, err := h.resultService.GetAllForStream(c.Request().Context(), streamId)
	if err != nil {
		h.sugar.Error(err)
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return c.JSON(http.StatusOK, GenericDataListResponse[*sdk.Result]{
		Data: results,
	})
}

// GetResult godoc
//
//	@Summary	Fetch a single assessment result
//	@Tags		Assessment Results
//	@Accept		json
//	@Produce	json
//	@Success	200	{object}	handler.GenericDataResponse[domain.Result]
//	@Failure	401	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Router		/assessment-results/:id [get]
func (h *ResultsHandler) GetResult(c echo.Context) error {
	resultId, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	result, err := h.resultService.Get(c.Request().Context(), &resultId)
	if err != nil {
		h.sugar.Error(err)
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return c.JSON(http.StatusOK, GenericDataResponse[*sdk.Result]{
		Data: result,
	})
}

// SearchResults godoc
//
//	@Summary		Search assessment results using label selectors
//	@Description	Returns a list of the latest result for each stream matching the specified label selector
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[domain.Result]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/assessment-results/search [POST]
func (h *ResultsHandler) SearchResults(ctx echo.Context) error {
	// Initialize a new plan object
	filter := &labelfilter.Filter{}

	req := filteredSearchRequest{}

	// Bind the incoming request to the plan object
	// If there's an error, return a 422 status code with the error message
	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	// Attempt to create the plan in the resultService
	// If there's an error, return a 500 status code with the error message
	results, err := h.resultService.Search(ctx.Request().Context(), filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// If everything went well, return a 201 status code with the ID of the created plan
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[*sdk.Result]{
		Data: results,
	})
}

// CreateResult godoc
//
//	@Summary		Create new assessment result
//	@Description	Creates an assessment result in the specified stream and label mapping
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[domain.Result]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/assessment-results [POST]
func (h *ResultsHandler) CreateResult(ctx echo.Context) error {
	result := &sdk.Result{}

	err := ctx.Bind(result)
	if err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	err = h.resultService.Create(ctx.Request().Context(), result)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[sdk.Result]{
		Data: *result,
	})
}

// ComplianceOverTimeBySearch godoc
//
//	@Summary		Get Compliance Over Time for Search query
//	@Description	Returns the compliance over time records for a particular search query
//	@Tags			Assessment Results Observability
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[service.StreamRecords]
//	@Failure		500	{object}	api.Error
//	@Router			/assessment-results/compliance-by-search [POST]
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

	// Attempt to create the plan in the resultService
	// If there's an error, return a 500 status code with the error message
	results, err := h.resultService.GetIntervalledComplianceReportForFilter(ctx.Request().Context(), filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// This ensures we don't get a null in the JSON response
	if len(results) == 0 {
		results = []*service.StreamRecords{}
	}

	// If everything went well, return a 201 status code with the ID of the created plan
	return ctx.JSON(http.StatusOK, GenericDataListResponse[*service.StreamRecords]{
		Data: results,
	})
}

// ComplianceOverTimeByStream godoc
//
//	@Summary		Get Compliance Over Time for stream
//	@Description	Returns the compliance over time records for a particular streamId
//	@Tags			Assessment Results Observability
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[service.StreamRecords]
//	@Failure		500	{object}	api.Error
//	@Router			/assessment-results/compliance-by-stream [POST]
func (h *ResultsHandler) ComplianceOverTimeByStream(ctx echo.Context) error {
	// Initialize a new plan object
	req := &struct {
		Stream uuid.UUID `json:"streamId,omitempty"`
	}{}
	err := ctx.Bind(req)
	if err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	// Attempt to create the plan in the resultService
	// If there's an error, return a 500 status code with the error message
	results, err := h.resultService.GetIntervalledComplianceReportForStream(ctx.Request().Context(), req.Stream)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// This ensures we don't get a null in the JSON response
	if len(results) == 0 {
		results = []*service.StreamRecords{}
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[*service.StreamRecords]{
		Data: results,
	})
}
