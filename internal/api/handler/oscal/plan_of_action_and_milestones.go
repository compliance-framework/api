package oscal

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// PlanOfActionAndMilestonesHandler handles OSCAL Plan of Action and Milestones (POA&M) endpoints.
//
//	@Tags	OScal
//
// All types are defined in oscalTypes_1_1_3 (see types.go)
type PlanOfActionAndMilestonesHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

// NewPlanOfActionAndMilestonesHandler creates a new handler for POA&M endpoints.
func NewPlanOfActionAndMilestonesHandler(sugar *zap.SugaredLogger, db *gorm.DB) *PlanOfActionAndMilestonesHandler {
	return &PlanOfActionAndMilestonesHandler{
		sugar: sugar,
		db:    db,
	}
}

// Register registers POA&M endpoints to the API group.
func (h *PlanOfActionAndMilestonesHandler) Register(api *echo.Group) {
	api.GET("", h.List) // GET /oscal/plan-of-action-and-milestones
	// api.POST("", h.Create)      // POST /oscal/plan-of-action-and-milestones (not implemented)
	api.GET(":id", h.Get) // GET /oscal/plan-of-action-and-milestones/:id
	// api.PUT(":id", h.Update)    // PUT /oscal/plan-of-action-and-milestones/:id (not implemented)
	api.GET(":id/full", h.Full) // GET /oscal/plan-of-action-and-milestones/:id/full
	api.GET(":id/observations", h.GetObservations)
	api.GET(":id/risks", h.GetRisks)
	api.GET(":id/findings", h.GetFindings)
	api.GET(":id/poam-items", h.GetPoamItems)
}

// List godoc
//
//	@Summary		List POA&Ms
//	@Description	Retrieves all Plan of Action and Milestones.
//	@Tags			OScal
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones [get]
func (h *PlanOfActionAndMilestonesHandler) List(ctx echo.Context) error {
	var poams []relational.PlanOfActionAndMilestones
	if err := h.db.Find(&poams).Error; err != nil {
		h.sugar.Errorw("failed to list poams", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalPoams := make([]oscalTypes_1_1_3.PlanOfActionAndMilestones, len(poams))
	for i, poam := range poams {
		oscalPoams[i] = *poam.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]{Data: oscalPoams})
}

// Get godoc
//
//	@Summary		Get a POA&M
//	@Description	Retrieves a single Plan of Action and Milestones by its unique ID.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id} [get]
func (h *PlanOfActionAndMilestonesHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]{Data: *poam.MarshalOscal()})
}

// Full godoc
//
//	@Summary		Get a complete POA&M
//	@Description	Retrieves a complete POA&M by its ID, including all metadata and related objects.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/full [get]
func (h *PlanOfActionAndMilestonesHandler) Full(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]{Data: *poam.MarshalOscal()})
}

// GetObservations godoc
//
//	@Summary		Get observations for a POA&M
//	@Description	Retrieves all observations for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/observations [get]
func (h *PlanOfActionAndMilestonesHandler) GetObservations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	if poam.Observations == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]{Data: []oscalTypes_1_1_3.Observation{}})
	}
	oscalObs := make([]oscalTypes_1_1_3.Observation, len(*poam.Observations))
	for i, obs := range *poam.Observations {
		oscalObs[i] = *obs.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]{Data: oscalObs})
}

// GetRisks godoc
//
//	@Summary		Get risks for a POA&M
//	@Description	Retrieves all risks for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/risks [get]
func (h *PlanOfActionAndMilestonesHandler) GetRisks(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	if poam.Risks == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]{Data: []oscalTypes_1_1_3.Risk{}})
	}
	oscalRisks := make([]oscalTypes_1_1_3.Risk, len(*poam.Risks))
	for i, risk := range *poam.Risks {
		oscalRisks[i] = *risk.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]{Data: oscalRisks})
}

// GetFindings godoc
//
//	@Summary		Get findings for a POA&M
//	@Description	Retrieves all findings for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/findings [get]
func (h *PlanOfActionAndMilestonesHandler) GetFindings(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	if poam.Findings == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]{Data: []oscalTypes_1_1_3.Finding{}})
	}
	oscalFindings := make([]oscalTypes_1_1_3.Finding, len(*poam.Findings))
	for i, finding := range *poam.Findings {
		oscalFindings[i] = *finding.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]{Data: oscalFindings})
}

// GetPoamItems godoc
//
//	@Summary		Get POA&M items
//	@Description	Retrieves all POA&M items for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.PoamItem]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/poam-items [get]
func (h *PlanOfActionAndMilestonesHandler) GetPoamItems(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	oscalItems := make([]oscalTypes_1_1_3.PoamItem, len(poam.PoamItems))
	for i, item := range poam.PoamItems {
		oscalItems[i] = *item.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.PoamItem]{Data: oscalItems})
}
