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
	api.GET("/:id", h.Get) // GET /oscal/plan-of-action-and-milestones/:id
	// api.PUT("/:id", h.Update)    // PUT /oscal/plan-of-action-and-milestones/:id (not implemented)
	api.GET("/:id/full", h.Full) // GET /oscal/plan-of-action-and-milestones/:id/full
	api.GET("/:id/metadata", h.GetMetadata)
	api.GET("/:id/import-ssp", h.GetImportSsp)
	api.GET("/:id/system-id", h.GetSystemId)
	api.GET("/:id/local-definitions", h.GetLocalDefinitions)
	api.GET("/:id/back-matter", h.GetBackMatter)
	api.GET("/:id/observations", h.GetObservations)
	api.GET("/:id/risks", h.GetRisks)
	api.GET("/:id/findings", h.GetFindings)
	api.GET("/:id/poam-items", h.GetPoamItems)
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
	if err := h.db.Preload("Metadata").Find(&poams).Error; err != nil {
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
	if err := h.db.Preload("Metadata").First(&poam, "id = ?", id).Error; err != nil {
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
	if err := h.db.Preload("Observations").Preload("Risks").Preload("Findings").Preload("PoamItems").First(&poam, "id = ?", id).Error; err != nil {
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
	if err := h.db.Preload("Observations").Preload("Risks").Preload("Findings").Preload("PoamItems").First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	// Query polymorphic observations directly
	var observations []relational.Observation
	if err := h.db.Where("parent_id = ? AND parent_type = ?", id, "plan_of_action_and_milestones").Find(&observations).Error; err != nil {
		h.sugar.Errorw("failed to get observations", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalObs := make([]oscalTypes_1_1_3.Observation, len(observations))
	for i, obs := range observations {
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
	if err := h.db.Preload("Observations").Preload("Risks").Preload("Findings").Preload("PoamItems").First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	// Query polymorphic risks directly
	var risks []relational.Risk
	if err := h.db.Where("parent_id = ? AND parent_type = ?", id, "plan_of_action_and_milestones").Find(&risks).Error; err != nil {
		h.sugar.Errorw("failed to get risks", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalRisks := make([]oscalTypes_1_1_3.Risk, len(risks))
	for i, risk := range risks {
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
	if err := h.db.Preload("Observations").Preload("Risks").Preload("Findings").Preload("PoamItems").First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	// Query polymorphic findings directly
	var findings []relational.Finding
	if err := h.db.Where("parent_id = ? AND parent_type = ?", id, "plan_of_action_and_milestones").Find(&findings).Error; err != nil {
		h.sugar.Errorw("failed to get findings", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalFindings := make([]oscalTypes_1_1_3.Finding, len(findings))
	for i, finding := range findings {
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
	if err := h.db.Preload("Observations").Preload("Risks").Preload("Findings").Preload("PoamItems").First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	oscalItems := make([]oscalTypes_1_1_3.PoamItem, len(poam.PoamItems))
	for i, item := range poam.PoamItems {
		oscalItems[i] = *item.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.PoamItem]{Data: oscalItems})
}

// GetMetadata godoc
//
//	@Summary		Get POA&M metadata
//	@Description	Retrieves metadata for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/metadata [get]
func (h *PlanOfActionAndMilestonesHandler) GetMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.Preload("Metadata").First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]{Data: *poam.Metadata.MarshalOscal()})
}

// GetImportSsp godoc
//
//	@Summary		Get POA&M import-ssp
//	@Description	Retrieves import-ssp for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportSsp]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/import-ssp [get]
func (h *PlanOfActionAndMilestonesHandler) GetImportSsp(ctx echo.Context) error {
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
	importSsp := poam.ImportSsp.Data()
	if importSsp.Href == "" {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportSsp]{Data: *importSsp.MarshalOscal()})
}

// GetSystemId godoc
//
//	@Summary		Get POA&M system-id
//	@Description	Retrieves system-id for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemId]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/system-id [get]
func (h *PlanOfActionAndMilestonesHandler) GetSystemId(ctx echo.Context) error {
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
	systemId := poam.SystemId.Data()
	if systemId.ID == "" {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemId]{Data: *systemId.MarshalOscal()})
}

// GetLocalDefinitions godoc
//
//	@Summary		Get POA&M local definitions
//	@Description	Retrieves local definitions for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/local-definitions [get]
func (h *PlanOfActionAndMilestonesHandler) GetLocalDefinitions(ctx echo.Context) error {
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
	localDefs := poam.LocalDefinitions.Data()
	if localDefs.Remarks == "" && len(localDefs.Components) == 0 && len(localDefs.InventoryItems) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions]{Data: *localDefs.MarshalOscal()})
}

// GetBackMatter godoc
//
//	@Summary		Get POA&M back-matter
//	@Description	Retrieves back-matter for a given POA&M.
//	@Tags			OScal
//	@Produce		json
//	@Param			id	path		string	true	"POA&M ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/back-matter [get]
func (h *PlanOfActionAndMilestonesHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.Preload("BackMatter").First(&poam, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	if len(poam.BackMatter.Resources) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *poam.BackMatter.MarshalOscal()})
}
