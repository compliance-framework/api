package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
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
//	@Tags	Oscal
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

// verifyPoamExists checks if a POA&M exists by ID and returns appropriate HTTP error if not
func (h *PlanOfActionAndMilestonesHandler) verifyPoamExists(ctx echo.Context, poamID uuid.UUID) error {
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", poamID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("POAM not found")))
		}
		h.sugar.Errorf("Failed to find POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return nil
}

// Register registers POA&M endpoints to the API group.
func (h *PlanOfActionAndMilestonesHandler) Register(api *echo.Group) {
	api.GET("", h.List)          // GET /oscal/plan-of-action-and-milestones
	api.POST("", h.Create)       // POST /oscal/plan-of-action-and-milestones
	api.GET("/:id", h.Get)       // GET /oscal/plan-of-action-and-milestones/:id
	api.PUT("/:id", h.Update)    // PUT /oscal/plan-of-action-and-milestones/:id
	api.DELETE("/:id", h.Delete) // DELETE /oscal/plan-of-action-and-milestones/:id
	api.GET("/:id/full", h.Full) // GET /oscal/plan-of-action-and-milestones/:id/full
	api.GET("/:id/metadata", h.GetMetadata)
	api.GET("/:id/import-ssp", h.GetImportSsp)
	api.GET("/:id/system-id", h.GetSystemId)
	api.GET("/:id/local-definitions", h.GetLocalDefinitions)
	api.GET("/:id/back-matter", h.GetBackMatter)
	api.GET("/:id/observations", h.GetObservations)
	api.POST("/:id/observations", h.CreateObservation)
	api.PUT("/:id/observations/:obsId", h.UpdateObservation)
	api.DELETE("/:id/observations/:obsId", h.DeleteObservation)
	api.GET("/:id/risks", h.GetRisks)
	api.POST("/:id/risks", h.CreateRisk)
	api.PUT("/:id/risks/:riskId", h.UpdateRisk)
	api.DELETE("/:id/risks/:riskId", h.DeleteRisk)
	api.GET("/:id/findings", h.GetFindings)
	api.POST("/:id/findings", h.CreateFinding)
	api.PUT("/:id/findings/:findingId", h.UpdateFinding)
	api.DELETE("/:id/findings/:findingId", h.DeleteFinding)
	api.GET("/:id/poam-items", h.GetPoamItems)
	api.POST("/:id/poam-items", h.CreatePoamItem)
	api.PUT("/:id/poam-items/:itemId", h.UpdatePoamItem)
	api.DELETE("/:id/poam-items/:itemId", h.DeletePoamItem)
}

// validatePoamInput validates POAM input following OSCAL requirements
func (h *PlanOfActionAndMilestonesHandler) validatePoamInput(poam *oscalTypes_1_1_3.PlanOfActionAndMilestones) error {
	if poam.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(poam.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if poam.Metadata.Title == "" {
		return fmt.Errorf("metadata.title is required")
	}
	if poam.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	if poam.SystemId == nil || poam.SystemId.ID == "" {
		return fmt.Errorf("system-id is required")
	}
	return nil
}

// validateObservationInput validates observation input
func (h *PlanOfActionAndMilestonesHandler) validateObservationInput(obs *oscalTypes_1_1_3.Observation) error {
	if obs.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(obs.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if obs.Description == "" {
		return fmt.Errorf("description is required")
	}
	if obs.Methods == nil || len(obs.Methods) == 0 {
		return fmt.Errorf("methods are required")
	}
	return nil
}

// validateRiskInput validates risk input
func (h *PlanOfActionAndMilestonesHandler) validateRiskInput(risk *oscalTypes_1_1_3.Risk) error {
	if risk.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(risk.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if risk.Title == "" {
		return fmt.Errorf("title is required")
	}
	if risk.Description == "" {
		return fmt.Errorf("description is required")
	}
	if risk.Statement == "" {
		return fmt.Errorf("statement is required")
	}
	if risk.Status == "" {
		return fmt.Errorf("status is required")
	}
	return nil
}

// validateFindingInput validates finding input
func (h *PlanOfActionAndMilestonesHandler) validateFindingInput(finding *oscalTypes_1_1_3.Finding) error {
	if finding.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(finding.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if finding.Title == "" {
		return fmt.Errorf("title is required")
	}
	if finding.Description == "" {
		return fmt.Errorf("description is required")
	}
	if finding.Target.Type == "" {
		return fmt.Errorf("target.type is required")
	}
	if finding.Target.TargetId == "" {
		return fmt.Errorf("target.target-id is required")
	}
	return nil
}

// validatePoamItemInput validates POAM item input
func (h *PlanOfActionAndMilestonesHandler) validatePoamItemInput(item *oscalTypes_1_1_3.PoamItem) error {
	if item.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if item.Title == "" {
		return fmt.Errorf("title is required")
	}
	if item.Description == "" {
		return fmt.Errorf("description is required")
	}
	return nil
}

// List godoc
//
//	@Summary		List POA&Ms
//	@Description	Retrieves all Plan of Action and Milestones.
//	@Tags			Oscal
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones [get]
func (h *PlanOfActionAndMilestonesHandler) List(ctx echo.Context) error {
	var poams []relational.PlanOfActionAndMilestones
	if err := h.db.Preload("Metadata").Preload("Metadata.Revisions").Find(&poams).Error; err != nil {
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
//	@Tags			Oscal
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
	if err := h.db.Preload("Metadata").Preload("Metadata.Revisions").First(&poam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load POA&M", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]{Data: *poam.MarshalOscal()})
}

// Full godoc
//
//	@Summary		Get a complete POA&M
//	@Description	Retrieves a complete POA&M by its ID, including all metadata and related objects.
//	@Tags			Oscal
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
	if err := h.db.Preload("Metadata").Preload("Observations").Preload("Risks").Preload("Findings").Preload("PoamItems").First(&poam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]{Data: *poam.MarshalOscal()})
}

// GetObservations godoc
//
//	@Summary		Get observations for a POA&M
//	@Description	Retrieves all observations for a given POA&M.
//	@Tags			Oscal
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
	if err := h.db.Preload("Observations").First(&poam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load POA&M", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalObs := make([]oscalTypes_1_1_3.Observation, len(poam.Observations))
	for i, obs := range poam.Observations {
		oscalObs[i] = *obs.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]{Data: oscalObs})
}

// GetRisks godoc
//
//	@Summary		Get risks for a POA&M
//	@Description	Retrieves all risks for a given POA&M.
//	@Tags			Oscal
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
	if err := h.db.Preload("Risks").First(&poam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load POA&M", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	// Query polymorphic risks directly
	oscalRisks := make([]oscalTypes_1_1_3.Risk, len(poam.Risks))
	for i, risk := range poam.Risks {
		oscalRisks[i] = *risk.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]{Data: oscalRisks})
}

// GetFindings godoc
//
//	@Summary		Get findings for a POA&M
//	@Description	Retrieves all findings for a given POA&M.
//	@Tags			Oscal
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
	if err := h.db.Preload("Findings").First(&poam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load POA&M", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalFindings := make([]oscalTypes_1_1_3.Finding, len(poam.Findings))
	for i, finding := range poam.Findings {
		oscalFindings[i] = *finding.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]{Data: oscalFindings})
}

// GetPoamItems godoc
//
//	@Summary		Get POA&M items
//	@Description	Retrieves all POA&M items for a given POA&M.
//	@Tags			Oscal
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
	if err := h.db.Preload("PoamItems").First(&poam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load POA&M", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
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
//	@Tags			Oscal
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
//	@Tags			Oscal
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
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no import-ssp for POA&M %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportSsp]{Data: *importSsp.MarshalOscal()})
}

// GetSystemId godoc
//
//	@Summary		Get POA&M system-id
//	@Description	Retrieves system-id for a given POA&M.
//	@Tags			Oscal
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
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no system-id for POA&M %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemId]{Data: *systemId.MarshalOscal()})
}

// GetLocalDefinitions godoc
//
//	@Summary		Get POA&M local definitions
//	@Description	Retrieves local definitions for a given POA&M.
//	@Tags			Oscal
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
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no local-definitions for POA&M %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions]{Data: *localDefs.MarshalOscal()})
}

// GetBackMatter godoc
//
//	@Summary		Get POA&M back-matter
//	@Description	Retrieves back-matter for a given POA&M.
//	@Tags			Oscal
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
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no back-matter for POA&M %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *poam.BackMatter.MarshalOscal()})
}

// Create godoc
//
//	@Summary		Create a new POA&M
//	@Description	Creates a new Plan of Action and Milestones.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			poam	body		oscalTypes_1_1_3.PlanOfActionAndMilestones	true	"POA&M data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones [post]
func (h *PlanOfActionAndMilestonesHandler) Create(ctx echo.Context) error {
	now := time.Now()

	var oscalPoam oscalTypes_1_1_3.PlanOfActionAndMilestones
	if err := ctx.Bind(&oscalPoam); err != nil {
		h.sugar.Warnw("Invalid create POAM request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validatePoamInput(&oscalPoam); err != nil {
		h.sugar.Warnw("Invalid POAM input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relPoam := &relational.PlanOfActionAndMilestones{}
	relPoam.UnmarshalOscal(oscalPoam)
	relPoam.Metadata.LastModified = &now
	relPoam.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if err := h.db.Create(relPoam).Error; err != nil {
		h.sugar.Errorf("Failed to create POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]{Data: *relPoam.MarshalOscal()})
}

// CreateObservation godoc
//
//	@Summary		Create a new observation for a POA&M
//	@Description	Creates a new observation for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"POA&M ID"
//	@Param			observation	body		oscalTypes_1_1_3.Observation	true	"Observation data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/observations [post]
func (h *PlanOfActionAndMilestonesHandler) CreateObservation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, id); err != nil {
		return err
	}

	var oscalObs oscalTypes_1_1_3.Observation
	if err := ctx.Bind(&oscalObs); err != nil {
		h.sugar.Warnw("Invalid create observation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateObservationInput(&oscalObs); err != nil {
		h.sugar.Warnw("Invalid observation input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relObs := &relational.Observation{}
	relObs.UnmarshalOscal(oscalObs)

	poam := relational.PlanOfActionAndMilestones{UUIDModel: relational.UUIDModel{
		ID: &id,
	}}
	if err := h.db.Model(&poam).Association("Observations").Append(relObs); err != nil {
		h.sugar.Errorf("Failed to create observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Observation]{Data: *relObs.MarshalOscal()})
}

// CreateRisk godoc
//
//	@Summary		Create a new risk for a POA&M
//	@Description	Creates a new risk for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"POA&M ID"
//	@Param			risk	body		oscalTypes_1_1_3.Risk	true	"Risk data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/risks [post]
func (h *PlanOfActionAndMilestonesHandler) CreateRisk(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, id); err != nil {
		return err
	}

	var oscalRisk oscalTypes_1_1_3.Risk
	if err := ctx.Bind(&oscalRisk); err != nil {
		h.sugar.Warnw("Invalid create risk request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateRiskInput(&oscalRisk); err != nil {
		h.sugar.Warnw("Invalid risk input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relRisk := &relational.Risk{}
	relRisk.UnmarshalOscal(oscalRisk)

	poam := relational.PlanOfActionAndMilestones{UUIDModel: relational.UUIDModel{
		ID: &id,
	}}
	if err := h.db.Model(&poam).Association("Risks").Append(relRisk); err != nil {
		h.sugar.Errorf("Failed to create risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Risk]{Data: *relRisk.MarshalOscal()})
}

// CreateFinding godoc
//
//	@Summary		Create a new finding for a POA&M
//	@Description	Creates a new finding for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"POA&M ID"
//	@Param			finding	body		oscalTypes_1_1_3.Finding	true	"Finding data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/findings [post]
func (h *PlanOfActionAndMilestonesHandler) CreateFinding(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, id); err != nil {
		return err
	}

	var oscalFinding oscalTypes_1_1_3.Finding
	if err := ctx.Bind(&oscalFinding); err != nil {
		h.sugar.Warnw("Invalid create finding request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateFindingInput(&oscalFinding); err != nil {
		h.sugar.Warnw("Invalid finding input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relFinding := &relational.Finding{}
	relFinding.UnmarshalOscal(oscalFinding)

	poam := relational.PlanOfActionAndMilestones{UUIDModel: relational.UUIDModel{
		ID: &id,
	}}
	if err := h.db.Model(&poam).Association("Findings").Append(relFinding); err != nil {
		h.sugar.Errorf("Failed to create finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Finding]{Data: *relFinding.MarshalOscal()})
}

// CreatePoamItem godoc
//
//	@Summary		Create a new POAM item for a POA&M
//	@Description	Creates a new POAM item for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"POA&M ID"
//	@Param			poam-item	body		oscalTypes_1_1_3.PoamItem	true	"POAM Item data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.PoamItem]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/poam-items [post]
func (h *PlanOfActionAndMilestonesHandler) CreatePoamItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, id); err != nil {
		return err
	}

	var oscalPoamItem oscalTypes_1_1_3.PoamItem
	if err := ctx.Bind(&oscalPoamItem); err != nil {
		h.sugar.Warnw("Invalid create POAM item request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validatePoamItemInput(&oscalPoamItem); err != nil {
		h.sugar.Warnw("Invalid POAM item input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relPoamItem := &relational.PoamItem{}
	relPoamItem.UnmarshalOscal(oscalPoamItem, id)

	if err := h.db.Create(relPoamItem).Error; err != nil {
		h.sugar.Errorf("Failed to create POAM item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.PoamItem]{Data: *relPoamItem.MarshalOscal()})
}

// Update godoc
//
//	@Summary		Update a POA&M
//	@Description	Updates an existing Plan of Action and Milestones.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string										true	"POA&M ID"
//	@Param			poam	body		oscalTypes_1_1_3.PlanOfActionAndMilestones	true	"POA&M data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id} [put]
func (h *PlanOfActionAndMilestonesHandler) Update(ctx echo.Context) error {
	// Parse and validate ID parameter
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Bind request body to OSCAL type
	var oscalPoam oscalTypes_1_1_3.PlanOfActionAndMilestones
	if err := ctx.Bind(&oscalPoam); err != nil {
		h.sugar.Warnw("Invalid update POAM request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validatePoamInput(&oscalPoam); err != nil {
		h.sugar.Warnw("Invalid POAM input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if record exists
	var existingPoam relational.PlanOfActionAndMilestones
	if err := h.db.First(&existingPoam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata with current timestamp and OSCAL version
	now := time.Now()
	relPoam := &relational.PlanOfActionAndMilestones{}
	relPoam.UnmarshalOscal(oscalPoam)
	relPoam.ID = &id // Ensure ID is preserved
	relPoam.Metadata.LastModified = &now
	relPoam.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	// Perform database update
	if err := h.db.Model(relPoam).Where("id = ?", id).Updates(relPoam).Error; err != nil {
		h.sugar.Errorf("Failed to update POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Return updated object
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PlanOfActionAndMilestones]{Data: *relPoam.MarshalOscal()})
}

// UpdateObservation godoc
//
//	@Summary		Update an observation for a POA&M
//	@Description	Updates an existing observation for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"POA&M ID"
//	@Param			obsId		path		string							true	"Observation ID"
//	@Param			observation	body		oscalTypes_1_1_3.Observation	true	"Observation data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/observations/{obsId} [put]
func (h *PlanOfActionAndMilestonesHandler) UpdateObservation(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	obsIdParam := ctx.Param("obsId")
	obsID, err := uuid.Parse(obsIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid observation id", "obsId", obsIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, poamID); err != nil {
		return err
	}

	// Check if risk exists and belongs to this POAM
	var existingObs []relational.Observation
	err = h.db.Model(&relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamID,
		},
	}).Where("id = ?", obsID).Association("Observations").Find(&existingObs)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Bind updated data
	var oscalObs oscalTypes_1_1_3.Observation
	if err := ctx.Bind(&oscalObs); err != nil {
		h.sugar.Warnw("Invalid update observation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Update with preserved IDs and relationships
	relObs := &relational.Observation{}
	relObs.UnmarshalOscal(oscalObs)
	relObs.ID = existingObs[0].ID // Preserve the existing ID

	// Save with GORM's Save method
	if err := h.db.Save(relObs).Error; err != nil {
		h.sugar.Errorf("Failed to update observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Observation]{Data: *relObs.MarshalOscal()})
}

// UpdateRisk godoc
//
//	@Summary		Update a risk for a POA&M
//	@Description	Updates an existing risk for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"POA&M ID"
//	@Param			riskId	path		string					true	"Risk ID"
//	@Param			risk	body		oscalTypes_1_1_3.Risk	true	"Risk data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/risks/{riskId} [put]
func (h *PlanOfActionAndMilestonesHandler) UpdateRisk(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	riskIdParam := ctx.Param("riskId")
	riskID, err := uuid.Parse(riskIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid risk id", "riskId", riskIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, poamID); err != nil {
		return err
	}

	// Check if risk exists and belongs to this POAM
	var existingRisks []relational.Risk
	err = h.db.Model(&relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamID,
		},
	}).Where("id = ?", riskID).Association("Risks").Find(&existingRisks)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Bind updated data
	var oscalRisk oscalTypes_1_1_3.Risk
	if err := ctx.Bind(&oscalRisk); err != nil {
		h.sugar.Warnw("Invalid update risk request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Update with preserved IDs and relationships
	relRisk := &relational.Risk{}
	relRisk.UnmarshalOscal(oscalRisk)
	relRisk.ID = existingRisks[0].ID // Preserve the existing ID

	// Save with GORM's Save method
	if err := h.db.Save(relRisk).Error; err != nil {
		h.sugar.Errorf("Failed to update risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Risk]{Data: *relRisk.MarshalOscal()})
}

// UpdateFinding godoc
//
//	@Summary		Update a finding for a POA&M
//	@Description	Updates an existing finding for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"POA&M ID"
//	@Param			findingId	path		string						true	"Finding ID"
//	@Param			finding		body		oscalTypes_1_1_3.Finding	true	"Finding data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/findings/{findingId} [put]
func (h *PlanOfActionAndMilestonesHandler) UpdateFinding(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	findingIdParam := ctx.Param("findingId")
	findingID, err := uuid.Parse(findingIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid finding id", "findingId", findingIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, poamID); err != nil {
		return err
	}

	// Check if risk exists and belongs to this POAM
	var existingFindings []relational.Finding
	err = h.db.Model(&relational.PlanOfActionAndMilestones{
		UUIDModel: relational.UUIDModel{
			ID: &poamID,
		},
	}).Where("id = ?", findingID).Association("Findings").Find(&existingFindings)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Bind updated data
	var oscalFinding oscalTypes_1_1_3.Finding
	if err := ctx.Bind(&oscalFinding); err != nil {
		h.sugar.Warnw("Invalid update finding request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Update with preserved IDs and relationships
	relFinding := &relational.Finding{}
	relFinding.UnmarshalOscal(oscalFinding)
	relFinding.ID = existingFindings[0].ID // Preserve the existing ID

	// Save with GORM's Save method
	if err := h.db.Save(relFinding).Error; err != nil {
		h.sugar.Errorf("Failed to update finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Finding]{Data: *relFinding.MarshalOscal()})
}

// UpdatePoamItem godoc
//
//	@Summary		Update a POAM item for a POA&M
//	@Description	Updates an existing POAM item for a given POA&M.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"POA&M ID"
//	@Param			itemId		path		string						true	"POAM Item ID"
//	@Param			poam-item	body		oscalTypes_1_1_3.PoamItem	true	"POAM Item data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.PoamItem]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/poam-items/{itemId} [put]
func (h *PlanOfActionAndMilestonesHandler) UpdatePoamItem(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	itemIdParam := ctx.Param("itemId")
	// Note: POAM items use string UUIDs, not uuid.UUID type
	if itemIdParam == "" {
		h.sugar.Warnw("Missing POAM item id", "itemId", itemIdParam)
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("itemId is required")))
	}

	// Verify POAM exists
	if err := h.verifyPoamExists(ctx, poamID); err != nil {
		return err
	}

	// Check if POAM item exists and belongs to this POAM
	var existingItem relational.PoamItem
	if err := h.db.Where("uuid = ? AND plan_of_action_and_milestones_id = ?", itemIdParam, poamID).First(&existingItem).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find POAM item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Bind updated data
	var oscalPoamItem oscalTypes_1_1_3.PoamItem
	if err := ctx.Bind(&oscalPoamItem); err != nil {
		h.sugar.Warnw("Invalid update POAM item request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Update with preserved IDs and relationships
	relPoamItem := &relational.PoamItem{}
	relPoamItem.UnmarshalOscal(oscalPoamItem, poamID)
	relPoamItem.UUID = itemIdParam // Preserve the existing UUID
	relPoamItem.PlanOfActionAndMilestonesID = poamID

	// Save with GORM's Save method
	if err := h.db.Save(relPoamItem).Error; err != nil {
		h.sugar.Errorf("Failed to update POAM item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.PoamItem]{Data: *relPoamItem.MarshalOscal()})
}

// @Summary		Delete a POA&M
// @Description	Deletes an existing Plan of Action and Milestones and all its related data.
// @Tags			Oscal
// @Param			id	path	string	true	"POA&M ID"
// @Success		204	"No Content"
// @Failure		400	{object}	api.Error
// @Failure		404	{object}	api.Error
// @Failure		500	{object}	api.Error
// @Router			/oscal/plan-of-action-and-milestones/{id} [delete]
func (h *PlanOfActionAndMilestonesHandler) Delete(ctx echo.Context) error {
	// Parse and validate ID parameter
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if record exists
	var existingPoam relational.PlanOfActionAndMilestones
	if err := h.db.First(&existingPoam, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete all related entities and main record in a transaction
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Delete all related entities first (cascading delete)
		if err := h.db.Model(&existingPoam).Association("Observations").Clear(); err != nil {
			return fmt.Errorf("failed to delete observations: %v", err)
		}

		if err := h.db.Model(&existingPoam).Association("Findings").Clear(); err != nil {
			return fmt.Errorf("failed to delete findings: %v", err)
		}

		if err := h.db.Model(&existingPoam).Association("Risks").Clear(); err != nil {
			return fmt.Errorf("failed to delete risks: %v", err)
		}

		if err := tx.Where("plan_of_action_and_milestones_id = ?", id).Delete(&relational.PoamItem{}).Error; err != nil {
			return fmt.Errorf("failed to delete POAM items: %v", err)
		}

		// Delete the main POAM record
		if err := tx.Delete(&existingPoam).Error; err != nil {
			return fmt.Errorf("failed to delete POAM: %v", err)
		}

		return nil
	})

	if err != nil {
		h.sugar.Errorf("Failed to delete POAM and related entities: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// DeleteObservation godoc
//
//	@Summary		Delete an observation from a POA&M
//	@Description	Deletes an existing observation for a given POA&M.
//	@Tags			Oscal
//	@Param			id		path	string	true	"POA&M ID"
//	@Param			obsId	path	string	true	"Observation ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/observations/{obsId} [delete]
func (h *PlanOfActionAndMilestonesHandler) DeleteObservation(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	obsIdParam := ctx.Param("obsId")
	obsID, err := uuid.Parse(obsIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid observation id", "obsId", obsIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", poamID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("POAM not found")))
		}
		h.sugar.Errorf("Failed to find POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	err = h.db.Model(&poam).Association("Observations").Delete(&relational.Observation{
		UUIDModel: relational.UUIDModel{
			ID: &obsID,
		},
	})
	if err != nil {
		h.sugar.Errorf("Failed to delete finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// DeleteRisk godoc
//
//	@Summary		Delete a risk from a POA&M
//	@Description	Deletes an existing risk for a given POA&M.
//	@Tags			Oscal
//	@Param			id		path	string	true	"POA&M ID"
//	@Param			riskId	path	string	true	"Risk ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/risks/{riskId} [delete]
func (h *PlanOfActionAndMilestonesHandler) DeleteRisk(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	riskIdParam := ctx.Param("riskId")
	riskID, err := uuid.Parse(riskIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid risk id", "riskId", riskIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", poamID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("POAM not found")))
		}
		h.sugar.Errorf("Failed to find POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	err = h.db.Model(&poam).Association("Risks").Delete(&relational.Risk{
		UUIDModel: relational.UUIDModel{
			ID: &riskID,
		},
	})
	if err != nil {
		h.sugar.Errorf("Failed to delete finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// DeleteFinding godoc
//
//	@Summary		Delete a finding from a POA&M
//	@Description	Deletes an existing finding for a given POA&M.
//	@Tags			Oscal
//	@Param			id			path	string	true	"POA&M ID"
//	@Param			findingId	path	string	true	"Finding ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/findings/{findingId} [delete]
func (h *PlanOfActionAndMilestonesHandler) DeleteFinding(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	findingIdParam := ctx.Param("findingId")
	findingID, err := uuid.Parse(findingIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid finding id", "findingId", findingIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify POAM exists
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", poamID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("POAM not found")))
		}
		h.sugar.Errorf("Failed to find POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	err = h.db.Model(&poam).Association("Findings").Delete(&relational.Finding{
		UUIDModel: relational.UUIDModel{
			ID: &findingID,
		},
	})
	if err != nil {
		h.sugar.Errorf("Failed to delete finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// DeletePoamItem godoc
//
//	@Summary		Delete a POAM item from a POA&M
//	@Description	Deletes an existing POAM item for a given POA&M.
//	@Tags			Oscal
//	@Param			id		path	string	true	"POA&M ID"
//	@Param			itemId	path	string	true	"POAM Item ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/plan-of-action-and-milestones/{id}/poam-items/{itemId} [delete]
func (h *PlanOfActionAndMilestonesHandler) DeletePoamItem(ctx echo.Context) error {
	// Parse and validate ID parameters
	idParam := ctx.Param("id")
	poamID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid POAM id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	itemIdParam := ctx.Param("itemId")
	if itemIdParam == "" {
		h.sugar.Warnw("Missing POAM item id", "itemId", itemIdParam)
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("itemId is required")))
	}

	// Verify POAM exists
	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "id = ?", poamID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("POAM not found")))
		}
		h.sugar.Errorf("Failed to find POAM: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete POAM item
	result := h.db.Where("uuid = ? AND plan_of_action_and_milestones_id = ?", itemIdParam, poamID).Delete(&relational.PoamItem{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete POAM item: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("POAM item not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}
