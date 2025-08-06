package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	"github.com/google/uuid"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type SystemSecurityPlanHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewSystemSecurityPlanHandler(sugar *zap.SugaredLogger, db *gorm.DB) *SystemSecurityPlanHandler {
	return &SystemSecurityPlanHandler{
		sugar: sugar,
		db:    db,
	}
}

// validateSSPInput validates SSP input following OSCAL requirements
func (h *SystemSecurityPlanHandler) validateSSPInput(ssp *oscalTypes_1_1_3.SystemSecurityPlan) error {
	if ssp.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(ssp.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if ssp.Metadata.Title == "" {
		return fmt.Errorf("metadata.title is required")
	}
	if ssp.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	return nil
}

// validateSystemUserInput validates system user input
func (h *SystemSecurityPlanHandler) validateSystemUserInput(user *oscalTypes_1_1_3.SystemUser) error {
	if user.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(user.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if user.Title == "" {
		return fmt.Errorf("title is required")
	}
	return nil
}

// validateSystemComponentInput validates system component input
func (h *SystemSecurityPlanHandler) validateSystemComponentInput(comp *oscalTypes_1_1_3.SystemComponent) error {
	if comp.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(comp.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if comp.Title == "" {
		return fmt.Errorf("title is required")
	}
	if comp.Type == "" {
		return fmt.Errorf("type is required")
	}
	return nil
}

// validateInventoryItemInput validates inventory item input
func (h *SystemSecurityPlanHandler) validateInventoryItemInput(item *oscalTypes_1_1_3.InventoryItem) error {
	if item.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(item.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	return nil
}

// validateImplementedRequirementInput validates implemented requirement input
func (h *SystemSecurityPlanHandler) validateImplementedRequirementInput(req *oscalTypes_1_1_3.ImplementedRequirement) error {
	if req.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(req.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if req.ControlId == "" {
		return fmt.Errorf("control-id is required")
	}
	return nil
}

func (h *SystemSecurityPlanHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.POST("", h.Create)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.GET("/:id/profile", h.GetProfile)
	api.PUT("/:id/profile", h.AttachProfile)
	api.DELETE("/:id", h.Delete)
	api.GET("/:id/full", h.Full)
	api.GET("/:id/metadata", h.GetMetadata)
	api.PUT("/:id/metadata", h.UpdateMetadata)
	api.GET("/:id/import-profile", h.GetImportProfile)
	api.PUT("/:id/import-profile", h.UpdateImportProfile)
	api.GET("/:id/system-characteristics", h.GetCharacteristics)
	api.PUT("/:id/system-characteristics", h.UpdateCharacteristics)
	api.GET("/:id/system-characteristics/network-architecture", h.GetCharacteristicsNetworkArchitecture)
	api.PUT("/:id/system-characteristics/network-architecture/diagrams/:diagram", h.UpdateCharacteristicsNetworkArchitectureDiagram)
	api.GET("/:id/system-characteristics/data-flow", h.GetCharacteristicsDataFlow)
	api.PUT("/:id/system-characteristics/data-flow/diagrams/:diagram", h.UpdateCharacteristicsDataFlowDiagram)
	api.GET("/:id/system-characteristics/authorization-boundary", h.GetCharacteristicsAuthorizationBoundary)
	api.PUT("/:id/system-characteristics/authorization-boundary/diagrams/:diagram", h.UpdateCharacteristicsAuthorizationBoundaryDiagram)
	api.GET("/:id/system-implementation", h.GetSystemImplementation)
	api.PUT("/:id/system-implementation", h.UpdateSystemImplementation)
	api.GET("/:id/system-implementation/users", h.GetSystemImplementationUsers)
	api.POST("/:id/system-implementation/users", h.CreateSystemImplementationUser)
	api.PUT("/:id/system-implementation/users/:userId", h.UpdateSystemImplementationUser)
	api.DELETE("/:id/system-implementation/users/:userId", h.DeleteSystemImplementationUser)
	api.GET("/:id/system-implementation/components", h.GetSystemImplementationComponents)
	api.GET("/:id/system-implementation/components/:componentId", h.GetSystemImplementationComponent)
	api.POST("/:id/system-implementation/components", h.CreateSystemImplementationComponent)
	api.PUT("/:id/system-implementation/components/:componentId", h.UpdateSystemImplementationComponent)
	api.DELETE("/:id/system-implementation/components/:componentId", h.DeleteSystemImplementationComponent)
	api.GET("/:id/system-implementation/inventory-items", h.GetSystemImplementationInventoryItems)
	api.POST("/:id/system-implementation/inventory-items", h.CreateSystemImplementationInventoryItem)
	api.PUT("/:id/system-implementation/inventory-items/:itemId", h.UpdateSystemImplementationInventoryItem)
	api.DELETE("/:id/system-implementation/inventory-items/:itemId", h.DeleteSystemImplementationInventoryItem)
	api.GET("/:id/system-implementation/leveraged-authorizations", h.GetSystemImplementationLeveragedAuthorizations)
	api.POST("/:id/system-implementation/leveraged-authorizations", h.CreateSystemImplementationLeveragedAuthorization)
	api.PUT("/:id/system-implementation/leveraged-authorizations/:authId", h.UpdateSystemImplementationLeveragedAuthorization)
	api.DELETE("/:id/system-implementation/leveraged-authorizations/:authId", h.DeleteSystemImplementationLeveragedAuthorization)
	api.GET("/:id/control-implementation", h.GetControlImplementation)
	api.PUT("/:id/control-implementation", h.UpdateControlImplementation)
	api.GET("/:id/control-implementation/implemented-requirements", h.GetImplementedRequirements)
	api.POST("/:id/control-implementation/implemented-requirements", h.CreateImplementedRequirement)
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId", h.UpdateImplementedRequirement)
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements", h.CreateImplementedRequirementStatement)
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId", h.UpdateImplementedRequirementStatement)
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId", h.DeleteImplementedRequirement)
	api.GET("/:id/back-matter", h.GetBackMatter)
	api.PUT("/:id/back-matter", h.UpdateBackMatter)
	api.GET("/:id/back-matter/resources", h.GetBackMatterResources)
	api.POST("/:id/back-matter/resources", h.CreateBackMatterResource)
	api.PUT("/:id/back-matter/resources/:resourceId", h.UpdateBackMatterResource)
	api.DELETE("/:id/back-matter/resources/:resourceId", h.DeleteBackMatterResource)
}

// List godoc
//
//	@Summary		List System Security Plans
//	@Description	Retrieves all System Security Plans.
//	@Tags			System Security Plans
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans [get]
func (h *SystemSecurityPlanHandler) List(ctx echo.Context) error {
	type response struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	var ssps []relational.SystemSecurityPlan

	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Find(&ssps).Error; err != nil {
		h.sugar.Error(err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalSSP := make([]oscalTypes_1_1_3.SystemSecurityPlan, len(ssps))
	for i, ssp := range ssps {
		oscalSSP[i] = *ssp.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: oscalSSP})
}

// Get godoc
//
//	@Summary		Get a System Security Plan
//	@Description	Retrieves a single System Security Plan by its unique ID.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id} [get]
func (h *SystemSecurityPlanHandler) Get(ctx echo.Context) error {
	type response struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.SystemSecurityPlan]{Data: ssp.MarshalOscal()})
}

// Create godoc
//
//	@Summary		Create a System Security Plan
//	@Description	Creates a System Security Plan from input.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			ssp	body		oscalTypes_1_1_3.SystemSecurityPlan	true	"SSP data"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans [post]
func (h *SystemSecurityPlanHandler) Create(ctx echo.Context) error {
	var oscalSSP oscalTypes_1_1_3.SystemSecurityPlan
	if err := ctx.Bind(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid create SSP request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateSSPInput(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid SSP input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	now := time.Now()
	relSSP := &relational.SystemSecurityPlan{}
	relSSP.UnmarshalOscal(oscalSSP)
	relSSP.Metadata.LastModified = &now
	relSSP.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if err := h.db.Create(relSSP).Error; err != nil {
		h.sugar.Errorf("Failed to create SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *relSSP.MarshalOscal()})
}

// GetCharacteristics godoc
//
//	@Summary		Get System Characteristics
//	@Description	Retrieves the System Characteristics for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics [get]
func (h *SystemSecurityPlanHandler) GetCharacteristics(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]{Data: ssp.MarshalOscal().SystemCharacteristics})
}

// GetCharacteristicsNetworkArchitecture godoc
//
//	@Summary		Get Network Architecture
//	@Description	Retrieves the Network Architecture for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.NetworkArchitecture]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/network-architecture [get]
func (h *SystemSecurityPlanHandler) GetCharacteristicsNetworkArchitecture(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.NetworkArchitecture").
		Preload("SystemCharacteristics.NetworkArchitecture.Diagrams").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	na := ssp.SystemCharacteristics.NetworkArchitecture
	if na == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no network architecture for system security plan %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.NetworkArchitecture]{Data: na.MarshalOscal()})
}

// UpdateCharacteristicsNetworkArchitectureDiagram godoc
//
//	@Summary		Update a Network Architecture Diagram
//	@Description	Updates a specific Diagram under the Network Architecture of a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	path		string						true	"Diagram ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Updated Diagram object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/network-architecture/diagrams/{diagram} [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristicsNetworkArchitectureDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	_, err = uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.NetworkArchitecture").
		Preload("SystemCharacteristics.NetworkArchitecture.Diagrams").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	na := ssp.SystemCharacteristics.NetworkArchitecture
	if na == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no network architecture for system security plan %s", idParam)))
	}
	var existingDiag *relational.Diagram
	for _, diag := range na.Diagrams {
		if diag.ID.String() == diagramParam {
			d := diag
			existingDiag = &d
			break
		}
	}
	if existingDiag == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("diagram %s not found", diagramParam)))
	}
	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid update diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalDiag.UUID = existingDiag.ID.String()
	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	relDiag.ID = existingDiag.ID
	relDiag.ParentID = existingDiag.ParentID
	relDiag.ParentType = existingDiag.ParentType
	if err := h.db.Save(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to update network architecture diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Diagram]{Data: relDiag.MarshalOscal()})
}

// GetCharacteristicsDataFlow godoc
//
//	@Summary		Get Data Flow
//	@Description	Retrieves the Data Flow for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.DataFlow]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/data-flow [get]
func (h *SystemSecurityPlanHandler) GetCharacteristicsDataFlow(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.DataFlow").
		Preload("SystemCharacteristics.DataFlow.Diagrams").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	na := ssp.SystemCharacteristics.DataFlow
	if na == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no network architecture for system security plan %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.DataFlow]{Data: na.MarshalOscal()})
}

// UpdateCharacteristicsDataFlowDiagram godoc
//
//	@Summary		Update a Data Flow Diagram
//	@Description	Updates a specific Diagram under the Data Flow of a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	path		string						true	"Diagram ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Updated Diagram object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/data-flow/diagrams/{diagram} [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristicsDataFlowDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	_, err = uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.DataFlow").
		Preload("SystemCharacteristics.DataFlow.Diagrams").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	df := ssp.SystemCharacteristics.DataFlow
	if df == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no data flow for system security plan %s", idParam)))
	}
	var existingDiag *relational.Diagram
	for _, diag := range df.Diagrams {
		if diag.ID.String() == diagramParam {
			d := diag
			existingDiag = &d
			break
		}
	}
	if existingDiag == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("diagram %s not found", diagramParam)))
	}
	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid update diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalDiag.UUID = existingDiag.ID.String()
	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	relDiag.ID = existingDiag.ID
	relDiag.ParentID = existingDiag.ParentID
	relDiag.ParentType = existingDiag.ParentType
	if err := h.db.Save(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to update data flow diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Diagram]{Data: relDiag.MarshalOscal()})
}

// GetCharacteristicsAuthorizationBoundary godoc
//
//	@Summary		Get Authorization Boundary
//	@Description	Retrieves the Authorization Boundary for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AuthorizationBoundary]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/authorization-boundary [get]
func (h *SystemSecurityPlanHandler) GetCharacteristicsAuthorizationBoundary(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.AuthorizationBoundary").
		Preload("SystemCharacteristics.AuthorizationBoundary.Diagrams").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	ab := ssp.SystemCharacteristics.AuthorizationBoundary
	if ab == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no authorization boundary for system security plan %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.AuthorizationBoundary]{Data: ab.MarshalOscal()})
}

// UpdateCharacteristicsAuthorizationBoundaryDiagram godoc
//
//	@Summary		Update an Authorization Boundary Diagram
//	@Description	Updates a specific Diagram under the Authorization Boundary of a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	path		string						true	"Diagram ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Updated Diagram object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/authorization-boundary/diagrams/{diagram} [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristicsAuthorizationBoundaryDiagram(ctx echo.Context) error {

	// This is ugly for now, but it's safe and it works.
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	_, err = uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.AuthorizationBoundary").
		Preload("SystemCharacteristics.AuthorizationBoundary.Diagrams").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	ab := ssp.SystemCharacteristics.AuthorizationBoundary
	if ab == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no authorization boundary for system security plan %s", idParam)))
	}

	var existingDialog *relational.Diagram
	for _, diag := range ab.Diagrams {
		if diag.ID.String() == diagramParam {
			existingDialog = &diag
		}
	}
	if existingDialog == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	// Bind updated OSCAL diagram
	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid update diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalDiag.UUID = existingDialog.ID.String()
	// Map to relational model
	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	relDiag.ID = existingDialog.ID
	relDiag.ParentID = existingDialog.ParentID
	relDiag.ParentType = existingDialog.ParentType
	// Persist update
	if err := h.db.Save(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to update authorization boundary diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Diagram]{Data: relDiag.MarshalOscal()})
}

// UpdateCharacteristics godoc
//
//	@Summary		Update System Characteristics
//	@Description	Updates the System Characteristics for a given System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string									true	"System Security Plan ID"
//	@Param			characteristics	body		oscalTypes_1_1_3.SystemCharacteristics	true	"Updated System Characteristics object"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]
//	@Failure		400				{object}	api.Error
//	@Failure		401				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristics(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalSC oscalTypes_1_1_3.SystemCharacteristics
	if err := ctx.Bind(&oscalSC); err != nil {
		h.sugar.Warnw("Invalid update system characteristics request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	sc := &relational.SystemCharacteristics{}
	sc.UnmarshalOscal(oscalSC)
	fmt.Println(oscalSC.Description)
	sc.SystemSecurityPlanId = *ssp.ID
	sc.ID = ssp.SystemCharacteristics.ID

	// We do not want to update these subcomponents here.
	if err = h.db.Model(&sc).Omit("AuthorizationBoundary", "NetworkArchitecture", "DataFlow").Updates(&sc).Error; err != nil {
		h.sugar.Errorf("Failed to update system characteristics: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]{Data: *sc.MarshalOscal()})
}

// GetSystemImplementation godoc
//
//	@Summary		Get System Implementation
//	@Description	Retrieves the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Load SystemImplementation separately with all its associations
	var si relational.SystemImplementation
	if err := h.db.
		Preload("Users").
		Preload("Users.AuthorizedPrivileges").
		Preload("Components").
		Preload("LeveragedAuthorizations").
		Preload("InventoryItems").
		Where("system_security_plan_id = ?", id).
		First(&si).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// SystemImplementation might not exist yet
			h.sugar.Infow("SystemImplementation not found for SSP", "sspId", id)
			return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]{Data: oscalTypes_1_1_3.SystemImplementation{}})
		}
		h.sugar.Warnw("Failed to load system implementation", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]{Data: *si.MarshalOscal()})
}

// GetSystemImplementationUsers godoc
//
//	@Summary		List System Implementation Users
//	@Description	Retrieves users in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.SystemUser]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationUsers(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.Users").
		Preload("SystemImplementation.Users.AuthorizedPrivileges").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SystemUser]{Data: ssp.MarshalOscal().SystemImplementation.Users})
}

// GetSystemImplementationComponents godoc
//
//	@Summary		List System Implementation Components
//	@Description	Retrieves components in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.Components").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SystemComponent]{Data: ssp.MarshalOscal().SystemImplementation.Components})
}

// GetSystemImplementationComponent godoc
//
//	@Summary		Get System Implementation Component
//	@Description	Retrieves component in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id			path		string	true	"System Security Plan ID"
//	@Param			componentId	path		string	true	"Component ID"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components/{componentId} [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	componentId := ctx.Param("componentId")

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.Components", "id = ?", componentId).
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if len(ssp.SystemImplementation.Components) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]{Data: ssp.MarshalOscal().SystemImplementation.Components[0]})
}

// GetSystemImplementationInventoryItems godoc
//
//	@Summary		List System Implementation Inventory Items
//	@Description	Retrieves inventory items in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationInventoryItems(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.InventoryItems").
		Preload("SystemImplementation.InventoryItems.ImplementedComponents").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalSSP := ssp.MarshalOscal()
	if oscalSSP.SystemImplementation.InventoryItems == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]{Data: []oscalTypes_1_1_3.InventoryItem{}})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]{Data: *oscalSSP.SystemImplementation.InventoryItems})
}

// GetSystemImplementationLeveragedAuthorizations godoc
//
//	@Summary		List System Implementation Leveraged Authorizations
//	@Description	Retrieves leveraged authorizations in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationLeveragedAuthorizations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.LeveragedAuthorizations").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalSSP := ssp.MarshalOscal()
	if oscalSSP.SystemImplementation.LeveragedAuthorizations == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: []oscalTypes_1_1_3.LeveragedAuthorization{}})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: *oscalSSP.SystemImplementation.LeveragedAuthorizations})
}

// GetControlImplementation godoc
//
//	@Summary		Get Control Implementation
//	@Description	Retrieves the Control Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation [get]
func (h *SystemSecurityPlanHandler) GetControlImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("ControlImplementation").
		Preload("ControlImplementation.ImplementedRequirements").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Provided").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Responsibilities").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Inherited").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Satisfied").
		Preload("ControlImplementation.ImplementedRequirements.Statements").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Provided").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Responsibilities").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]{Data: ssp.MarshalOscal().ControlImplementation})
}

func (h *SystemSecurityPlanHandler) Full(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid ssp id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Preload("SystemCharacteristics").
		Preload("SystemCharacteristics.AuthorizationBoundary").
		Preload("SystemCharacteristics.AuthorizationBoundary.Diagrams").
		Preload("SystemCharacteristics.NetworkArchitecture").
		Preload("SystemCharacteristics.NetworkArchitecture.Diagrams").
		Preload("SystemCharacteristics.DataFlow").
		Preload("SystemCharacteristics.DataFlow.Diagrams").
		Preload("SystemImplementation").
		Preload("SystemImplementation.Users").
		Preload("SystemImplementation.Users.AuthorizedPrivileges").
		Preload("SystemImplementation.LeveragedAuthorizations").
		Preload("SystemImplementation.Components").
		Preload("SystemImplementation.InventoryItems").
		Preload("SystemImplementation.InventoryItems.ImplementedComponents").
		First(&ssp, "id = ?", id.String()).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load ssp", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *ssp.MarshalOscal()})
}

// Update godoc
//
//	@Summary		Update a System Security Plan
//	@Description	Updates an existing System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string								true	"SSP ID"
//	@Param			ssp	body		oscalTypes_1_1_3.SystemSecurityPlan	true	"SSP data"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id} [put]
func (h *SystemSecurityPlanHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalSSP oscalTypes_1_1_3.SystemSecurityPlan
	if err := ctx.Bind(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid update SSP request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateSSPInput(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid SSP input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	now := time.Now()
	relSSP := &relational.SystemSecurityPlan{}
	relSSP.UnmarshalOscal(oscalSSP)
	relSSP.ID = &id
	relSSP.Metadata.LastModified = &now
	relSSP.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if err := h.db.Model(relSSP).Where("id = ?", id).Updates(relSSP).Error; err != nil {
		h.sugar.Errorf("Failed to update SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *relSSP.MarshalOscal()})
}

// Delete godoc
//
//	@Summary		Delete a System Security Plan
//	@Description	Deletes an existing System Security Plan and all its related data.
//	@Tags			System Security Plans
//	@Param			id	path	string	true	"SSP ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id} [delete]
func (h *SystemSecurityPlanHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Delete(&existingSSP).Error; err != nil {
		h.sugar.Errorf("Failed to delete SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetMetadata godoc
//
//	@Summary		Get SSP metadata
//	@Description	Retrieves metadata for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/metadata [get]
func (h *SystemSecurityPlanHandler) GetMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("Metadata").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	metadata := ssp.Metadata.MarshalOscal()
	if metadata == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no metadata for SSP %s", idParam)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]{Data: *metadata})
}

// UpdateMetadata godoc
//
//	@Summary		Update SSP metadata
//	@Description	Updates metadata for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			metadata	body		oscalTypes_1_1_3.Metadata	true	"Metadata data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/metadata [put]
func (h *SystemSecurityPlanHandler) UpdateMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalMetadata oscalTypes_1_1_3.Metadata
	if err := ctx.Bind(&oscalMetadata); err != nil {
		h.sugar.Warnw("Invalid update metadata request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("Metadata").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	now := time.Now()
	relMetadata := &relational.Metadata{}
	relMetadata.UnmarshalOscal(oscalMetadata)
	relMetadata.LastModified = &now
	relMetadata.OscalVersion = versioning.GetLatestSupportedVersion()
	relMetadata.ID = ssp.Metadata.ID
	sspIDStr := ssp.ID.String()
	parentType := "system_security_plans"
	relMetadata.ParentID = &sspIDStr
	relMetadata.ParentType = &parentType

	if err := h.db.Save(relMetadata).Error; err != nil {
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]{Data: *relMetadata.MarshalOscal()})
}

// GetProfile godoc
//
//	@Summary		Get Profile for a System Security Plan
//	@Description	Retrieves the Profile attached to the specified System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Profile]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/profile [get]
func (h *SystemSecurityPlanHandler) GetProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP ID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("Profile").
		Preload("Profile.Metadata").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorf("Failed to fetch SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if ssp.Profile == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("No profile attached")))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Profile]{Data: ssp.Profile.MarshalOscal()})
}

// AttachProfile godoc
//
//	@Summary		Attach a Profile to a System Security Plan
//	@Description	Associates a given Profile with a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string	true	"SSP ID"
//	@Param			profileId	body		string	true	"Profile ID to attach"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/profile [put]
func (h *SystemSecurityPlanHandler) AttachProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var input struct {
		ProfileID string `json:"profileId"`
	}
	if err := ctx.Bind(&input); err != nil {
		h.sugar.Warnw("Invalid profile ID input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profileID, err := uuid.Parse(input.ProfileID)
	if err != nil {
		h.sugar.Warnw("Invalid profile ID format", "profileId", input.ProfileID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", sspID).Error; err != nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
	}

	// Ensure the profile exists
	var profile relational.Profile
	if err := h.db.First(&profile, "id = ?", profileID).Error; err != nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("Profile not found")))
	}

	ssp.Profile = &profile
	if err := h.db.Save(&ssp).Error; err != nil {
		h.sugar.Errorf("Failed to attach profile to SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *ssp.MarshalOscal()})
}

// GetImportProfile godoc
//
//	@Summary		Get SSP import-profile
//	@Description	Retrieves import-profile for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/import-profile [get]
func (h *SystemSecurityPlanHandler) GetImportProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	importProfile := ssp.ImportProfile.Data()
	if importProfile.Href == "" {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no import-profile for SSP %s", idParam)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]{Data: *importProfile.MarshalOscal()})
}

// UpdateImportProfile godoc
//
//	@Summary		Update SSP import-profile
//	@Description	Updates import-profile for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string							true	"SSP ID"
//	@Param			import-profile	body		oscalTypes_1_1_3.ImportProfile	true	"Import Profile data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/import-profile [put]
func (h *SystemSecurityPlanHandler) UpdateImportProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalImportProfile oscalTypes_1_1_3.ImportProfile
	if err := ctx.Bind(&oscalImportProfile); err != nil {
		h.sugar.Warnw("Invalid update import-profile request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relImportProfile := &relational.ImportProfile{}
	relImportProfile.UnmarshalOscal(oscalImportProfile)

	// Update the ImportProfile field in the SSP
	ssp.ImportProfile = datatypes.NewJSONType(*relImportProfile)

	if err := h.db.Save(&ssp).Error; err != nil {
		h.sugar.Errorf("Failed to update import-profile: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]{Data: *relImportProfile.MarshalOscal()})
}

// UpdateSystemImplementation godoc
//
//	@Summary		Update System Implementation
//	@Description	Updates the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string									true	"System Security Plan ID"
//	@Param			system-implementation	body		oscalTypes_1_1_3.SystemImplementation	true	"Updated System Implementation object"
//	@Success		200						{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalSI oscalTypes_1_1_3.SystemImplementation
	if err := ctx.Bind(&oscalSI); err != nil {
		h.sugar.Warnw("Invalid update system implementation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("SystemImplementation").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	si := &relational.SystemImplementation{}
	si.UnmarshalOscal(oscalSI)
	si.SystemSecurityPlanId = *ssp.ID
	si.ID = ssp.SystemImplementation.ID

	// Use Save instead of Updates to ensure all fields are properly saved
	if err := h.db.Save(&si).Error; err != nil {
		h.sugar.Errorf("Failed to update system implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Reload the updated system implementation from database to get the latest data with all associations
	var updatedSI relational.SystemImplementation
	if err := h.db.
		Preload("Users").
		Preload("Users.AuthorizedPrivileges").
		Preload("Components").
		Preload("LeveragedAuthorizations").
		Preload("InventoryItems").
		Preload("InventoryItems.ImplementedComponents").
		First(&updatedSI, "id = ?", si.ID).Error; err != nil {
		h.sugar.Errorf("Failed to reload updated system implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]{Data: *updatedSI.MarshalOscal()})
}

// CreateSystemImplementationUser godoc
//
//	@Summary		Create a new system user
//	@Description	Creates a new system user for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"SSP ID"
//	@Param			user	body		oscalTypes_1_1_3.SystemUser	true	"System User data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationUser(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var oscalUser oscalTypes_1_1_3.SystemUser
	if err := ctx.Bind(&oscalUser); err != nil {
		h.sugar.Warnw("Invalid create user request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateSystemUserInput(&oscalUser); err != nil {
		h.sugar.Warnw("Invalid user input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relUser := &relational.SystemUser{}
	relUser.UnmarshalOscal(oscalUser)
	relUser.SystemImplementationId = *systemImpl.ID

	if err := h.db.Create(relUser).Error; err != nil {
		h.sugar.Errorf("Failed to create user: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]{Data: *relUser.MarshalOscal()})
}

// UpdateSystemImplementationUser godoc
//
//	@Summary		Update a system user
//	@Description	Updates an existing system user for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"SSP ID"
//	@Param			userId	path		string						true	"User ID"
//	@Param			user	body		oscalTypes_1_1_3.SystemUser	true	"System User data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users/{userId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationUser(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	userIdParam := ctx.Param("userId")
	userID, err := uuid.Parse(userIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid user id", "userId", userIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingUser relational.SystemUser
	if err := h.db.Where("id = ? AND system_implementation_id = ?", userID, *systemImpl.ID).First(&existingUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find user: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalUser oscalTypes_1_1_3.SystemUser
	if err := ctx.Bind(&oscalUser); err != nil {
		h.sugar.Warnw("Invalid update user request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relUser := &relational.SystemUser{}
	relUser.UnmarshalOscal(oscalUser)
	relUser.SystemImplementationId = *systemImpl.ID
	relUser.ID = &userID

	if err := h.db.Save(relUser).Error; err != nil {
		h.sugar.Errorf("Failed to update user: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]{Data: *relUser.MarshalOscal()})
}

// DeleteSystemImplementationUser godoc
//
//	@Summary		Delete a system user
//	@Description	Deletes an existing system user for a given SSP.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			userId	path	string	true	"User ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users/{userId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationUser(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	userIdParam := ctx.Param("userId")
	userID, err := uuid.Parse(userIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid user id", "userId", userIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	result := h.db.Where("id = ? AND system_implementation_id = ?", userID, *systemImpl.ID).Delete(&relational.SystemUser{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete user: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("user not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateSystemImplementationComponent godoc
//
//	@Summary		Create a new system component
//	@Description	Creates a new system component for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string								true	"SSP ID"
//	@Param			component	body		oscalTypes_1_1_3.SystemComponent	true	"System Component data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var oscalComponent oscalTypes_1_1_3.SystemComponent
	if err := ctx.Bind(&oscalComponent); err != nil {
		h.sugar.Warnw("Invalid create component request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateSystemComponentInput(&oscalComponent); err != nil {
		h.sugar.Warnw("Invalid component input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relComponent := &relational.SystemComponent{}
	relComponent.UnmarshalOscal(oscalComponent)
	relComponent.ParentID = systemImpl.ID
	relComponent.ParentType = "system_implementation"

	if err := h.db.Create(relComponent).Error; err != nil {
		h.sugar.Errorf("Failed to create component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]{Data: *relComponent.MarshalOscal()})
}

// UpdateSystemImplementationComponent godoc
//
//	@Summary		Update a system component
//	@Description	Updates an existing system component for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string								true	"SSP ID"
//	@Param			componentId	path		string								true	"Component ID"
//	@Param			component	body		oscalTypes_1_1_3.SystemComponent	true	"System Component data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components/{componentId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	componentIdParam := ctx.Param("componentId")
	componentID, err := uuid.Parse(componentIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid component id", "componentId", componentIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingComponent relational.SystemComponent
	if err := h.db.Where("id = ? AND system_implementation_id = ?", componentID, *systemImpl.ID).First(&existingComponent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalComponent oscalTypes_1_1_3.SystemComponent
	if err := ctx.Bind(&oscalComponent); err != nil {
		h.sugar.Warnw("Invalid update component request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relComponent := &relational.SystemComponent{}
	relComponent.UnmarshalOscal(oscalComponent)
	relComponent.ParentID = systemImpl.ID
	relComponent.ParentType = "system_implementation"
	relComponent.ID = &componentID

	if err := h.db.Save(relComponent).Error; err != nil {
		h.sugar.Errorf("Failed to update component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]{Data: *relComponent.MarshalOscal()})
}

// DeleteSystemImplementationComponent godoc
//
//	@Summary		Delete a system component
//	@Description	Deletes an existing system component for a given SSP.
//	@Tags			System Security Plans
//	@Param			id			path	string	true	"SSP ID"
//	@Param			componentId	path	string	true	"Component ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components/{componentId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	componentIdParam := ctx.Param("componentId")
	componentID, err := uuid.Parse(componentIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid component id", "componentId", componentIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	result := h.db.Where("id = ? AND system_implementation_id = ?", componentID, *systemImpl.ID).Delete(&relational.SystemComponent{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete component: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("component not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateSystemImplementationInventoryItem godoc
//
//	@Summary		Create a new inventory item
//	@Description	Creates a new inventory item for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"SSP ID"
//	@Param			item	body		oscalTypes_1_1_3.InventoryItem	true	"Inventory Item data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationInventoryItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var oscalItem oscalTypes_1_1_3.InventoryItem
	if err := ctx.Bind(&oscalItem); err != nil {
		h.sugar.Warnw("Invalid create inventory item request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateInventoryItemInput(&oscalItem); err != nil {
		h.sugar.Warnw("Invalid inventory item input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relItem := &relational.InventoryItem{}
	relItem.UnmarshalOscal(oscalItem)
	relItem.SystemImplementationId = *systemImpl.ID

	if err := h.db.Create(relItem).Error; err != nil {
		h.sugar.Errorf("Failed to create inventory item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]{Data: relItem.MarshalOscal()})
}

// UpdateSystemImplementationInventoryItem godoc
//
//	@Summary		Update an inventory item
//	@Description	Updates an existing inventory item for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"SSP ID"
//	@Param			itemId	path		string							true	"Item ID"
//	@Param			item	body		oscalTypes_1_1_3.InventoryItem	true	"Inventory Item data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items/{itemId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationInventoryItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	itemIdParam := ctx.Param("itemId")
	itemID, err := uuid.Parse(itemIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid item id", "itemId", itemIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingItem relational.InventoryItem
	if err := h.db.Where("id = ? AND system_implementation_id = ?", itemID, *systemImpl.ID).First(&existingItem).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find inventory item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalItem oscalTypes_1_1_3.InventoryItem
	if err := ctx.Bind(&oscalItem); err != nil {
		h.sugar.Warnw("Invalid update inventory item request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relItem := &relational.InventoryItem{}
	relItem.UnmarshalOscal(oscalItem)

	relItem.SystemImplementationId = *systemImpl.ID
	relItem.ID = &itemID

	if err := h.db.Save(relItem).Error; err != nil {
		h.sugar.Errorf("Failed to update inventory item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]{Data: relItem.MarshalOscal()})
}

// DeleteSystemImplementationInventoryItem godoc
//
//	@Summary		Delete an inventory item
//	@Description	Deletes an existing inventory item for a given SSP.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			itemId	path	string	true	"Item ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items/{itemId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationInventoryItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	itemIdParam := ctx.Param("itemId")
	itemID, err := uuid.Parse(itemIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid item id", "itemId", itemIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	result := h.db.Where("id = ? AND system_implementation_id = ?", itemID, *systemImpl.ID).Delete(&relational.InventoryItem{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete inventory item: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("inventory item not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateSystemImplementationLeveragedAuthorization godoc
//
//	@Summary		Create a new leveraged authorization
//	@Description	Creates a new leveraged authorization for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string									true	"SSP ID"
//	@Param			auth	body		oscalTypes_1_1_3.LeveragedAuthorization	true	"Leveraged Authorization data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationLeveragedAuthorization(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var oscalAuth oscalTypes_1_1_3.LeveragedAuthorization
	if err := ctx.Bind(&oscalAuth); err != nil {
		h.sugar.Warnw("Invalid create leveraged authorization request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relAuth := &relational.LeveragedAuthorization{}
	relAuth.UnmarshalOscal(oscalAuth)
	relAuth.SystemImplementationId = *systemImpl.ID

	if err := h.db.Create(relAuth).Error; err != nil {
		h.sugar.Errorf("Failed to create leveraged authorization: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: *relAuth.MarshalOscal()})
}

// UpdateSystemImplementationLeveragedAuthorization godoc
//
//	@Summary		Update a leveraged authorization
//	@Description	Updates an existing leveraged authorization for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string									true	"SSP ID"
//	@Param			authId	path		string									true	"Authorization ID"
//	@Param			auth	body		oscalTypes_1_1_3.LeveragedAuthorization	true	"Leveraged Authorization data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations/{authId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationLeveragedAuthorization(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	authIdParam := ctx.Param("authId")
	authID, err := uuid.Parse(authIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid authorization id", "authId", authIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingAuth relational.LeveragedAuthorization
	if err := h.db.Where("id = ? AND system_implementation_id = ?", authID, *systemImpl.ID).First(&existingAuth).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find leveraged authorization: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalAuth oscalTypes_1_1_3.LeveragedAuthorization
	if err := ctx.Bind(&oscalAuth); err != nil {
		h.sugar.Warnw("Invalid update leveraged authorization request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relAuth := &relational.LeveragedAuthorization{}
	relAuth.UnmarshalOscal(oscalAuth)
	relAuth.SystemImplementationId = *systemImpl.ID
	relAuth.ID = &authID

	if err := h.db.Save(relAuth).Error; err != nil {
		h.sugar.Errorf("Failed to update leveraged authorization: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: *relAuth.MarshalOscal()})
}

// DeleteSystemImplementationLeveragedAuthorization godoc
//
//	@Summary		Delete a leveraged authorization
//	@Description	Deletes an existing leveraged authorization for a given SSP.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			authId	path	string	true	"Authorization ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations/{authId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationLeveragedAuthorization(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	authIdParam := ctx.Param("authId")
	authID, err := uuid.Parse(authIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid authorization id", "authId", authIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	result := h.db.Where("id = ? AND system_implementation_id = ?", authID, *systemImpl.ID).Delete(&relational.LeveragedAuthorization{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete leveraged authorization: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("leveraged authorization not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UpdateControlImplementation godoc
//
//	@Summary		Update Control Implementation
//	@Description	Updates the Control Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string									true	"System Security Plan ID"
//	@Param			control-implementation	body		oscalTypes_1_1_3.ControlImplementation	true	"Updated Control Implementation object"
//	@Success		200						{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]
//	@Failure		400						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation [put]
func (h *SystemSecurityPlanHandler) UpdateControlImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalCI oscalTypes_1_1_3.ControlImplementation
	if err := ctx.Bind(&oscalCI); err != nil {
		h.sugar.Warnw("Invalid update control implementation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	ci := &relational.ControlImplementation{}
	ci.UnmarshalOscal(oscalCI)
	ci.SystemSecurityPlanId = *ssp.ID
	ci.ID = ssp.ControlImplementation.ID

	if err := h.db.Model(&ci).Omit("ImplementedRequirements").Updates(&ci).Error; err != nil {
		h.sugar.Errorf("Failed to update control implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]{Data: *ci.MarshalOscal()})
}

// GetImplementedRequirements godoc
//
//	@Summary		Get implemented requirements for a SSP
//	@Description	Retrieves all implemented requirements for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirement]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirements(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load SSP", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var implementedRequirements []relational.ImplementedRequirement
	if err := h.db.Where("control_implementation_id = ?", ssp.ControlImplementation.ID).Find(&implementedRequirements).Error; err != nil {
		h.sugar.Errorw("failed to get implemented requirements", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalReqs := make([]oscalTypes_1_1_3.ImplementedRequirement, len(implementedRequirements))
	for i, req := range implementedRequirements {
		oscalReqs[i] = *req.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirement]{Data: oscalReqs})
}

// CreateImplementedRequirement godoc
//
//	@Summary		Create a new implemented requirement for a SSP
//	@Description	Creates a new implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string									true	"SSP ID"
//	@Param			requirement	body		oscalTypes_1_1_3.ImplementedRequirement	true	"Implemented Requirement data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalReq oscalTypes_1_1_3.ImplementedRequirement
	if err := ctx.Bind(&oscalReq); err != nil {
		h.sugar.Warnw("Invalid create implemented requirement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateImplementedRequirementInput(&oscalReq); err != nil {
		h.sugar.Warnw("Invalid implemented requirement input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relReq := &relational.ImplementedRequirement{}
	relReq.UnmarshalOscal(oscalReq)
	relReq.ControlImplementationId = *ssp.ControlImplementation.ID

	if err := h.db.Create(relReq).Error; err != nil {
		h.sugar.Errorf("Failed to create implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]{Data: *relReq.MarshalOscal()})
}

// UpdateImplementedRequirement godoc
//
//	@Summary		Update an implemented requirement for a SSP
//	@Description	Updates an existing implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string									true	"SSP ID"
//	@Param			reqId		path		string									true	"Requirement ID"
//	@Param			requirement	body		oscalTypes_1_1_3.ImplementedRequirement	true	"Implemented Requirement data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingReq relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).First(&existingReq).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalReq oscalTypes_1_1_3.ImplementedRequirement
	if err := ctx.Bind(&oscalReq); err != nil {
		h.sugar.Warnw("Invalid update implemented requirement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relReq := &relational.ImplementedRequirement{}
	relReq.UnmarshalOscal(oscalReq)
	relReq.ControlImplementationId = *ssp.ControlImplementation.ID
	relReq.ID = &reqID

	if err := h.db.Save(relReq).Error; err != nil {
		h.sugar.Errorf("Failed to update implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]{Data: *relReq.MarshalOscal()})
}

// DeleteImplementedRequirement godoc
//
//	@Summary		Delete an implemented requirement from a SSP
//	@Description	Deletes an existing implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			reqId	path	string	true	"Requirement ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	result := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).Delete(&relational.ImplementedRequirement{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete implemented requirement: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("implemented requirement not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateImplementedRequirementStatement godoc
//
//	@Summary		Create a new statement within an implemented requirement
//	@Description	Creates a new statement within an implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			reqId		path		string						true	"Requirement ID"
//	@Param			statement	body		oscalTypes_1_1_3.Statement	true	"Statement data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Statement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingReq relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).First(&existingReq).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalStmt oscalTypes_1_1_3.Statement
	if err := ctx.Bind(&oscalStmt); err != nil {
		h.sugar.Warnw("Invalid create statement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relStmt := &relational.Statement{}
	relStmt.UnmarshalOscal(oscalStmt)
	relStmt.ImplementedRequirementId = reqID

	if err := h.db.Create(relStmt).Error; err != nil {
		h.sugar.Errorf("Failed to create statement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Statement]{Data: *relStmt.MarshalOscal()})
}

// GetBackMatter godoc
//
//	@Summary		Get SSP back-matter
//	@Description	Retrieves back-matter for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter [get]
func (h *SystemSecurityPlanHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	if ssp.BackMatter == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no back-matter for SSP %s", idParam)))
	}

	if len(ssp.BackMatter.Resources) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no back-matter for SSP %s", idParam)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *ssp.BackMatter.MarshalOscal()})
}

// UpdateBackMatter godoc
//
//	@Summary		Update SSP back-matter
//	@Description	Updates back-matter for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			back-matter	body		oscalTypes_1_1_3.BackMatter	true	"Back Matter data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter [put]
func (h *SystemSecurityPlanHandler) UpdateBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalBackMatter oscalTypes_1_1_3.BackMatter
	if err := ctx.Bind(&oscalBackMatter); err != nil {
		h.sugar.Warnw("Invalid update back-matter request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relBackMatter := &relational.BackMatter{}
	relBackMatter.UnmarshalOscal(oscalBackMatter)
	relBackMatter.ID = ssp.BackMatter.ID
	sspIDStr := ssp.ID.String()
	parentType := "system_security_plans"
	relBackMatter.ParentID = &sspIDStr
	relBackMatter.ParentType = &parentType

	if err := h.db.Model(&relBackMatter).Omit("Resources").Updates(&relBackMatter).Error; err != nil {
		h.sugar.Errorf("Failed to update back-matter: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *relBackMatter.MarshalOscal()})
}

// GetBackMatterResources godoc
//
//	@Summary		Get back-matter resources for a SSP
//	@Description	Retrieves all back-matter resources for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources [get]
func (h *SystemSecurityPlanHandler) GetBackMatterResources(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").Preload("BackMatter.Resources").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load SSP", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalResources := make([]oscalTypes_1_1_3.Resource, len(ssp.BackMatter.Resources))
	for i, resource := range ssp.BackMatter.Resources {
		oscalResources[i] = *resource.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Resource]{Data: oscalResources})
}

// CreateBackMatterResource godoc
//
//	@Summary		Create a new back-matter resource for a SSP
//	@Description	Creates a new back-matter resource for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			resource	body		oscalTypes_1_1_3.Resource	true	"Resource data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources [post]
func (h *SystemSecurityPlanHandler) CreateBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalResource oscalTypes_1_1_3.Resource
	if err := ctx.Bind(&oscalResource); err != nil {
		h.sugar.Warnw("Invalid create resource request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relResource := &relational.BackMatterResource{}
	relResource.UnmarshalOscal(oscalResource)
	relResource.BackMatterID = *ssp.BackMatter.ID

	if err := h.db.Create(relResource).Error; err != nil {
		h.sugar.Errorf("Failed to create resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Resource]{Data: *relResource.MarshalOscal()})
}

// UpdateBackMatterResource godoc
//
//	@Summary		Update a back-matter resource for a SSP
//	@Description	Updates an existing back-matter resource for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			resourceId	path		string						true	"Resource ID"
//	@Param			resource	body		oscalTypes_1_1_3.Resource	true	"Resource data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources/{resourceId} [put]
func (h *SystemSecurityPlanHandler) UpdateBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resourceIdParam := ctx.Param("resourceId")
	resourceID, err := uuid.Parse(resourceIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid resource id", "resourceId", resourceIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingResource relational.BackMatterResource
	if err := h.db.Where("id = ? AND back_matter_id = ?", resourceID, ssp.BackMatter.ID).First(&existingResource).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalResource oscalTypes_1_1_3.Resource
	if err := ctx.Bind(&oscalResource); err != nil {
		h.sugar.Warnw("Invalid update resource request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relResource := &relational.BackMatterResource{}
	relResource.UnmarshalOscal(oscalResource)
	relResource.BackMatterID = *ssp.BackMatter.ID
	relResource.ID = resourceID

	if err := h.db.Save(relResource).Error; err != nil {
		h.sugar.Errorf("Failed to update resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Resource]{Data: *relResource.MarshalOscal()})
}

// DeleteBackMatterResource godoc
//
//	@Summary		Delete a back-matter resource from a SSP
//	@Description	Deletes an existing back-matter resource for a given SSP.
//	@Tags			System Security Plans
//	@Param			id			path	string	true	"SSP ID"
//	@Param			resourceId	path	string	true	"Resource ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources/{resourceId} [delete]
func (h *SystemSecurityPlanHandler) DeleteBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resourceIdParam := ctx.Param("resourceId")
	resourceID, err := uuid.Parse(resourceIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid resource id", "resourceId", resourceIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	result := h.db.Where("id = ? AND back_matter_id = ?", resourceID, ssp.BackMatter.ID).Delete(&relational.BackMatterResource{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete resource: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("resource not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UpdateImplementedRequirementStatement godoc
//
//	@Summary		Update a statement within an implemented requirement
//	@Description	Updates an existing statement within an implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			reqId		path		string						true	"Requirement ID"
//	@Param			stmtId		path		string						true	"Statement ID"
//	@Param			statement	body		oscalTypes_1_1_3.Statement	true	"Statement data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Statement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stmtIdParam := ctx.Param("stmtId")
	stmtID, err := uuid.Parse(stmtIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid statement id", "stmtId", stmtIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingReq relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).First(&existingReq).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingStmt relational.Statement
	if err := h.db.Where("id = ? AND implemented_requirement_id = ?", stmtID, reqID).First(&existingStmt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find statement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalStmt oscalTypes_1_1_3.Statement
	if err := ctx.Bind(&oscalStmt); err != nil {
		h.sugar.Warnw("Invalid update statement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relStmt := &relational.Statement{}
	relStmt.UnmarshalOscal(oscalStmt)
	relStmt.ImplementedRequirementId = reqID
	relStmt.ID = &stmtID

	if err := h.db.Save(relStmt).Error; err != nil {
		h.sugar.Errorf("Failed to update statement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Statement]{Data: *relStmt.MarshalOscal()})
}
