package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	"github.com/google/uuid"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
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

func (h *SystemSecurityPlanHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.POST("", h.Create)
	api.GET("/:id", h.Get)
	api.GET("/:id/full", h.Full)
	api.GET("/:id/system-characteristics", h.GetCharacteristics)
	api.PUT("/:id/system-characteristics", h.UpdateCharacteristics)
	api.GET("/:id/system-characteristics/network-architecture", h.GetCharacteristicsNetworkArchitecture)
	api.PUT("/:id/system-characteristics/network-architecture/diagrams/:diagram", h.UpdateCharacteristicsNetworkArchitectureDiagram)
	api.GET("/:id/system-characteristics/data-flow", h.GetCharacteristicsDataFlow)
	api.PUT("/:id/system-characteristics/data-flow/diagrams/:diagram", h.UpdateCharacteristicsDataFlowDiagram)
	api.GET("/:id/system-characteristics/authorization-boundary", h.GetCharacteristicsAuthorizationBoundary)
	api.PUT("/:id/system-characteristics/authorization-boundary/diagrams/:diagram", h.UpdateCharacteristicsAuthorizationBoundaryDiagram)
	api.GET("/:id/system-implementation", h.GetSystemImplementation)
	api.GET("/:id/system-implementation/users", h.GetSystemImplementationUsers)
	api.GET("/:id/system-implementation/components", h.GetSystemImplementationComponents)
	api.GET("/:id/system-implementation/inventory-items", h.GetSystemImplementationInventoryItems)
	api.GET("/:id/system-implementation/leveraged-authorizations", h.GetSystemImplementationLeveragedAuthorizations)
	api.GET("/:id/control-implementation", h.GetControlImplementation)
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
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans [post]
func (h *SystemSecurityPlanHandler) Create(ctx echo.Context) error {
	type response struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	ssp := &oscalTypes_1_1_3.SystemSecurityPlan{}
	err := ctx.Bind(ssp)
	if err != nil {
		h.sugar.Warnw("Invalid create ssp request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	now := time.Now()
	relSsp := &relational.SystemSecurityPlan{}
	relSsp.UnmarshalOscal(*ssp)
	relSsp.Metadata.LastModified = &now
	relSsp.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if err := h.db.Create(relSsp).Error; err != nil {
		h.sugar.Errorf("Failed to create ssp: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.SystemSecurityPlan]{Data: relSsp.MarshalOscal()})
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
	if err := h.db.
		Preload("SystemImplementation").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]{Data: ssp.MarshalOscal().SystemImplementation})
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

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]{Data: *ssp.MarshalOscal().SystemImplementation.InventoryItems})
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

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: *ssp.MarshalOscal().SystemImplementation.LeveragedAuthorizations})
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
