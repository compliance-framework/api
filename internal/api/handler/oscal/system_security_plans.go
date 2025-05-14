package oscal

import (
	"errors"
	"github.com/google/uuid"
	"net/http"

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
	api.GET("/:id", h.Get)
	api.GET("/:id/back-matter", h.GetBackMatter)
}

func (h *SystemSecurityPlanHandler) List(ctx echo.Context) error {
	var ssps []relational.SystemSecurityPlan

	// TODO: Add more preloads for other models we need to pull data from
	// TODO: Add in pagination & limits within the API endpoint and the query
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Metadata.Roles").
		Find(&ssps).Error; err != nil {
		h.sugar.Error(err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalSSP := make([]oscalTypes_1_1_3.SystemSecurityPlan, len(ssps))
	for i, ssp := range ssps {
		// TODO: Only the main SSP has been Marshaled with the UUID and Metadata - we need to expand it further down throughout the relational model
		oscalSSP[i] = *ssp.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: oscalSSP})
}

func (h *SystemSecurityPlanHandler) Get(ctx echo.Context) error {
	// TODO: Pull 1 specific SSP via an id specified within the URI
	// TODO: make sure it exists and return an error if the UUID is not found that is sensible
	var ssp oscalTypes_1_1_3.SystemSecurityPlan

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: ssp})
}

// GetBackMatter godoc
//
//	@Summary		Get back-matter for a System Security Plan
//	@Description	Retrieves the back-matter for a given System Security Plan by the specified param ID in the path
//	@Tags			Oscal System Security Plan
//	@Product		json
//	@Param			id							path		string	true	"System Security Plan ID"
//	@Success		200							{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400							{object}	api.Error
//	@Failure		404							{object}	api.Error
//	@Failure		500							{object}	api.Error
//	@Router			/oscal/ssp/{id}/back-matter	[get]
func (h *SystemSecurityPlanHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		First(&ssp, "id = ?", id).Error; err != nil {

		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}

		h.sugar.Warnw("Failed to load SSP", "id", id, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.BackMatter]{Data: ssp.BackMatter.MarshalOscal()})
}
