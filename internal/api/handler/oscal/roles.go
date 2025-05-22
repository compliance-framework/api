package oscal

import (
	"errors"
	"github.com/compliance-framework/configuration-service/internal/api"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
)

type RoleHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewRoleHandler(l *zap.SugaredLogger, db *gorm.DB) *RoleHandler {
	return &RoleHandler{
		sugar: l,
		db:    db,
	}
}

func (h *RoleHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
}

// List godoc
//
//	@Summary		List roles
//	@Description	Retrieves all roles.
//	@Tags			Oscal
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Role]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/roles [get]
func (h *RoleHandler) List(ctx echo.Context) error {
	var parties []relational.Role
	if err := h.db.
		Find(&parties).Error; err != nil {
		h.sugar.Warnw("Failed to load catalogs", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalparties := []oscalTypes_1_1_3.Role{}
	for _, party := range parties {
		oscalparties = append(oscalparties, *party.MarshalOscal())
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Role]{Data: oscalparties})
}

// Get godoc
//
//	@Summary		Get a Role
//	@Description	Retrieves a single Role by its unique ID.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Party ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Role]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/roles/{id} [get]
func (h *RoleHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid party id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var party relational.Role
	if err := h.db.
		First(&party, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load party", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Role]{Data: *party.MarshalOscal()})
}
