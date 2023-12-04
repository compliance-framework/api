package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/store"
	"github.com/labstack/echo/v4"
)

type CatalogHandler struct {
	store store.CatalogStore
}

func NewCatalogHandler(s store.CatalogStore) *CatalogHandler {
	return &CatalogHandler{store: s}
}

func (h *CatalogHandler) Register(api *echo.Group) {
	api.POST("", h.CreateCatalog)
	api.GET("/:id", h.GetCatalog)
	api.PATCH("/:id", h.UpdateCatalog)
	api.DELETE("/:id", h.DeleteCatalog)
	api.POST("/:id/controls", h.CreateControl)
	api.GET("/:id/controls/:controlId", h.GetControl)
	// api.POST("/:id/control/:controlId", h.UpdateControl)
}

// CreateCatalog godoc
//	@Summary		Create a catalog
//	@Description	Create a catalog with the given title
//	@Tags			  Catalog
//	@Accept			json
//	@Produce		json
//	@Param			catalog	body		createCatalogRequest	true	"Catalog to add"
//	@Success		201		{object}	catalogIdResponse
//	@Failure		401		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/api/catalog [post]
func (h *CatalogHandler) CreateCatalog(ctx echo.Context) error {
	var c domain.Catalog
	req := newCreateCatalogRequest()
	if err := req.bind(ctx, &c); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	id, err := h.store.CreateCatalog(&c)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, catalogIdResponse{
		Id: id.(string),
	})
}

func (h *CatalogHandler) GetCatalog(ctx echo.Context) error {
	id := ctx.Param("id")
	c, err := h.store.GetCatalog(id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, c)
}

func (h *CatalogHandler) UpdateCatalog(ctx echo.Context) error {
	id := ctx.Param("id")
	var c domain.Catalog
	req := newCreateCatalogRequest()
	if err := req.bind(ctx, &c); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	err := h.store.UpdateCatalog(id, &c)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	updatedCatalog, err := h.store.GetCatalog(id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, updatedCatalog)
}

func (h *CatalogHandler) DeleteCatalog(ctx echo.Context) error {
	id := ctx.Param("id")
	var c domain.Catalog

	// Check if the catalog exists before attempting to delete
	existingCatalog, err := h.store.GetCatalog(id)
	if err != nil || existingCatalog == nil {
		return ctx.JSON(http.StatusNotFound, map[string]string{"message": "Catalog not found"})
	}

	req := newCreateCatalogRequest()

	if err := req.bind(ctx, &c); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	err = h.store.DeleteCatalog(id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, map[string]string{"message": "Catalog has been deleted"})
}

func (h *CatalogHandler) CreateControl(ctx echo.Context) error {
	id := ctx.Param("id")
	var c domain.Control
	req := newCreateControlRequest()
	if err := req.bind(ctx, &c); err != nil {
			return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	if h.store == nil {
			return errors.New("store is not initialized")
	}

	controlId, err := h.store.CreateControl(id, &c)

	if err != nil {
		fmt.Println("err is not equal to nil")
	} else {
		fmt.Println("controlId: ", controlId)
	}

	if controlId == nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(errors.New("controlId is nil")))
	}

	return ctx.JSON(http.StatusCreated, catalogIdResponse{
		Id: string(controlId.(domain.Uuid)),
	})
}

func (h *CatalogHandler) GetControl(ctx echo.Context) error {
	id := ctx.Param("id")
	controlId := ctx.Param("controlId")
	log.Println("GetControl called with catalogId:", id)
	log.Println("GetControl called with controlId:", controlId)

	control, err := h.store.GetControl(id, controlId)
	if err != nil {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, control)
}

