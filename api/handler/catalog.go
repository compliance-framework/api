package handler

import (
	"errors"
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
	api.PUT("/:id/controls/:controlId", h.UpdateControl)
}

// CreateCatalog godoc
//
//	@Summary		Create a catalog
//	@Description	Create a catalog with the given title
//	@Tags			Catalog
//	@Accept			json
//	@Produce		json
//	@Param			catalog	body		createCatalogRequest	true	"Catalog to add"
//	@Success		201		{object}	catalogIdResponse
//	@Failure		401		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/catalog [post]
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

// GetCatalog godoc
//
//	@Summary		Get a catalog
//	@Description	Get a specific catalog by its ID
//	@Tags			Catalog
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Catalog ID"
//	@Success		200	{object}	domain.Catalog
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/catalog/{id} [get]
func (h *CatalogHandler) GetCatalog(ctx echo.Context) error {
	id := ctx.Param("id")
	c, err := h.store.GetCatalog(id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, c)
}

// UpdateCatalog godoc
//
// @Summary		Update a catalog
// @Description	Update a specific catalog by its ID
// @Tags			Catalog
// @Accept			json
// @Produce		json
// @Param			id		path		string					true	"Catalog ID"
// @Param			catalog	body		UpdateCatalogRequest	true	"Catalog to update"
// @Success		200		{object}	domain.Catalog
// @Failure		401		{object}	api.Error
// @Failure		422		{object}	api.Error
// @Failure		500		{object}	api.Error
// @Router			/catalog/{id} [patch]
func (h *CatalogHandler) UpdateCatalog(ctx echo.Context) error {
	id := ctx.Param("id")
	var c domain.Catalog
	req := &UpdateCatalogRequest{}
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

// DeleteCatalog godoc
//
//	@Summary		Delete a catalog
//	@Description	Delete a specific catalog by its ID
//	@Tags			Catalog
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Catalog ID"
//	@Success		200	{object}	map[string]string
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/catalog/{id} [delete]
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

// CreateControl godoc
//
//	@Summary		Create a control
//	@Description	Create a control with the given title
//	@Tags			Catalog
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Catalog ID"
//	@Param			control	body		createControlRequest	true	"Control to add"
//	@Success		201		{object}	catalogIdResponse
//	@Failure		401		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/catalog/{id}/controls [post]
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
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if controlId == nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(errors.New("controlId is nil")))
	}

	return ctx.JSON(http.StatusCreated, catalogIdResponse{
		Id: string(controlId.(domain.Uuid)),
	})
}

// GetControl godoc
//
//	@Summary		Get a control
//	@Description	Get a specific control by its ID
//	@Tags			Catalog
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string	true	"Catalog ID"
//	@Param			controlId	path		string	true	"Control ID"
//	@Success		200			{object}	domain.Control
//	@Failure		401			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/catalog/{id}/controls/{controlId} [get]
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

// UpdateControl godoc
//
//	@Summary		Update a control
//	@Description	Update a specific control by its ID
//	@Tags			Catalog
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"Catalog ID"
//	@Param			controlId	path		string					true	"Control ID"
//	@Param			control		body		UpdateControlRequest	true	"Control to update"
//	@Success		200			{object}	domain.Control
//	@Failure		401			{object}	api.Error
//	@Failure		422			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/catalog/{id}/controls/{controlId} [put]
func (h *CatalogHandler) UpdateControl(ctx echo.Context) error {
	id := ctx.Param("id")
	controlId := ctx.Param("controlId")
	var c domain.Control
	req := &UpdateControlRequest{}
	if err := req.bind(ctx, &c); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	_, err := h.store.UpdateControl(id, controlId, &c)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	updatedControl, err := h.store.GetControl(id, controlId)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, updatedControl)
}
