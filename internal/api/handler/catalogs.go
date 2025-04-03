package handler

import (
	"bytes"
	"context"
	"encoding/json"
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"io"
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// CatalogHandler handles CRUD operations for Catalogs.
type CatalogHandler struct {
	service        *service.CatalogService
	controlService *service.CatalogControlService
	groupService   *service.CatalogGroupService
	sugar          *zap.SugaredLogger
}

// NewCatalogHandler creates a new CatalogHandler.
func NewCatalogHandler(l *zap.SugaredLogger, s *service.CatalogService, g *service.CatalogGroupService, c *service.CatalogControlService) *CatalogHandler {
	return &CatalogHandler{
		sugar:          l,
		service:        s,
		groupService:   g,
		controlService: c,
	}
}

// Register registers the Catalog endpoints.
func (h *CatalogHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.POST("", h.Create)
}

// Get godoc
//
//	@Summary		Get a Catalog
//	@Description	Retrieves a single Catalog by its unique ID.
//	@Tags			Catalogs
//	@Produce		json
//	@Param			id	path		string	true	"Catalog ID"
//	@Success		200	{object}	GenericDataResponse[service.Catalog]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/catalogs/{id} [get]
func (h *CatalogHandler) Get(ctx echo.Context) error {
	catalog, err := h.service.Get(ctx.Request().Context(), uuid.MustParse(ctx.Param("id")))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	} else if catalog == nil {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[service.Catalog]{
		Data: *catalog,
	})
}

// List godoc
//
//	@Summary		List catalogs
//	@Description	Retrieves all catalogs.
//	@Tags			Catalogs
//	@Produce		json
//	@Success		200	{object}	GenericDataListResponse[service.Catalog]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/catalogs [get]
func (h *CatalogHandler) List(c echo.Context) error {
	results, err := h.service.List(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[*service.Catalog]{
		Data: results,
	})
}

// Create godoc
//
//	@Summary		Create a new catalog
//	@Description	Creates a new catalog.
//	@Tags			Catalogs
//	@Accept			json
//	@Produce		json
//	@Success		201	{object}	GenericDataResponse[service.Catalog]
//	@Failure		400	{object}	api.Error
//	@Failure		422	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/catalogs [post]
func (h *CatalogHandler) Create(ctx echo.Context) error {
	file, err := ctx.FormFile("file")
	if err != nil {
		return err
	}
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, src)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	//var data []byte
	//_, err = src.Read(data)
	//if err != nil {
	//	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	//}
	type content struct {
		Catalog oscaltypes113.Catalog `json:"catalog"`
	}
	data := &content{}
	err = json.Unmarshal(buf.Bytes(), data)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	catalog := data.Catalog
	// Now we loop and create our internal catalog

	id := uuid.MustParse(catalog.UUID)
	// First the catalog
	internalCatalog := service.Catalog{
		UUID:     &id,
		Metadata: catalog.Metadata,
	}
	_, err = h.service.Create(ctx.Request().Context(), &internalCatalog)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	parent := service.CatalogItemParentIdentifier{
		ID:   internalCatalog.UUID.String(),
		Type: service.CatalogItemParentTypeCatalog,
	}

	if catalog.Groups != nil {
		for _, g := range *catalog.Groups {
			err = h.handleGroup(ctx.Request().Context(), g, parent)
			if err != nil {
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
		}
	}

	if catalog.Controls != nil {
		for _, c := range *catalog.Controls {
			err = h.handleControl(ctx.Request().Context(), c, parent)
			if err != nil {
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
		}
	}

	//// Return the created catalog wrapped in a GenericDataResponse.
	return ctx.JSON(http.StatusCreated, GenericDataResponse[oscaltypes113.Catalog]{
		Data: catalog,
	})
}

func (h *CatalogHandler) handleGroup(ctx context.Context, group oscaltypes113.Group, parent service.CatalogItemParentIdentifier) error {
	internalGroup := service.CatalogGroup{
		ID:     group.ID,
		Title:  group.Title,
		Class:  group.Class,
		Parts:  group.Parts,
		Parent: parent,
		Links:  group.Links,
		Props:  group.Props,
	}
	_, err := h.groupService.Create(ctx, &internalGroup)
	if err != nil {
		return err
	}

	childParent := service.CatalogItemParentIdentifier{
		ID:    internalGroup.ID,
		Class: internalGroup.Class,
		Type:  service.CatalogItemParentTypeGroup,
	}

	if group.Groups != nil {
		for _, g := range *group.Groups {
			err = h.handleGroup(ctx, g, childParent)
			if err != nil {
				return err
			}
		}
	}

	if group.Controls != nil {
		for _, c := range *group.Controls {
			err = h.handleControl(ctx, c, childParent)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (h *CatalogHandler) handleControl(ctx context.Context, control oscaltypes113.Control, parent service.CatalogItemParentIdentifier) error {
	internalControl := service.CatalogControl{
		ID:     control.ID,
		Title:  control.Title,
		Class:  control.Class,
		Parts:  control.Parts,
		Parent: parent,
		Links:  control.Links,
		Props:  control.Props,
	}
	_, err := h.controlService.Create(ctx, &internalControl)
	if err != nil {
		return err
	}

	childParent := service.CatalogItemParentIdentifier{
		ID:    internalControl.ID,
		Class: internalControl.Class,
		Type:  service.CatalogItemParentTypeControl,
	}

	if control.Controls != nil {
		for _, g := range *control.Controls {
			err = h.handleControl(ctx, g, childParent)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
