package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/labstack/echo/v4"
)

type MetadataHandler struct {
	service *service.MetadataService
}

func NewMetadataHandler(s *service.MetadataService) *MetadataHandler {
	return &MetadataHandler{
		service: s,
	}
}

func (h *MetadataHandler) Register(group *echo.Group) {
	group.POST("/revisions", h.AttachMetadata)
}

// AttachMetadata godoc
//
//	@Summary		Attaches metadata to a specific revision
//	@Description	This method attaches metadata to a specific revision.
//	@Tags			Metadata
//	@Accept			json
//	@Produce		json
//	@Param			revision	body		attachMetadataRequest	true	"Revision that will be attached"
//	@Success		200			{string}	string					"OK"
//	@Failure		400			{object}	api.Error				"Bad Request: Error binding the request"
//	@Failure		404			{object}	api.Error				"Object not found"
//	@Failure		500			{object}	api.Error				"Internal Server Error"
//	@Router			/metadata/revisions [post]
func (h *MetadataHandler) AttachMetadata(c echo.Context) error {
	var revision domain.Revision
	req := attachMetadataRequest{}

	if err := req.bind(c, &revision); err != nil {
		return c.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	err := h.service.AttachMetadata(req.Id, req.Collection, revision)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return c.NoContent(http.StatusOK)
}
