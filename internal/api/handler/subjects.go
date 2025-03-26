package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"go.uber.org/zap"
)

type SubjectsHandler struct {
	service *service.SubjectService
	sugar   *zap.SugaredLogger
}

func NewSubjectsHandler(l *zap.SugaredLogger, s *service.SubjectService) *SubjectsHandler {
	return &SubjectsHandler{
		sugar:   l,
		service: s,
	}
}

func (h *SubjectsHandler) Register(api *echo.Group) {
	api.GET("/:id", h.FindSubjectById)
}

// FindSubjectById godoc
//
//	@Summary		Get a single subject
//	@Description	Fetches a subject based on its internal ID.
//	@Tags			Subjects
//	@Produce		json
//	@Param			id	path		string	true	"Subject ID"
//	@Success		200	{object}	handler.GenericDataResponse[service.Subject]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/subjects/{id} [get]
func (h *SubjectsHandler) FindSubjectById(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	subject, err := h.service.FindById(ctx.Request().Context(), &id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	} else if subject == nil {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[service.Subject]{
		Data: *subject,
	})
}
