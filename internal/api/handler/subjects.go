package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo"

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
	api.PATCH("/:id", h.UpdateSubjectById)
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

// UpdateSubjectById godoc
//
//	@Summary		Update a subject's title and/or remarks
//	@Description	Updates a subject's title and/or remarks based on the provided subject ID. Only title and remarks are updated if provided. If no fields are provided, a `400 Bad Request` is returned.
//	@Tags			Subjects
//	@Produce		json
//	@Param			subjectId	path		string	true	"Subject ID"
//	@Param			body		body		models.Subject	true	"Subject data"
//	@Success		200	{object}	models.Subject
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/subjects/{subjectId} [patch]
func (h *SubjectsHandler) UpdateSubjectById(ctx echo.Context) error {

	subjectID := ctx.Param("subjectId")
	id, err := uuid.Parse(subjectID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid subject ID format")
	}

	var updatedSubject service.Subject
	if err := ctx.Bind(&updatedSubject); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid input data")
	}

	// Check if title or remarks are present and update them
	// If no changes to title or remarks, the fields will stay the same
	if updatedSubject.Title == "" && updatedSubject.Remarks == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "No title or remarks to update")
	}

	updated, err := h.service.Update(ctx.Request().Context(), &id, &updatedSubject)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return echo.NewHTTPError(http.StatusNotFound, "Subject not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update subject")
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[service.Subject]{
		Data: *updated,
	})
}
