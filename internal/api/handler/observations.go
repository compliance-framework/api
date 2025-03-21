package handler

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/configuration-service/sdk/types"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

type ObservationHandler struct {
	observationService *service.ObservationService
	subjectService     *service.SubjectService
	componentService   *service.ComponentService
	sugar              *zap.SugaredLogger
}

func (h *ObservationHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("/:id", h.Fetch)
	api.GET("/history/:uuid", h.History)
}

func NewObservationHandler(
	l *zap.SugaredLogger,
	observationService *service.ObservationService,
	subjectService *service.SubjectService,
	componentService *service.ComponentService,
) *ObservationHandler {
	return &ObservationHandler{
		sugar:              l,
		observationService: observationService,
		subjectService:     subjectService,
		componentService:   componentService,
	}
}

// Create godoc
//
//	@Summary		Create new observations
//	@Description	Creates multiple observations in the CCF API, along with their subject and component counterparts.
//	               The SDK observation objects are converted to internal representations, mapping subjects (via seeded UUIDs)
//	               and components (by identifier) to their internal IDs.
//	@Tags			Observations
//	@Accept			json
//	@Produce		json
//	@Success		201	"Created"
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/observations [post]
func (h *ObservationHandler) Create(ctx echo.Context) error {
	// Bind the incoming JSON payload into a slice of SDK observations.
	var observations []*types.Observation
	if err := ctx.Bind(&observations); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Process each observation.
	for _, observation := range observations {
		// Process SDK subjects if provided.
		subjectIds := make([]uuid.UUID, 0)
		if observation.Subjects != nil {
			for _, subject := range *observation.Subjects {
				seededID, err := sdk.SeededUUID(subject.Attributes)
				if err != nil {
					return ctx.JSON(http.StatusBadRequest, api.NewError(err))
				}
				createdSubject, err := h.subjectService.FindOrCreate(ctx.Request().Context(), &seededID, &service.Subject{
					Type:       subject.Type,
					Title:      subject.Title,
					Remarks:    subject.Remarks,
					Attributes: subject.Attributes,
					Links:      subject.Links,
					Props:      subject.Props,
				})
				if err != nil {
					return ctx.JSON(http.StatusBadRequest, api.NewError(err))
				}
				subjectIds = append(subjectIds, *createdSubject.ID)
			}
		}

		// Ensure components are in the database using the FindOrCreate method.
		componentIds := make([]uuid.UUID, 0)
		if observation.Components != nil {
			for _, componentReference := range *observation.Components {
				component, err := h.componentService.FindOrCreate(ctx.Request().Context(), componentReference.Identifier, &service.Component{
					Identifier: componentReference.Identifier,
					Title:      componentReference.Identifier, // Using identifier as title for now.
				})
				if err != nil {
					return ctx.JSON(http.StatusBadRequest, api.NewError(err))
				}
				componentIds = append(componentIds, *component.ID)
			}
		}

		// If an empty ID is passed, generate one.
		if observation.ID == uuid.Nil {
			observation.ID = uuid.New()
		}
		// Build the internal observation.
		newObservation := &service.Observation{
			ID:               &observation.ID,
			UUID:             observation.UUID,
			Title:            &observation.Title,
			Description:      observation.Description,
			Remarks:          &observation.Remarks,
			Collected:        observation.Collected,
			Expires:          observation.Expires,
			Methods:          observation.Methods,
			Links:            observation.Links,
			Props:            observation.Props,
			Origins:          observation.Origins,
			SubjectIDs:       &subjectIds,
			Activities:       observation.Activities,
			ComponentIDs:     &componentIds,
			RelevantEvidence: observation.RelevantEvidence,
		}

		// Create the observation.
		if _, err := h.observationService.Create(ctx.Request().Context(), newObservation); err != nil {
			h.sugar.Errorw("failed to create observation", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Return a 201 Created response with no content.
	return ctx.NoContent(http.StatusCreated)
}

// Fetch godoc
//
//	@Summary		Get a single observation
//	@Description	Fetches an observation based on its internal ID.
//	@Tags			Observations
//	@Produce		json
//	@Param			id	path		string	true	"Observation ID"
//	@Success		200	{object}	handler.GenericDataResponse[service.Observation]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/observations/{id} [get]
func (h *ObservationHandler) Fetch(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	obs, err := h.observationService.FindById(ctx.Request().Context(), &id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[*service.Observation]{
		Data: obs,
	})
}

// History godoc
//
//	@Summary		Get observation history by stream UUID
//	@Description	Fetches up to 200 observations (ordered by Collected descending) that share the same stream UUID.
//	@Tags			Observations
//	@Produce		json
//	@Param			uuid	path		string	true	"Stream UUID"
//	@Success		200		{object}	handler.GenericDataListResponse[service.Observation]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/observations/history/{uuid} [get]
func (h *ObservationHandler) History(ctx echo.Context) error {
	uuidParam := ctx.Param("uuid")
	streamUuid, err := uuid.Parse(uuidParam)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	history, err := h.observationService.FindByUuid(ctx.Request().Context(), streamUuid)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[*service.Observation]{
		Data: history,
	})
}
