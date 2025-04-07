package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/configuration-service/sdk/types"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type FindingsHandler struct {
	findingService   *service.FindingService
	subjectService   *service.SubjectService
	componentService *service.ComponentService
	sugar            *zap.SugaredLogger
}

func (h *FindingsHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.POST("/search", h.Search)
	api.POST("/search-by-subject", h.SearchBySubject)
	api.POST("/compliance-by-search", h.ComplianceBySearch)
	api.GET("/instant-compliance-by-control/:class/:id", h.InstantComplianceByControlID)
	api.GET("/compliance-by-uuid/:uuid", h.ComplianceByUUID)
	api.GET("/history/:uuid", h.History)
	api.GET("/:id", h.GetFinding)
	api.GET("/list-control-classes", h.ListControlClasses)
	api.GET("/by-control/:class/:id", h.SearchByControlID)
	api.GET("/by-control/:class", h.SearchByControlClass)
}

func NewFindingsHandler(
	l *zap.SugaredLogger,
	findingService *service.FindingService,
	subjectService *service.SubjectService,
	componentService *service.ComponentService,
) *FindingsHandler {
	return &FindingsHandler{
		sugar:            l,
		findingService:   findingService,
		subjectService:   subjectService,
		componentService: componentService,
	}
}

// GetFinding godoc
//
//	@Summary		Get a single finding
//	@Description	Fetches a finding based on its internal ID.
//	@Tags			Findings
//	@Produce		json
//	@Param			id	path		string	true	"Finding ID"
//	@Success		200	{object}	handler.GenericDataListResponse[service.Finding]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/findings/{id} [get]
func (h *FindingsHandler) GetFinding(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	finding, err := h.findingService.FindOneById(ctx.Request().Context(), &id)
	if err != nil {
		// Optionally, check for not found error.
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the result in GenericDataResponse.
	return ctx.JSON(http.StatusOK, GenericDataResponse[*service.Finding]{
		Data: finding,
	})
}

// History godoc
//
//	@Summary		Get finding history by stream UUID
//	@Description	Fetches up to 200 findings (ordered by Collected descending) that share the same stream UUID.
//	@Tags			Findings
//	@Produce		json
//	@Param			uuid	path		string	true	"Stream UUID"
//	@Success		200		{object}	handler.GenericDataListResponse[service.Finding]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/findings/history/{uuid} [get]
func (h *FindingsHandler) History(ctx echo.Context) error {
	uuidParam := ctx.Param("uuid")
	streamUuid, err := uuid.Parse(uuidParam)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	history, err := h.findingService.FindByUuid(ctx.Request().Context(), streamUuid)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the list in GenericDataListResponse.
	return ctx.JSON(http.StatusOK, GenericDataListResponse[*service.Finding]{
		Data: history,
	})
}

// Create godoc
//
//	@Summary		Create new findings
//	@Description	Creates multiple findings in the CCF API, as well as their subject and component counterparts.
//	               The SDK finding objects are converted to internal representations, mapping subjects (via seeded UUIDs)
//	               and components (by identifier) to their internal IDs.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Success		201	"Created"
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/findings [post]
func (h *FindingsHandler) Create(ctx echo.Context) error {
	// Bind the incoming JSON payload into a slice of SDK findings.
	var findings []*types.Finding
	if err := ctx.Bind(&findings); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Process each finding.
	for _, finding := range findings {
		// Process SDK subjects, generating a seeded UUID for each and using FindOrCreate.
		subjectIds := make([]uuid.UUID, 0)
		if finding.Subjects != nil {
			var subjectIDs []uuid.UUID
			for _, subject := range *finding.Subjects {
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
				subjectIDs = append(subjectIDs, *createdSubject.ID)
			}
			subjectIds = subjectIDs
		}

		// Compile related observation IDs.
		observationIds := make([]uuid.UUID, 0)
		if finding.RelatedObservations != nil {
			for _, relatedObservation := range *finding.RelatedObservations {
				observationIds = append(observationIds, relatedObservation.ObservationUuid)
			}
		}

		// Ensure components are in the database using the FindOrCreate method.
		componentIds := make([]uuid.UUID, 0)
		if finding.Components != nil {
			for _, componentReference := range *finding.Components {
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
		if finding.ID == uuid.Nil {
			finding.ID = uuid.New()
		}
		// Build the internal finding.
		newFinding := &service.Finding{
			ID:             &finding.ID,
			UUID:           finding.UUID,
			Title:          finding.Title,
			Description:    finding.Description,
			Collected:      finding.Collected,
			Remarks:        &finding.Remarks,
			Labels:         finding.Labels,
			Origins:        finding.Origins,
			SubjectIDs:     &subjectIds,
			ComponentIDs:   &componentIds,
			ObservationIDs: &observationIds,
			Controls:       finding.Controls,
			Risks:          finding.Risks,
			Status:         finding.Status,
			Links:          finding.Links,
			Props:          finding.Props,
		}

		if _, err := h.findingService.Create(ctx.Request().Context(), newFinding); err != nil {
			h.sugar.Errorw("failed to create finding", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Return a 201 Created response with no content.
	return ctx.NoContent(http.StatusCreated)
}

// Search godoc
//
//	@Summary		Search findings by labels
//	@Description	Searches for findings using label filters.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Success		201	{object}	handler.GenericDataListResponse[service.Finding]
//	@Failure		422	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/findings/search [post]
func (h *FindingsHandler) Search(ctx echo.Context) error {
	filter := &labelfilter.Filter{}
	req := filteredSearchRequest{}

	// Bind the incoming request to the filter.
	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	results, err := h.findingService.SearchByLabels(ctx.Request().Context(), filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the search results in GenericDataListResponse.
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[*service.Finding]{
		Data: results,
	})
}

// SearchBySubject godoc
//
//	@Summary		Search findings grouped by subject
//	@Description	Searches for findings, and groups them by subject
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Success		201	{object}	handler.GenericDataListResponse[service.FindingsBySubject]
//	@Failure		422	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/findings/search-by-subject [post]
func (h *FindingsHandler) SearchBySubject(ctx echo.Context) error {
	filter := &labelfilter.Filter{}
	req := filteredSearchRequest{}

	// Bind the incoming request to the filter.
	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	results, err := h.findingService.SearchBySubjects(ctx.Request().Context(), filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the search results in GenericDataListResponse.
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[*service.FindingsBySubject]{
		Data: results,
	})
}

// SearchByControlClass godoc
//
//	@Summary		Search findings grouped by control class
//	@Description	Searches for findings and groups them by control class
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Param			class	path		string	true	"Control Class"
//	@Success		200		{object}	handler.GenericDataListResponse[service.FindingsGroupedByControl]
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/findings/by-control/{class} [get]
func (h *FindingsHandler) SearchByControlClass(ctx echo.Context) error {
	classParam := ctx.Param("class")

	results, err := h.findingService.SearchByControlClass(ctx.Request().Context(), classParam)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[service.FindingsGroupedByControl]{
		Data: results,
	})
}

// SearchByControlID godoc
//
//	@Summary	Get compliance report by controlID
//	@Tags		Findings
//	@Accept		json
//	@Produce	json
//	@Param		class	path		string	true	"Label filter criteria"
//	@Param		id		path		string	true	"Label filter criteria"
//	@Success	201		{object}	handler.GenericDataListResponse[service.StatusOverTimeRecord]
//	@Failure	422		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Router		/findings/instant-compliance-by-control/{class}/{id} [get]
func (h *FindingsHandler) SearchByControlID(ctx echo.Context) error {
	classParam := ctx.Param("class")
	idParam := ctx.Param("id")

	results, err := h.findingService.SearchByControlID(ctx.Request().Context(), classParam, idParam)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[*service.Finding]{
		Data: results,
	})
}

// ComplianceBySearch godoc
//
//	@Summary		Get intervalled compliance report by search
//	@Description	Fetches an intervalled compliance report for findings that match the provided label filter. The report groups findings status over time and returns a list of compliance report groups.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Param			filter	body		labelfilter.Filter	true	"Label filter criteria"
//	@Success		201		{object}	handler.GenericDataListResponse[service.StatusOverTimeGroup]
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/findings/compliance-by-search [post]
func (h *FindingsHandler) ComplianceBySearch(ctx echo.Context) error {
	filter := &labelfilter.Filter{}
	req := filteredSearchRequest{}

	// Bind the incoming request to the filter.
	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	results, err := h.findingService.GetIntervalledComplianceReportForFilter(ctx.Request().Context(), filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the search results in GenericDataListResponse.
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[service.StatusOverTimeGroup]{
		Data: results,
	})
}

// InstantComplianceByControlID godoc
//
//	@Summary	Get compliance report by controlID
//	@Tags		Findings
//	@Accept		json
//	@Produce	json
//	@Param		class	path		string	true	"Label filter criteria"
//	@Param		id		path		string	true	"Label filter criteria"
//	@Success	201		{object}	handler.GenericDataListResponse[service.StatusOverTimeRecord]
//	@Failure	422		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Router		/findings/instant-compliance-by-control/{class}/{id} [get]
func (h *FindingsHandler) InstantComplianceByControlID(ctx echo.Context) error {
	class := ctx.Param("class")
	id := ctx.Param("id")

	results, err := h.findingService.GetComplianceReportForControl(ctx.Request().Context(), class, id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the search results in GenericDataListResponse.
	return ctx.JSON(http.StatusCreated, GenericDataListResponse[service.StatusOverTimeRecord]{
		Data: results,
	})
}

// ListControlClasses godoc
//
//	@Summary		List unique control classes from findings
//	@Description	Retrieves all unique control classes found in the stored findings
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GenericDataListResponse[string]
//	@Failure		500	{object}	api.Error
//	@Router			/findings/list-control-classes [get]
func (h *FindingsHandler) ListControlClasses(ctx echo.Context) error {

	classes, err := h.findingService.ListControlClasses(ctx.Request().Context())
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[string]{
		Data: classes,
	})
}

// ComplianceByUUID godoc
//
//	@Summary		Get intervalled compliance report by finding uuid
//	@Description	Fetches an intervalled compliance report for findings that match the provided uuid. The report groups findings status over time and returns a list of compliance report groups.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Param			uuid	path		uuid.UUID	true	"Finding UUID"
//	@Success		201		{object}	handler.GenericDataListResponse[service.StatusOverTimeGroup]
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/compliance-by-uuid/{uuid} [get]
func (h *FindingsHandler) ComplianceByUUID(ctx echo.Context) error {
	uuidParam := ctx.Param("uuid")
	findingUUID, err := uuid.Parse(uuidParam)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	results, err := h.findingService.GetIntervalledComplianceReportForUUID(ctx.Request().Context(), findingUUID)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the search results in GenericDataListResponse.
	return ctx.JSON(http.StatusOK, GenericDataListResponse[service.StatusOverTimeGroup]{
		Data: results,
	})
}
