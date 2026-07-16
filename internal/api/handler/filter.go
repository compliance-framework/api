package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// FilterHandler handles CRUD operations for filters.
type FilterHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func NewFilterHandler(sugar *zap.SugaredLogger, db *gorm.DB) *FilterHandler {
	return &FilterHandler{
		sugar: sugar,
		db:    db,
	}
}

// Register registers the filter endpoints.
func (h *FilterHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("", h.List, guard.Read())
	api.GET("/:id", h.Get, guard.Read())
	api.POST("", h.Create, guard.Create())
	api.PUT("/:id", h.Update, guard.Update())
	api.DELETE("/:id", h.Delete, guard.Delete())
	// Bulk import creates filters → create.
	api.POST("/import", h.ImportFilters, guard.Create())
	// Responsibility attachments mutate the filter's associations, exactly like the
	// control links PUT /:id manages — same guard.
	api.POST("/:id/responsibilities", h.AttachResponsibility, guard.Update())
	api.DELETE("/:id/responsibilities/:responsibilityUuid", h.DetachResponsibility, guard.Update())
}

type FilterWithAssociations struct {
	relational.Filter
	Controls   []oscalTypes_1_1_3.Control         `json:"controls"`
	Components []oscalTypes_1_1_3.SystemComponent `json:"components"`
}

// Get godoc
//
//	@Summary		Get a filter
//	@Description	Retrieves a single filter by its unique ID.
//	@Tags			Filters
//	@Produce		json
//	@Param			id	path		string	true	"Filter ID"
//	@Success		200	{object}	GenericDataResponse[FilterWithAssociations]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/filters/{id} [get]
func (h *FilterHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid filter id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var filter relational.Filter
	if err := h.db.Preload("Controls").Preload("Components").First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := FilterWithAssociations{
		Filter: filter,
		Controls: func() []oscalTypes_1_1_3.Control {
			result := []oscalTypes_1_1_3.Control{}
			for _, control := range filter.Controls {
				result = append(result, *control.MarshalOscal())
			}
			return result
		}(),
		Components: func() []oscalTypes_1_1_3.SystemComponent {
			result := []oscalTypes_1_1_3.SystemComponent{}
			for _, component := range filter.Components {
				result = append(result, *component.MarshalOscal())
			}
			return result
		}(),
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[FilterWithAssociations]{Data: response})
}

// List godoc
//
//	@Summary		List filters
//	@Description	Retrieves filters, optionally filtered by controlId, componentId, sspId, or global scope.
//	@Tags			Filters
//	@Produce		json
//	@Param			controlId	query		string	false	"Control ID"
//	@Param			componentId	query		string	false	"Component ID"
//	@Param			sspId		query		string	false	"System Security Plan ID; returns global + same-SSP filters"
//	@Param			scope		query		string	false	"Filter scope. Use 'global' for global filters only"
//	@Success		200			{object}	GenericDataListResponse[FilterWithAssociations]
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/filters [get]
func (h *FilterHandler) List(ctx echo.Context) error {
	controlID := ctx.QueryParam("controlId")
	componentID := ctx.QueryParam("componentId")
	scope := strings.TrimSpace(ctx.QueryParam("scope"))
	sspIDParam := strings.TrimSpace(ctx.QueryParam("sspId"))

	if controlID != "" && componentID != "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("controlId and componentId are mutually exclusive")))
	}

	query := h.db.Model(&relational.Filter{}).Preload("Controls").Preload("Components")

	if controlID != "" && componentID == "" {
		query = query.
			Joins("JOIN filter_controls ON filter_controls.filter_id = filters.id").
			Joins("JOIN controls ON controls.catalog_id = filter_controls.control_catalog_id AND controls.id = filter_controls.control_id").
			Where("controls.id = ?", controlID).
			Distinct()
	}

	if controlID == "" && componentID != "" {
		query = query.
			Joins("JOIN filter_system_components ON filter_system_components.filter_id = filters.id").
			Joins("JOIN system_components ON system_components.id = filter_system_components.system_component_id").
			Where("system_components.id = ?", componentID).
			Distinct()
	}

	switch {
	case scope == "global":
		query = query.Where("filters.ssp_id IS NULL")
	case scope != "":
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("unsupported scope %q", scope)))
	case sspIDParam != "":
		sspID, err := uuid.Parse(sspIDParam)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		query = query.Where("filters.ssp_id IS NULL OR filters.ssp_id = ?", sspID)
	}

	var filters []relational.Filter
	if err := query.Find(&filters).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := func() []FilterWithAssociations {
		result := []FilterWithAssociations{}
		for _, filter := range filters {
			result = append(result, FilterWithAssociations{
				Filter: filter,
				Controls: func() []oscalTypes_1_1_3.Control {
					result := []oscalTypes_1_1_3.Control{}
					for _, control := range filter.Controls {
						result = append(result, *control.MarshalOscal())
					}
					return result
				}(),
				Components: func() []oscalTypes_1_1_3.SystemComponent {
					result := []oscalTypes_1_1_3.SystemComponent{}
					for _, component := range filter.Components {
						result = append(result, *component.MarshalOscal())
					}
					return result
				}(),
			})
		}
		return result
	}()

	return ctx.JSON(http.StatusOK, GenericDataListResponse[FilterWithAssociations]{Data: response})
}

// Create godoc
//
//	@Summary		Create a new filter
//	@Description	Creates a new filter.
//	@Tags			Filters
//	@Accept			json
//	@Produce		json
//	@Param			filter	body		createFilterRequest	true	"Filter to add"
//	@Success		201		{object}	GenericDataResponse[relational.Filter]
//	@Failure		400		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/filters [post]
func (h *FilterHandler) Create(ctx echo.Context) error {
	var req createFilterRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	// Filters can be associated with either controls or components, but not both.
	hasControls := req.Controls != nil && len(*req.Controls) > 0
	hasComponents := req.Components != nil && len(*req.Components) > 0

	if hasControls && hasComponents {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf(
				"filter Controls and Components fields are mutually exclusive",
			)),
		)
	}

	filter := relational.Filter{
		Name:   req.Name,
		SSPID:  req.SSPID,
		Filter: datatypes.NewJSONType(req.Filter),
	}

	if hasControls {
		for _, controlId := range *req.Controls {
			searchDB := h.db.Session(&gorm.Session{})
			control := relational.Control{}
			err := searchDB.First(&control, "id = ?", controlId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Controls = append(filter.Controls, control)
		}
	}

	if hasComponents {
		for _, componentId := range *req.Components {
			searchDB := h.db.Session(&gorm.Session{})
			component := relational.SystemComponent{}
			err := searchDB.First(&component, "id = ?", componentId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Components = append(filter.Components, component)
		}
	}

	if err := h.db.Create(&filter).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[relational.Filter]{Data: filter})
}

// Update godoc
//
//	@Summary		Update a filter
//	@Description	Updates an existing filter.
//	@Tags			Filters
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Filter ID"
//	@Param			filter	body		createFilterRequest	true	"Filter to update"
//	@Success		200		{object}	GenericDataResponse[relational.Filter]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/filters/{id} [put]
func (h *FilterHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid filter id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req createFilterRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	var filter relational.Filter
	if err := h.db.First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	filter.Name = req.Name
	// PUT is full replacement: omitted or null sspId intentionally clears the SSP binding.
	filter.SSPID = req.SSPID
	filter.Filter = datatypes.NewJSONType(req.Filter)

	// Note: nil and empty slices are semantically different here.
	// If one of controls / components is present but empty, that
	// means clear the existing controls / components, whereas a nil
	// slice means we should ignore it entirely. Now consider, an
	// existing filter with controls, and a request to update it where
	// controls is nil but components is populated. This should be
	// invalid, as the expected update would be to ignore the controls
	// and update the components, resulting in a filter with both.

	// The request contains one or more of both Controls and Components
	if (req.Controls != nil && len(*req.Controls) > 0) && (req.Components != nil && len(*req.Components) > 0) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf(
				"cannot associate a Filter with both Controls and Components",
			)),
		)
	}

	// The request contains one or more Controls, with a nil slice for Components
	if (req.Controls != nil && len(*req.Controls) > 0) && (req.Components == nil) && len(filter.Components) > 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf(
				"cannot link Controls to a Filter with associated Components."+
					"To remove existing Component associations, send an empty list for the Components field",
			)),
		)
	}

	// The request contains a nil slice for Controls, with one or more Components
	if (req.Controls == nil) && (req.Components != nil && len(*req.Components) > 0) && len(filter.Controls) > 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf(
				"cannot link Components to a Filter with associated Controls."+
					"To remove existing Control associations, send an empty list for the Controls field",
			)),
		)
	}

	// Update controls if provided
	if req.Controls != nil {
		// Clear existing controls association
		if err := h.db.Model(&filter).Association("Controls").Clear(); err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		// Add new controls
		for _, controlId := range *req.Controls {
			searchDB := h.db.Session(&gorm.Session{})
			control := relational.Control{}
			err := searchDB.First(&control, "id = ?", controlId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Controls = append(filter.Controls, control)
		}
	}

	if req.Components != nil {
		if err := h.db.Model(&filter).Association("Components").Clear(); err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		for _, componentId := range *req.Components {
			searchDB := h.db.Session(&gorm.Session{})
			component := relational.SystemComponent{}
			err := searchDB.First(&component, "id = ?", componentId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Components = append(filter.Components, component)
		}
	}

	if err := h.db.Save(&filter).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[relational.Filter]{Data: filter})
}

// Delete godoc
//
//	@Summary		Delete a filter
//	@Description	Deletes a filter.
//	@Tags			Filters
//	@Param			id	path	string	true	"Filter ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/filters/{id} [delete]
func (h *FilterHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid filter id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var filter relational.Filter
	if err := h.db.First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Delete(&filter).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// AttachResponsibility godoc
//
//	@Summary		Attach a filter to an inherited responsibility
//	@Description	Associates this filter with an upstream responsibility the given downstream
//	@Description	SSP inherits (BCH-1339's filter_responsibilities), so the responsibility's
//	@Description	posture is computed live from the filter's evidence. When controlId is given,
//	@Description	the filter is also linked to that control (so control-level compliance
//	@Description	surfaces include it) with provenance recorded: detaching removes the control
//	@Description	link only if this attach created it.
//	@Tags			Filters
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string								true	"Filter ID"
//	@Param			attachment	body		attachFilterResponsibilityRequest	true	"Responsibility to attach"
//	@Success		201			{object}	GenericDataResponse[relational.FilterResponsibility]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/filters/{id}/responsibilities [post]
func (h *FilterHandler) AttachResponsibility(ctx echo.Context) error {
	idParam := ctx.Param("id")
	filterID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid filter id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req attachFilterResponsibilityRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	var filter relational.Filter
	if err := h.db.Preload("Controls").First(&filter, "id = ?", filterID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.First(&relational.SystemSecurityPlan{}, "id = ?", req.SSPID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("system security plan %s not found", req.SSPID)))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// The responsibility must be one the downstream SSP actually inherits: posture reads
	// tolerate junk rows, but writes are validated. This replicates the
	// bulkResolveUpstreamResponsibilities join (handler/oscal cannot be imported from
	// here — it imports this package for the response envelopes).
	var inherits int64
	if err := h.db.Table("ssp_leverage_links AS l").
		Joins("JOIN provided_control_implementations p ON p.id = l.provided_uuid").
		Joins("JOIN control_implementation_responsibilities r ON r.provided_uuid = p.id AND r.export_id = p.export_id").
		Where("l.downstream_ssp_id = ? AND r.id = ?", req.SSPID, req.ResponsibilityUUID).
		Count(&inherits).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if inherits == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf("responsibilityUuid %s is not a responsibility this SSP inherits", req.ResponsibilityUUID)))
	}

	var existing relational.FilterResponsibility
	err = h.db.First(&existing,
		"filter_id = ? AND responsibility_uuid = ? AND ssp_id = ?",
		filterID, req.ResponsibilityUUID, req.SSPID,
	).Error
	if err == nil {
		return ctx.JSON(http.StatusConflict, api.NewError(
			fmt.Errorf("filter is already attached to this responsibility for this SSP")))
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	row := relational.FilterResponsibility{
		FilterID:           filterID,
		ResponsibilityUUID: req.ResponsibilityUUID,
		SSPID:              req.SSPID,
	}

	var controlToLink *relational.Control
	if req.ControlID != nil && strings.TrimSpace(*req.ControlID) != "" {
		// The caller passes the SSP's casing of the control id, which is not reliably
		// the catalog's — match case-insensitively, like the leverage joins do.
		var control relational.Control
		if err := h.db.First(&control, "LOWER(id) = LOWER(?)", strings.TrimSpace(*req.ControlID)).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("control %q not found", *req.ControlID)))
			}
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		row.ControlID = &control.ID
		row.ControlCatalogID = &control.CatalogID

		linkExists := false
		for _, linked := range filter.Controls {
			if linked.CatalogID == control.CatalogID && linked.ID == control.ID {
				linkExists = true
				break
			}
		}
		if !linkExists {
			controlToLink = &control
			row.ControlLinkCreated = true
		} else {
			// Co-ownership: if the existing link was itself created by a responsibility
			// attachment, this row claims it too, so the LAST detacher removes it. An
			// independently created link (POST/PUT /filters) is never owned.
			var owners int64
			if err := h.db.Model(&relational.FilterResponsibility{}).
				Where("filter_id = ? AND control_id = ? AND control_link_created = true", filterID, control.ID).
				Count(&owners).Error; err != nil {
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			row.ControlLinkCreated = owners > 0
		}
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if controlToLink != nil {
			if err := tx.Model(&filter).Association("Controls").Append(controlToLink); err != nil {
				return err
			}
		}
		return tx.Create(&row).Error
	}); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[relational.FilterResponsibility]{Data: row})
}

// DetachResponsibility godoc
//
//	@Summary		Detach a filter from an inherited responsibility
//	@Description	Removes the filter↔responsibility association for the given downstream SSP
//	@Description	(sspId query param — the association's key is the full triple). The filter's
//	@Description	control link is removed only if it was created by a responsibility attachment
//	@Description	and no other attachment on this filter still claims that control.
//	@Tags			Filters
//	@Param			id					path	string	true	"Filter ID"
//	@Param			responsibilityUuid	path	string	true	"Responsibility UUID"
//	@Param			sspId				query	string	true	"Downstream SSP ID"
//	@Success		204					"No Content"
//	@Failure		400					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Router			/filters/{id}/responsibilities/{responsibilityUuid} [delete]
func (h *FilterHandler) DetachResponsibility(ctx echo.Context) error {
	filterID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	responsibilityUUID, err := uuid.Parse(ctx.Param("responsibilityUuid"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	sspID, err := uuid.Parse(strings.TrimSpace(ctx.QueryParam("sspId")))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf("sspId query parameter is required (the association is keyed per downstream SSP): %w", err)))
	}

	var row relational.FilterResponsibility
	if err := h.db.First(&row,
		"filter_id = ? AND responsibility_uuid = ? AND ssp_id = ?",
		filterID, responsibilityUUID, sspID,
	).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Where("filter_id = ? AND responsibility_uuid = ? AND ssp_id = ?", filterID, responsibilityUUID, sspID).
			Delete(&relational.FilterResponsibility{}).Error; err != nil {
			return err
		}

		// Unwind the control link only when this row owned it and nobody else claims it —
		// see the provenance comment on relational.FilterResponsibility.
		if row.ControlLinkCreated && row.ControlID != nil && row.ControlCatalogID != nil {
			var claims int64
			if err := tx.Model(&relational.FilterResponsibility{}).
				Where("filter_id = ? AND control_id = ?", filterID, *row.ControlID).
				Count(&claims).Error; err != nil {
				return err
			}
			if claims == 0 {
				var filter relational.Filter
				if err := tx.First(&filter, "id = ?", filterID).Error; err != nil {
					return err
				}
				control := relational.Control{CatalogID: *row.ControlCatalogID, ID: *row.ControlID}
				if err := tx.Model(&filter).Association("Controls").Delete(&control); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}
