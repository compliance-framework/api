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
	"gorm.io/gorm/clause"
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
	if err := h.db.First(&filter, "id = ?", filterID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to load filter", "filterId", filterID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	if err := h.db.First(&relational.SystemSecurityPlan{}, "id = ?", req.SSPID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("system security plan %s not found", req.SSPID)))
		}
		h.sugar.Errorw("Failed to load system security plan", "sspId", req.SSPID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	// The filter must belong to the SSP the attachment is being made for. Authorization is
	// evaluated on the FILTER id (the route is guarded by guard.Update() on :id), so req.SSPID is
	// body-supplied and never authorized on its own. Without this check a principal with update
	// rights on their own filter could write a FilterResponsibility scoped to any other SSP, and
	// that SSP's ResponsibilityPosture would then be computed from a filter it does not own.
	//
	// Second-order: Filter.SSPID carries OnDelete:CASCADE, so deleting the filter's owning SSP
	// would silently delete attachments another SSP depends on.
	//
	// Global filters (SSPID == nil) stay attachable anywhere — that is deliberate existing
	// behaviour, not an oversight.
	//
	// Ordered AFTER the SSP existence check on purpose: a non-existent sspId is a 404, and hoisting
	// this above it would turn that into a "belongs to a different system security plan" 400, which
	// is both wrong and misleading (TestAttachValidation pins the 404).
	if filter.SSPID != nil && *filter.SSPID != req.SSPID {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
			"filter %s belongs to a different system security plan", filterID)))
	}

	// The responsibility must be one the downstream SSP actually inherits: posture reads
	// tolerate junk rows, but writes are validated. This replicates the
	// bulkResolveUpstreamResponsibilities join (handler/oscal cannot be imported from
	// here — it imports this package for the response envelopes).
	//
	// Terminal link states are excluded deliberately, not by omission: a revoked or superseded
	// link means the SSP no longer inherits the responsibility, so attaching a filter to it would
	// target something that isn't there. A drifted link still qualifies — the subscription exists
	// and is being reconciled, so filtering on it remains meaningful.
	var inherits int64
	if err := h.db.Table("ssp_leverage_links AS l").
		Joins("JOIN provided_control_implementations p ON p.id = l.provided_uuid").
		Joins("JOIN control_implementation_responsibilities r ON r.provided_uuid = p.id AND r.export_id = p.export_id").
		Where("l.downstream_ssp_id = ? AND r.id = ? AND l.status NOT IN ?", req.SSPID, req.ResponsibilityUUID,
			[]relational.SSPLeverageStatus{relational.SSPLeverageStatusRevoked, relational.SSPLeverageStatusSuperseded}).
		Count(&inherits).Error; err != nil {
		h.sugar.Errorw("Failed to check inherited responsibility", "sspId", req.SSPID,
			"responsibilityUuid", req.ResponsibilityUUID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
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
		h.sugar.Errorw("Failed to check existing attachment", "filterId", filterID,
			"responsibilityUuid", req.ResponsibilityUUID, "sspId", req.SSPID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	row := relational.FilterResponsibility{
		FilterID:           filterID,
		ResponsibilityUUID: req.ResponsibilityUUID,
		SSPID:              req.SSPID,
	}

	var resolvedControl *relational.Control
	if req.ControlID != nil && strings.TrimSpace(*req.ControlID) != "" {
		// Control's PK is composite (catalog_id, id), so a control id alone does not identify a
		// control — NIST 800-53 rev4 and rev5 both define AC-2. Resolve the catalog through the
		// SSP's own profiles first; matching on id alone would pick an arbitrary catalog's row and
		// pin this filter (and every control-level compliance surface reading ControlCatalogID) to
		// a catalog the SSP may not even use.
		controlID := strings.TrimSpace(*req.ControlID)
		catalogID, err := h.resolveCatalogIDForSSPControl(req.SSPID, controlID)
		if errors.Is(err, errAmbiguousControlCatalog) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
				"control %q is defined in multiple catalogs and this SSP's profiles do not disambiguate it", controlID)))
		}
		if err != nil {
			h.sugar.Errorw("Failed to resolve control catalog", "controlId", controlID, "sspId", req.SSPID, "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		}
		if catalogID == nil {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("control %q not found", controlID)))
		}

		// The caller passes the SSP's casing of the control id, which is not reliably
		// the catalog's — match case-insensitively, like the leverage joins do.
		var control relational.Control
		if err := h.db.First(&control, "catalog_id = ? AND LOWER(id) = LOWER(?)", *catalogID, controlID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("control %q not found", *req.ControlID)))
			}
			h.sugar.Errorw("Failed to load control", "controlId", controlID, "catalogId", *catalogID, "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		}
		row.ControlID = &control.ID
		row.ControlCatalogID = &control.CatalogID
		resolvedControl = &control
	}

	// Link existence and co-ownership are decided INSIDE the transaction, under a row lock on the
	// filter. ControlLinkCreated is provenance, not derived state — nothing recomputes it later —
	// so a decision made against a snapshot another attach can invalidate is permanently wrong.
	//
	// The interleaving this prevents: attach A commits its filter_controls append; attach B, running
	// between A's two writes, sees the link present but no owning row yet and records
	// ControlLinkCreated = false; detaching A then finds no remaining claims and removes the
	// filter_controls row that B still depends on.
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if resolvedControl != nil {
			// Lock the filter row first: it is what concurrent attaches contend on, so it
			// serialises the read-decide-write below against another attach on the same filter.
			var locked relational.Filter
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&locked, "id = ?", filterID).Error; err != nil {
				return err
			}

			// Re-derive link existence inside the transaction with an explicit count. Reusing a
			// preloaded filter.Controls slice here would move the query but keep the stale
			// snapshot, which is the whole defect.
			var linkCount int64
			if err := tx.Table("filter_controls").
				Where("filter_id = ? AND control_id = ? AND control_catalog_id = ?",
					filterID, resolvedControl.ID, resolvedControl.CatalogID).
				Count(&linkCount).Error; err != nil {
				return err
			}

			if linkCount == 0 {
				if err := tx.Model(&locked).Association("Controls").Append(resolvedControl); err != nil {
					return err
				}
				row.ControlLinkCreated = true
			} else {
				// Co-ownership: if the existing link was itself created by a responsibility
				// attachment, this row claims it too, so the LAST detacher removes it. An
				// independently created link (POST/PUT /filters) is never owned.
				// Scoped by catalog as well as id: control_id alone spans catalogs, so a claim on
				// another catalog's AC-2 would otherwise read as a claim on this one.
				var owners int64
				if err := tx.Model(&relational.FilterResponsibility{}).
					Where("filter_id = ? AND control_id = ? AND control_catalog_id = ? AND control_link_created = true",
						filterID, resolvedControl.ID, resolvedControl.CatalogID).
					Count(&owners).Error; err != nil {
					return err
				}
				row.ControlLinkCreated = owners > 0
			}
		}
		return tx.Create(&row).Error
	}); err != nil {
		h.sugar.Errorw("Failed to attach responsibility", "filterId", filterID, "sspId", req.SSPID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
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
//
// errAmbiguousControlCatalog is returned when a control id matches controls in more than one
// catalog and nothing narrows the choice. Mapped to 400: picking one arbitrarily is the bug this
// resolution exists to prevent, so the caller has to say which catalog it means.
var errAmbiguousControlCatalog = errors.New("control id matches controls in multiple catalogs")

// resolveCatalogIDForSSPControl resolves controlID to exactly one catalog. Control's PK is
// composite (catalog_id, id), so a bare control id does not identify a control — NIST 800-53 rev4
// and rev5 both define AC-2.
//
// Two steps, in order:
//  1. The SSP's own profiles, which are authoritative about which catalog it means. This mirrors
//     handler/oscal's resolveCatalogIDForControl; it is replicated rather than shared because
//     handler/oscal imports this package for the response envelopes, so it cannot be imported back.
//  2. If the profiles don't import the control — which is legitimate and common, since a downstream
//     may rely on a leveraged capability without implementing the control itself — fall back to the
//     catalogs that define it. Exactly one match resolves; more than one is ambiguous and errors.
//     The fallback is tried against ACTIVE catalogs first: control ids like AC-2 recur in
//     essentially every catalog, so counting archived, superseded or draft catalogs would let a
//     dead catalog manufacture ambiguity among live ones and turn a legitimate attach into a 400
//     the client cannot resolve. Only if no active catalog defines the control does it re-run
//     unfiltered, so a control that lives solely in an archived catalog stays reachable.
//
// The point is that no arbitrary choice is ever made: the previous `First(id = ?)` returned
// whichever row the planner yielded, silently pinning the filter (and every control-level
// compliance surface reading ControlCatalogID) to a catalog the SSP may not even use.
//
// The join deliberately carries no CAST: ssp_profiles.profile_id and profile_controls.profile_id
// compare directly, matching the precedent in relational/system_component_suggestions.go, and
// casting to uuid would break the sqlite-backed unit suites. control_id stays free text, hence the
// UPPER() fold. A nil return with a nil error means no catalog defines the control at all — a 404.
func (h *FilterHandler) resolveCatalogIDForSSPControl(sspID uuid.UUID, controlID string) (*uuid.UUID, error) {
	var profileCatalogIDs []uuid.UUID
	if err := h.db.
		Table("profile_controls").
		Joins("JOIN ssp_profiles ON ssp_profiles.profile_id = profile_controls.profile_id").
		Where("ssp_profiles.system_security_plan_id = ? AND UPPER(profile_controls.control_id) = UPPER(?)", sspID, controlID).
		Distinct().
		Pluck("profile_controls.control_catalog_id", &profileCatalogIDs).Error; err != nil {
		return nil, err
	}
	switch len(profileCatalogIDs) {
	case 1:
		return &profileCatalogIDs[0], nil
	case 0:
		// Fall through to the catalog-wide lookup below.
	default:
		return nil, errAmbiguousControlCatalog
	}

	var activeCatalogIDs []uuid.UUID
	if err := h.db.Model(&relational.Control{}).
		Joins("JOIN catalogs ON catalogs.id = controls.catalog_id").
		Where("catalogs.active AND UPPER(controls.id) = UPPER(?)", controlID).
		Distinct().
		Pluck("controls.catalog_id", &activeCatalogIDs).Error; err != nil {
		return nil, err
	}
	switch len(activeCatalogIDs) {
	case 1:
		return &activeCatalogIDs[0], nil
	case 0:
		// Fall through to the unfiltered lookup below: no ACTIVE catalog defines this control, so
		// an archived one is the only candidate and is better than a spurious 404.
	default:
		// Genuine ambiguity among live catalogs — the caller has to say which it means.
		return nil, errAmbiguousControlCatalog
	}

	var catalogIDs []uuid.UUID
	if err := h.db.Model(&relational.Control{}).
		Where("UPPER(id) = UPPER(?)", controlID).
		Distinct().
		Pluck("catalog_id", &catalogIDs).Error; err != nil {
		return nil, err
	}
	switch len(catalogIDs) {
	case 1:
		return &catalogIDs[0], nil
	case 0:
		return nil, nil
	default:
		return nil, errAmbiguousControlCatalog
	}
}

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
		h.sugar.Errorw("Failed to load attachment", "filterId", filterID,
			"responsibilityUuid", responsibilityUUID, "sspId", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Where("filter_id = ? AND responsibility_uuid = ? AND ssp_id = ?", filterID, responsibilityUUID, sspID).
			Delete(&relational.FilterResponsibility{}).Error; err != nil {
			return err
		}

		// Unwind the control link only when this row owned it and nobody else claims it —
		// see the provenance comment on relational.FilterResponsibility.
		//
		// A claim is a row that CREATED the link (control_link_created), on this exact control
		// (catalog_id, id). Counting rows with control_link_created = false would count rows that
		// never claimed the link, blocking the unwind and leaking the link permanently; counting
		// across catalogs would do the same via an unrelated catalog's same-named control.
		if row.ControlLinkCreated && row.ControlID != nil && row.ControlCatalogID != nil {
			var claims int64
			if err := tx.Model(&relational.FilterResponsibility{}).
				Where("filter_id = ? AND control_id = ? AND control_catalog_id = ? AND control_link_created = true",
					filterID, *row.ControlID, *row.ControlCatalogID).
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
		h.sugar.Errorw("Failed to detach responsibility", "filterId", filterID,
			"responsibilityUuid", responsibilityUUID, "sspId", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	return ctx.NoContent(http.StatusNoContent)
}
