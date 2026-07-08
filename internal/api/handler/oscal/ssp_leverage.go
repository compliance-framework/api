package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
)

// thisSystemComponentType is the OSCAL convention for a placeholder component
// representing the system itself, used to anchor by-components that aren't tied to any
// specific local component (e.g. purely-inherited capabilities). There's no existing Go
// constant for this — it only appears in JSON test fixtures — so it's declared here.
const thisSystemComponentType = "this-system"

// upstreamResponsibility is the minimal shape both the catalog exposure (BCH-1338 task
// 004) and the subscribe handler (task 005) need: enough to let a downstream subscriber
// pick specific responsibility UUIDs to satisfy, and to compute full/partial coverage.
type upstreamResponsibility struct {
	ResponsibilityUUID uuid.UUID `json:"responsibilityUuid"`
	Description        string    `json:"description"`
}

// resolveUpstreamResponsibilities finds every ControlImplementationResponsibility that
// responsibility-maps to the ProvidedControlImplementation identified by providedUUID.
// The two are siblings under Export with no direct FK between them — only the shared
// OSCAL-level provided-uuid value — so this is a two-step lookup: find the provided
// item's ExportId, then find responsibilities in that same Export referencing
// providedUUID (scoped by export_id, not providedUUID alone, since provided-uuid values
// are only unique within a single upstream's Export). Returns an empty slice, not an
// error, if the provided item itself no longer exists — treated as "no responsibilities"
// rather than a failure, since an offering item's provided_uuid could in principle
// outlive the upstream row it once pointed at.
func resolveUpstreamResponsibilities(db *gorm.DB, providedUUID uuid.UUID) ([]upstreamResponsibility, error) {
	var provided relational.ProvidedControlImplementation
	if err := db.First(&provided, "id = ?", providedUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []upstreamResponsibility{}, nil
		}
		return nil, err
	}

	var responsibilities []relational.ControlImplementationResponsibility
	if err := db.Where("export_id = ? AND provided_uuid = ?", provided.ExportId, providedUUID).
		Find(&responsibilities).Error; err != nil {
		return nil, err
	}

	result := make([]upstreamResponsibility, 0, len(responsibilities))
	for _, r := range responsibilities {
		result = append(result, upstreamResponsibility{
			ResponsibilityUUID: *r.ID,
			Description:        r.Description,
		})
	}
	return result, nil
}

// deriveSatisfaction is the single definition of "full iff every upstream
// responsibility has a matching downstream satisfied" (vacuously full when full is
// empty), shared by Subscribe (computing the satisfaction to store on a new leverage
// link) and LeveragedControls (recomputing it live rather than trusting the stored
// value). Returns the subset of full not covered by satisfiedUUIDs as outstanding.
func deriveSatisfaction(full []upstreamResponsibility, satisfiedUUIDs map[uuid.UUID]bool) (relational.SSPLeverageSatisfaction, []upstreamResponsibility) {
	outstanding := make([]upstreamResponsibility, 0)
	for _, r := range full {
		if !satisfiedUUIDs[r.ResponsibilityUUID] {
			outstanding = append(outstanding, r)
		}
	}
	if len(outstanding) == 0 {
		return relational.SSPLeverageSatisfactionFull, outstanding
	}
	return relational.SSPLeverageSatisfactionPartial, outstanding
}

// SSPLeverageHandler serves the downstream side of BCH-1338 Phase 2: subscribing to a
// published SSPExportOffering (recording OSCAL inherited + satisfied + a
// leveraged-authorization on the downstream SSP) and the read-only projection over what
// a downstream SSP has subscribed to.
type SSPLeverageHandler struct {
	sugar    *zap.SugaredLogger
	db       *gorm.DB
	pdp      authz.PDP
	failMode authz.FailMode
}

func NewSSPLeverageHandler(l *zap.SugaredLogger, db *gorm.DB, pdp authz.PDP, failMode authz.FailMode) *SSPLeverageHandler {
	return &SSPLeverageHandler{sugar: l, db: db, pdp: pdp, failMode: failMode}
}

// RegisterSubscribe mounts the subscribe route onto the same group the flat
// ssp-export-offering catalog uses, gated by ssp-export-offering:subscribe.
func (h *SSPLeverageHandler) RegisterSubscribe(g *echo.Group, guard middleware.ResourceGuard) {
	g.POST("/:id/subscribe", h.Subscribe, guard.Do(authz.ActionSubscribe))
}

// RegisterProjection mounts the leveraged-controls projection onto the SSP handler's own
// route group, gated by the standard ssp:read.
func (h *SSPLeverageHandler) RegisterProjection(g *echo.Group, guard middleware.ResourceGuard) {
	g.GET("/:id/leveraged-controls", h.LeveragedControls, guard.Read())
}

// authorizeDownstreamUpdate enforces ssp:update on the downstream SSP identified by
// sspID, evaluated directly against the PDP rather than via route middleware — the
// downstream SSP id lives in the subscribe request body, not the URL, so the Subscribe
// route's own middleware (which only enforces ssp-export-offering:subscribe on the
// offering id in the URL) can't express this check. Mirrors PEP.Authorize's fail-mode
// handling. Critically, this is the only authorization check Subscribe performs against
// the downstream SSP's own resource — ssp:read on the *upstream* SSP is never evaluated
// anywhere in this path, which is the trust-boundary property AC #2 requires.
func (h *SSPLeverageHandler) authorizeDownstreamUpdate(ctx echo.Context, sspID uuid.UUID) (bool, error) {
	subject := middleware.SubjectFromContext(ctx)
	resource := authz.Resource{Type: authz.ResourceSSP, ID: sspID.String()}
	reqCtx := map[string]any{"method": ctx.Request().Method, "path": ctx.Path()}

	decision, err := h.pdp.Evaluate(ctx.Request().Context(), subject, authz.ActionUpdate, resource, reqCtx)
	if err != nil {
		if errors.Is(err, authz.ErrUnavailable) {
			h.sugar.Warnw("authz PDP unavailable for downstream ssp:update check",
				"sspId", sspID, "failMode", h.failMode, "error", err)
			return h.failMode == authz.FailOpen, nil
		}
		return false, err
	}
	return decision.Allow, nil
}

// findOrCreateThisSystemComponent finds the downstream's placeholder "this-system"
// component, creating one if none exists — not every SSP has one, and there's no
// guarantee the subscribing downstream does either.
func findOrCreateThisSystemComponent(tx *gorm.DB, systemImplementationID uuid.UUID) (*relational.SystemComponent, error) {
	var existing relational.SystemComponent
	err := tx.Where("system_implementation_id = ? AND type = ?", systemImplementationID, thisSystemComponentType).
		First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	created := relational.SystemComponent{
		Type:                   thisSystemComponentType,
		Title:                  "This System",
		Description:            "Placeholder component representing the system itself, used to anchor leveraged/inherited capabilities not tied to a specific local component.",
		SystemImplementationId: systemImplementationID,
	}
	if err := tx.Create(&created).Error; err != nil {
		return nil, err
	}
	return &created, nil
}

// findOrCreateImplementedRequirement finds the downstream's ImplementedRequirement for
// controlID under the given ControlImplementation, creating one if none exists. No
// find-or-create primitive exists elsewhere in the codebase for this — every existing
// creation path either does a naive insert (always creates) or a read-only lookup
// (404s if missing).
func findOrCreateImplementedRequirement(tx *gorm.DB, controlImplementationID uuid.UUID, controlID string) (*relational.ImplementedRequirement, error) {
	var existing relational.ImplementedRequirement
	err := tx.Where("control_implementation_id = ? AND control_id = ?", controlImplementationID, controlID).
		First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	created := relational.ImplementedRequirement{
		ControlImplementationId: controlImplementationID,
		ControlId:               controlID,
	}
	if err := tx.Create(&created).Error; err != nil {
		return nil, err
	}
	return &created, nil
}

// findOrCreateStatement finds the ImplementedRequirement's child Statement for
// statementID, creating one if none exists.
func findOrCreateStatement(tx *gorm.DB, implementedRequirementID uuid.UUID, statementID string) (*relational.Statement, error) {
	var existing relational.Statement
	err := tx.Where("implemented_requirement_id = ? AND statement_id = ?", implementedRequirementID, statementID).
		First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	created := relational.Statement{
		ImplementedRequirementId: implementedRequirementID,
		StatementId:              statementID,
	}
	if err := tx.Create(&created).Error; err != nil {
		return nil, err
	}
	return &created, nil
}

// findOrCreateByComponent finds the ByComponent row for (parentID, parentType,
// componentUUID), creating one if none exists. parentType is "implemented_requirements"
// or "statements", matching the string constants used throughout system_security_plans.go.
func findOrCreateByComponent(tx *gorm.DB, parentID uuid.UUID, parentType string, componentUUID uuid.UUID) (*relational.ByComponent, error) {
	var existing relational.ByComponent
	err := tx.Where("parent_id = ? AND parent_type = ? AND component_uuid = ?", parentID, parentType, componentUUID).
		First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	created := relational.ByComponent{
		ParentID:      &parentID,
		ParentType:    &parentType,
		ComponentUUID: componentUUID,
	}
	if err := tx.Create(&created).Error; err != nil {
		return nil, err
	}
	return &created, nil
}

type subscribeLeveragedAuthorizationRequest struct {
	Title          string `json:"title"`
	PartyUUID      string `json:"partyUuid"`
	DateAuthorized string `json:"dateAuthorized,omitempty"`
}

type subscribeItemRequest struct {
	ItemID                       string   `json:"itemId"`
	SatisfiedResponsibilityUUIDs []string `json:"satisfiedResponsibilityUuids,omitempty"`
}

type subscribeRequest struct {
	DownstreamSSPID        string                                 `json:"downstreamSspId"`
	LeveragedAuthorization subscribeLeveragedAuthorizationRequest `json:"leveragedAuthorization"`
	Items                  []subscribeItemRequest                 `json:"items"`
}

func (r subscribeRequest) validate() error {
	if _, err := uuid.Parse(r.DownstreamSSPID); err != nil {
		return fmt.Errorf("downstreamSspId must be a valid UUID")
	}
	if r.LeveragedAuthorization.Title == "" {
		return fmt.Errorf("leveragedAuthorization.title is required")
	}
	if _, err := uuid.Parse(r.LeveragedAuthorization.PartyUUID); err != nil {
		return fmt.Errorf("leveragedAuthorization.partyUuid must be a valid UUID")
	}
	if len(r.Items) == 0 {
		return fmt.Errorf("items must not be empty")
	}
	for _, item := range r.Items {
		if _, err := uuid.Parse(item.ItemID); err != nil {
			return fmt.Errorf("items[].itemId must be a valid UUID")
		}
		for _, respID := range item.SatisfiedResponsibilityUUIDs {
			if _, err := uuid.Parse(respID); err != nil {
				return fmt.Errorf("items[].satisfiedResponsibilityUuids must be valid UUIDs")
			}
		}
	}
	return nil
}

// Subscribe godoc
//
//	@Summary		Subscribe to a published export offering
//	@Description	Records, on the downstream SSP named in the request body, an OSCAL
//	@Description	inherited-control-implementation and (optionally) satisfied-responsibility
//	@Description	entries per chosen offering item, plus one leveraged-authorization for the
//	@Description	whole request — all in a single atomic write. Never checks ssp:read on the
//	@Description	upstream SSP: the trust boundary is that subscribing to a published offering
//	@Description	only requires ssp-export-offering:subscribe on the offering and ssp:update on
//	@Description	the downstream SSP.
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string				true	"Offering ID"
//	@Param			subscribe	body		subscribeRequest	true	"Subscribe request"
//	@Success		201			{object}	handler.GenericDataListResponse[relational.SSPLeverageLink]
//	@Failure		400			{object}	api.Error
//	@Failure		403			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/ssp-export-offerings/{id}/subscribe [post]
func (h *SSPLeverageHandler) Subscribe(ctx echo.Context) error {
	offeringIdParam := ctx.Param("id")
	offeringID, err := uuid.Parse(offeringIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid offering id", "id", offeringIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var offering relational.SSPExportOffering
	if err := h.db.Preload("Items").
		Where("status = ?", relational.SSPExportOfferingStatusPublished).
		First(&offering, "id = ?", offeringID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering not found")))
		}
		h.sugar.Errorf("Failed to load export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var req subscribeRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := req.validate(); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	downstreamSSPID := uuid.MustParse(req.DownstreamSSPID)

	allowed, err := h.authorizeDownstreamUpdate(ctx, downstreamSSPID)
	if err != nil {
		h.sugar.Errorf("authz evaluation failed for subscribe: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("authorization error")))
	}
	if !allowed {
		return echo.NewHTTPError(http.StatusForbidden, "forbidden")
	}

	itemsByID := make(map[uuid.UUID]relational.SSPExportOfferingItem, len(offering.Items))
	for _, item := range offering.Items {
		itemsByID[*item.ID] = item
	}
	for _, reqItem := range req.Items {
		if _, ok := itemsByID[uuid.MustParse(reqItem.ItemID)]; !ok {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("unknown offering item id %q", reqItem.ItemID)))
		}
	}

	var downstream relational.SystemSecurityPlan
	if err := h.db.
		Preload("ControlImplementation").
		Preload("SystemImplementation.Components").
		First(&downstream, "id = ?", downstreamSSPID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("downstream SSP not found")))
		}
		h.sugar.Errorf("Failed to load downstream SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Pre-check (downstream_ssp_id, provided_uuid) uniqueness before opening the write
	// transaction, so a duplicate subscribe gets a clean 409 rather than a raw
	// unique-constraint error whose shape differs between Postgres and sqlite.
	for _, reqItem := range req.Items {
		item := itemsByID[uuid.MustParse(reqItem.ItemID)]
		err := h.db.Where("downstream_ssp_id = ? AND provided_uuid = ?", downstreamSSPID, item.ProvidedUUID).
			First(&relational.SSPLeverageLink{}).Error
		if err == nil {
			return ctx.JSON(http.StatusConflict, api.NewError(fmt.Errorf("already subscribed to provided-uuid %q", item.ProvidedUUID)))
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Errorf("Failed to check existing leverage link: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	dateAuthorized := time.Now()
	if req.LeveragedAuthorization.DateAuthorized != "" {
		parsed, err := time.Parse(time.RFC3339, req.LeveragedAuthorization.DateAuthorized)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("leveragedAuthorization.dateAuthorized must be RFC3339")))
		}
		dateAuthorized = parsed
	}
	attestedBy := actorUserID(ctx)
	now := time.Now()

	var links []relational.SSPLeverageLink
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		thisSystemComponent, err := findOrCreateThisSystemComponent(tx, *downstream.SystemImplementation.ID)
		if err != nil {
			return err
		}

		leveragedAuth := relational.LeveragedAuthorization{
			Title:                  req.LeveragedAuthorization.Title,
			PartyUUID:              uuid.MustParse(req.LeveragedAuthorization.PartyUUID),
			DateAuthorized:         dateAuthorized,
			SystemImplementationId: *downstream.SystemImplementation.ID,
		}
		if err := tx.Create(&leveragedAuth).Error; err != nil {
			return err
		}

		for _, reqItem := range req.Items {
			item := itemsByID[uuid.MustParse(reqItem.ItemID)]

			implReq, err := findOrCreateImplementedRequirement(tx, *downstream.ControlImplementation.ID, item.ControlID)
			if err != nil {
				return err
			}

			parentID := *implReq.ID
			parentType := "implemented_requirements"
			if item.StatementID != nil {
				stmt, err := findOrCreateStatement(tx, *implReq.ID, *item.StatementID)
				if err != nil {
					return err
				}
				parentID = *stmt.ID
				parentType = "statements"
			}

			byComponent, err := findOrCreateByComponent(tx, parentID, parentType, *thisSystemComponent.ID)
			if err != nil {
				return err
			}

			inherited := relational.InheritedControlImplementation{
				ByComponentId: *byComponent.ID,
				ProvidedUuid:  item.ProvidedUUID,
				Description:   fmt.Sprintf("Inherited from offering %q (%s), v%d", offering.Title, offering.ID.String(), offering.Version),
			}
			if err := tx.Create(&inherited).Error; err != nil {
				return err
			}

			fullSet, err := resolveUpstreamResponsibilities(tx, item.ProvidedUUID)
			if err != nil {
				return err
			}
			fullByUUID := make(map[uuid.UUID]upstreamResponsibility, len(fullSet))
			for _, r := range fullSet {
				fullByUUID[r.ResponsibilityUUID] = r
			}

			satisfiedSet := make(map[uuid.UUID]bool, len(reqItem.SatisfiedResponsibilityUUIDs))
			for _, respIDStr := range reqItem.SatisfiedResponsibilityUUIDs {
				respID := uuid.MustParse(respIDStr)
				resp, ok := fullByUUID[respID]
				if !ok {
					return fmt.Errorf("responsibility uuid %q is not a valid responsibility for provided-uuid %q", respIDStr, item.ProvidedUUID)
				}
				if satisfiedSet[respID] {
					continue
				}
				satisfiedSet[respID] = true
				satisfied := relational.SatisfiedControlImplementationResponsibility{
					ByComponentId:      *byComponent.ID,
					ResponsibilityUuid: respID,
					Description:        resp.Description,
				}
				if err := tx.Create(&satisfied).Error; err != nil {
					return err
				}
			}

			satisfaction, _ := deriveSatisfaction(fullSet, satisfiedSet)

			link := relational.SSPLeverageLink{
				DownstreamSSPID:   downstreamSSPID,
				UpstreamSSPID:     offering.SSPID,
				OfferingID:        *offering.ID,
				OfferingVersion:   offering.Version,
				ControlID:         item.ControlID,
				StatementID:       item.StatementID,
				ProvidedUUID:      item.ProvidedUUID,
				InheritedUUID:     *inherited.ID,
				LeveragedAuthUUID: *leveragedAuth.ID,
				Satisfaction:      satisfaction,
				Status:            relational.SSPLeverageStatusActive,
				AttestedAt:        &now,
				AttestedByID:      attestedBy,
			}
			if err := tx.Create(&link).Error; err != nil {
				return err
			}
			links = append(links, link)
		}
		return nil
	}); err != nil {
		h.sugar.Errorf("Failed to subscribe to export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataListResponse[relational.SSPLeverageLink]{Data: links})
}

type leveragedControlInheritedFrom struct {
	UpstreamSSPID   uuid.UUID `json:"upstreamSspId"`
	OfferingID      uuid.UUID `json:"offeringId"`
	OfferingTitle   string    `json:"offeringTitle"`
	OfferingVersion int       `json:"offeringVersion"`
}

type leveragedControlResponse struct {
	ControlID                   string                             `json:"controlId"`
	StatementID                 *string                            `json:"statementId,omitempty"`
	InheritedFrom               leveragedControlInheritedFrom      `json:"inheritedFrom"`
	Satisfaction                relational.SSPLeverageSatisfaction `json:"satisfaction"`
	OutstandingResponsibilities []upstreamResponsibility           `json:"outstandingResponsibilities"`
}

// LeveragedControls godoc
//
//	@Summary		Project a downstream SSP's leveraged controls
//	@Description	Read-only view over the downstream SSP's own inherited/satisfied entries
//	@Description	joined to ssp_leverage_links + the upstream offering. Per control/statement,
//	@Description	returns which offering it was inherited from, whether satisfaction is full
//	@Description	or partial (recomputed live from the current satisfied-responsibility rows,
//	@Description	not trusted from the link's stored value), and any outstanding
//	@Description	responsibilities. Writes nothing; never touches profile_controls/controls.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id	path		string	true	"Downstream SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[leveragedControlResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/leveraged-controls [get]
func (h *SSPLeverageHandler) LeveragedControls(ctx echo.Context) error {
	sspIdParam := ctx.Param("id")
	sspID, err := uuid.Parse(sspIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", sspIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.db.Select("id").First(&relational.SystemSecurityPlan{}, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorf("Failed to load SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var links []relational.SSPLeverageLink
	if err := h.db.Where("downstream_ssp_id = ?", sspID).Find(&links).Error; err != nil {
		h.sugar.Errorf("Failed to list leverage links: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	result := make([]leveragedControlResponse, 0, len(links))
	for _, link := range links {
		var offering relational.SSPExportOffering
		if err := h.db.Select("id, title").First(&offering, "id = ?", link.OfferingID).Error; err != nil {
			h.sugar.Errorf("Failed to load offering for leverage link: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		var inherited relational.InheritedControlImplementation
		if err := h.db.First(&inherited, "id = ?", link.InheritedUUID).Error; err != nil {
			h.sugar.Errorf("Failed to load inherited control implementation for leverage link: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		fullSet, err := resolveUpstreamResponsibilities(h.db, link.ProvidedUUID)
		if err != nil {
			h.sugar.Errorf("Failed to resolve upstream responsibilities for leverage link: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		var satisfiedRows []relational.SatisfiedControlImplementationResponsibility
		if err := h.db.Where("by_component_id = ?", inherited.ByComponentId).Find(&satisfiedRows).Error; err != nil {
			h.sugar.Errorf("Failed to load satisfied responsibilities for leverage link: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		satisfiedByUUID := make(map[uuid.UUID]bool, len(satisfiedRows))
		for _, s := range satisfiedRows {
			satisfiedByUUID[s.ResponsibilityUuid] = true
		}

		satisfaction, outstanding := deriveSatisfaction(fullSet, satisfiedByUUID)

		result = append(result, leveragedControlResponse{
			ControlID:   link.ControlID,
			StatementID: link.StatementID,
			InheritedFrom: leveragedControlInheritedFrom{
				UpstreamSSPID:   link.UpstreamSSPID,
				OfferingID:      link.OfferingID,
				OfferingTitle:   offering.Title,
				OfferingVersion: link.OfferingVersion,
			},
			Satisfaction:                satisfaction,
			OutstandingResponsibilities: outstanding,
		})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[leveragedControlResponse]{Data: result})
}
