package oscal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
)

// canonicalOfferingItem is the deterministic, order-independent shape an
// SSPExportOfferingItem hashes into: only the fields that define what is being
// offered, normalized so struct field order and JSON tag order can't perturb the hash.
type canonicalOfferingItem struct {
	ControlID            string `json:"control_id"`
	StatementID          string `json:"statement_id"`
	ComponentUUID        string `json:"component_uuid"`
	ProvidedUUID         string `json:"provided_uuid"`
	ImplementationStatus string `json:"implementation_status"`
}

// resolveItemImplementationStatuses resolves, for the distinct ProvidedUUIDs across
// items, the live ImplementationStatus of the ByComponent backing each provided
// capability (item.ProvidedUUID -> ProvidedControlImplementation.ExportId ->
// Export.ByComponentId -> ByComponent.ImplementationStatus). This is looked up fresh on
// every call rather than trusted from any cached copy, since it's exactly the signal a
// downgrade (implemented -> planned/partial) needs to be visible as drift (BCH-1341). A
// provided uuid whose chain doesn't resolve (dangling reference) contributes an empty
// status rather than failing the whole sync.
func resolveItemImplementationStatuses(db *gorm.DB, items []relational.SSPExportOfferingItem) (map[uuid.UUID]string, error) {
	result := make(map[uuid.UUID]string, len(items))
	if len(items) == 0 {
		return result, nil
	}

	providedUUIDs := make([]uuid.UUID, 0, len(items))
	seen := make(map[uuid.UUID]struct{}, len(items))
	for _, item := range items {
		if _, ok := seen[item.ProvidedUUID]; ok {
			continue
		}
		seen[item.ProvidedUUID] = struct{}{}
		providedUUIDs = append(providedUUIDs, item.ProvidedUUID)
	}

	var provided []relational.ProvidedControlImplementation
	if err := db.Where("id IN ?", providedUUIDs).Find(&provided).Error; err != nil {
		return nil, fmt.Errorf("failed to load provided control implementations: %w", err)
	}
	if len(provided) == 0 {
		return result, nil
	}

	exportIDs := make([]uuid.UUID, 0, len(provided))
	exportIDByProvided := make(map[uuid.UUID]uuid.UUID, len(provided))
	for _, p := range provided {
		exportIDByProvided[*p.ID] = p.ExportId
		exportIDs = append(exportIDs, p.ExportId)
	}

	var exports []relational.Export
	if err := db.Where("id IN ?", exportIDs).Find(&exports).Error; err != nil {
		return nil, fmt.Errorf("failed to load exports: %w", err)
	}
	byComponentIDByExport := make(map[uuid.UUID]uuid.UUID, len(exports))
	byComponentIDs := make([]uuid.UUID, 0, len(exports))
	for _, e := range exports {
		byComponentIDByExport[*e.ID] = e.ByComponentId
		byComponentIDs = append(byComponentIDs, e.ByComponentId)
	}

	var byComponents []relational.ByComponent
	if err := db.Where("id IN ?", byComponentIDs).Find(&byComponents).Error; err != nil {
		return nil, fmt.Errorf("failed to load by-components: %w", err)
	}
	statusByComponent := make(map[uuid.UUID]string, len(byComponents))
	for _, bc := range byComponents {
		statusByComponent[*bc.ID] = string(bc.ImplementationStatus.Data().State)
	}

	for providedID, exportID := range exportIDByProvided {
		byComponentID, ok := byComponentIDByExport[exportID]
		if !ok {
			continue
		}
		if status, ok := statusByComponent[byComponentID]; ok {
			result[providedID] = status
		}
	}

	return result, nil
}

// computeOfferingContentHash returns a deterministic sha256 hex digest over an
// offering's curatorial content — title, description, and its items (including the
// live ImplementationStatus of the component backing each item, BCH-1341) — so that two
// offerings (or the same offering re-read in a different item order) with identical
// content always hash identically, and any real content change always changes it.
func computeOfferingContentHash(title, description string, items []relational.SSPExportOfferingItem, statusByProvidedUUID map[uuid.UUID]string) string {
	canon := make([]canonicalOfferingItem, 0, len(items))
	for _, item := range items {
		statementID := ""
		if item.StatementID != nil {
			statementID = *item.StatementID
		}
		canon = append(canon, canonicalOfferingItem{
			ControlID:            item.ControlID,
			StatementID:          statementID,
			ComponentUUID:        item.ComponentUUID.String(),
			ProvidedUUID:         item.ProvidedUUID.String(),
			ImplementationStatus: statusByProvidedUUID[item.ProvidedUUID],
		})
	}
	sort.Slice(canon, func(i, j int) bool {
		a, b := canon[i], canon[j]
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		if a.StatementID != b.StatementID {
			return a.StatementID < b.StatementID
		}
		if a.ComponentUUID != b.ComponentUUID {
			return a.ComponentUUID < b.ComponentUUID
		}
		return a.ProvidedUUID < b.ProvidedUUID
	})

	payload, _ := json.Marshal(struct {
		Title       string                  `json:"title"`
		Description string                  `json:"description"`
		Items       []canonicalOfferingItem `json:"items"`
	}{Title: title, Description: description, Items: canon})

	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// SyncExportOffering is the single write path for an SSPExportOffering's ContentHash
// and Version, sibling of SyncProfileControls (profiles.go). It recomputes the content
// hash from the offering's current title/description/items and, only if that hash
// actually changed, increments Version and persists the new hash — so calling it on an
// unchanged offering (an idempotent republish) is a no-op. Mirrors SyncProfileControls's
// concurrency guard: it captures UpdatedAt before recomputing, then aborts inside the
// write transaction if the row was modified in the meantime, rather than overwriting a
// newer state with a stale computation.
func SyncExportOffering(db *gorm.DB, offeringID uuid.UUID) ([]driftedLinkInfo, error) {
	var offering relational.SSPExportOffering
	if err := db.Preload("Items").First(&offering, "id = ?", offeringID).Error; err != nil {
		return nil, err
	}
	originalUpdatedAt := offering.UpdatedAt

	statusByProvidedUUID, err := resolveItemImplementationStatuses(db, offering.Items)
	if err != nil {
		return nil, err
	}
	newHash := computeOfferingContentHash(offering.Title, offering.Description, offering.Items, statusByProvidedUUID)

	var driftedLinks []driftedLinkInfo
	txErr := db.Transaction(func(tx *gorm.DB) error {
		var current relational.SSPExportOffering
		if err := tx.First(&current, "id = ?", offeringID).Error; err != nil {
			return err
		}

		// Safety check: if the offering has been modified since we started recomputing,
		// abort. This prevents an older, in-flight sync from overwriting a newer one.
		if current.UpdatedAt.After(originalUpdatedAt) {
			return fmt.Errorf("export offering was modified during sync; skipping stale sync")
		}

		if current.ContentHash == newHash {
			return nil
		}

		current.ContentHash = newHash
		current.Version++
		if err := tx.Save(&current).Error; err != nil {
			return err
		}

		links, err := evaluateLeverageDriftForOffering(tx, current)
		if err != nil {
			return err
		}
		driftedLinks = links
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return driftedLinks, nil
}

// touchOfferingUpdatedAt bumps an offering's own UpdatedAt without touching any other
// column. Item mutations (CreateItem/UpdateItem/DeleteItem) call this after writing to
// ssp_export_offering_items: SyncExportOffering's staleness guard only compares the
// offering row's own UpdatedAt, and an item change doesn't otherwise touch that row, so
// without this a concurrent item edit racing a publish could go undetected and get
// silently overwritten by a hash computed from the pre-edit item snapshot.
func touchOfferingUpdatedAt(tx *gorm.DB, offeringID uuid.UUID) error {
	return tx.Model(&relational.SSPExportOffering{}).
		Where("id = ?", offeringID).
		Update("updated_at", time.Now()).Error
}

// SSPExportOfferingHandler serves both the SSP-nested curation surface (create/edit/
// delete/publish, gated by ssp:export) and the top-level read-only ssp-export-offering
// catalog (gated by ssp-export-offering:read).
type SSPExportOfferingHandler struct {
	sugar       *zap.SugaredLogger
	db          *gorm.DB
	jobEnqueuer SSPJobEnqueuer
}

func NewSSPExportOfferingHandler(l *zap.SugaredLogger, db *gorm.DB, jobEnqueuer SSPJobEnqueuer) *SSPExportOfferingHandler {
	return &SSPExportOfferingHandler{sugar: l, db: db, jobEnqueuer: jobEnqueuer}
}

// RegisterNested mounts the SSP-scoped curation routes onto the SSP handler's own
// route group, guarded uniformly by ssp:export — curating and publishing an offering
// is a distinct capability from ssp's ordinary read/create/update/delete verbs.
func (h *SSPExportOfferingHandler) RegisterNested(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("/:id/export-offerings", h.ListForSSP, guard.Do(authz.ActionExport))
	api.POST("/:id/export-offerings", h.CreateOffering, guard.Do(authz.ActionExport))
	api.GET("/:id/export-offerings/:offeringId", h.GetOffering, guard.Do(authz.ActionExport))
	api.PUT("/:id/export-offerings/:offeringId", h.UpdateOffering, guard.Do(authz.ActionExport))
	api.DELETE("/:id/export-offerings/:offeringId", h.DeleteOffering, guard.Do(authz.ActionExport))
	api.POST("/:id/export-offerings/:offeringId/items", h.CreateItem, guard.Do(authz.ActionExport))
	api.PUT("/:id/export-offerings/:offeringId/items/:itemId", h.UpdateItem, guard.Do(authz.ActionExport))
	api.DELETE("/:id/export-offerings/:offeringId/items/:itemId", h.DeleteItem, guard.Do(authz.ActionExport))
	api.POST("/:id/export-offerings/:offeringId/publish", h.Publish, guard.Do(authz.ActionExport))
	api.PATCH("/:id/export-offerings/:offeringId/status", h.UpdateOfferingStatus, guard.Do(authz.ActionExport))
	api.GET("/:id/export-offerings/:offeringId/allowed-downstreams", h.ListAllowedDownstreams, guard.Do(authz.ActionExport))
	api.POST("/:id/export-offerings/:offeringId/allowed-downstreams", h.AddAllowedDownstream, guard.Do(authz.ActionExport))
	api.DELETE("/:id/export-offerings/:offeringId/allowed-downstreams/:downstreamSspId", h.RemoveAllowedDownstream, guard.Do(authz.ActionExport))
}

// Register mounts the top-level, cross-SSP read-only catalog: list and get any
// offering by its own ID, plus the control-centric by-control query — all gated by
// ssp-export-offering:read.
func (h *SSPExportOfferingHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("", h.ListAll, guard.Read())
	api.GET("/by-control/:controlId", h.ByControl, guard.Read())
	api.GET("/:id", h.GetByID, guard.Read())
}

// actorUserID resolves the authenticated subject's own user UUID (set on the JWT at
// login) for CreatedByID attribution. Returns nil (not an error) if the claim is
// missing/invalid — attribution is best-effort, not a request precondition.
func actorUserID(ctx echo.Context) *uuid.UUID {
	claims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || claims == nil || claims.UserUUID == "" {
		return nil
	}
	id, err := uuid.Parse(claims.UserUUID)
	if err != nil {
		return nil
	}
	return &id
}

// resolveOfferingForSSP loads the offering (with its items) and verifies it belongs to
// the SSP named in the :id path param, writing the appropriate error response and
// returning ok=false if either lookup fails.
func (h *SSPExportOfferingHandler) resolveOfferingForSSP(ctx echo.Context) (offering *relational.SSPExportOffering, ok bool) {
	sspIdParam := ctx.Param("id")
	sspID, err := uuid.Parse(sspIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", sspIdParam, "error", err)
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}

	offeringIdParam := ctx.Param("offeringId")
	offeringID, err := uuid.Parse(offeringIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid offering id", "offeringId", offeringIdParam, "error", err)
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}

	var existing relational.SSPExportOffering
	if err := h.db.Preload("Items").Where("id = ? AND ssp_id = ?", offeringID, sspID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering not found")))
			return nil, false
		}
		h.sugar.Errorf("Failed to load export offering: %v", err)
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	return &existing, true
}

// ListForSSP godoc
//
//	@Summary		List export offerings for an SSP
//	@Description	Retrieves every export offering curated for a given system security plan.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[relational.SSPExportOffering]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings [get]
func (h *SSPExportOfferingHandler) ListForSSP(ctx echo.Context) error {
	sspIdParam := ctx.Param("id")
	sspID, err := uuid.Parse(sspIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", sspIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var offerings []relational.SSPExportOffering
	if err := h.db.Preload("Items").Where("ssp_id = ?", sspID).Find(&offerings).Error; err != nil {
		h.sugar.Errorf("Failed to list export offerings: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[relational.SSPExportOffering]{Data: offerings})
}

type createExportOfferingRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// CreateOffering godoc
//
//	@Summary		Create an export offering
//	@Description	Creates a new draft export offering for an SSP.
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			offering	body		createExportOfferingRequest	true	"Offering data"
//	@Success		201			{object}	handler.GenericDataResponse[relational.SSPExportOffering]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings [post]
func (h *SSPExportOfferingHandler) CreateOffering(ctx echo.Context) error {
	sspIdParam := ctx.Param("id")
	sspID, err := uuid.Parse(sspIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", sspIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var req createExportOfferingRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.Title == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("title is required")))
	}

	offering := relational.SSPExportOffering{
		SSPID:       sspID,
		Title:       req.Title,
		Description: req.Description,
		Status:      relational.SSPExportOfferingStatusDraft,
		CreatedByID: actorUserID(ctx),
	}
	if err := h.db.Create(&offering).Error; err != nil {
		h.sugar.Errorf("Failed to create export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[relational.SSPExportOffering]{Data: offering})
}

// GetOffering godoc
//
//	@Summary		Get an export offering
//	@Description	Retrieves a single export offering (with its items) curated for an SSP.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id			path		string	true	"SSP ID"
//	@Param			offeringId	path		string	true	"Offering ID"
//	@Success		200			{object}	handler.GenericDataResponse[relational.SSPExportOffering]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId} [get]
func (h *SSPExportOfferingHandler) GetOffering(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPExportOffering]{Data: *offering})
}

// UpdateOffering godoc
//
//	@Summary		Update an export offering
//	@Description	Updates the title/description of an export offering. Does not change items, status, version or content_hash.
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			offeringId	path		string						true	"Offering ID"
//	@Param			offering	body		createExportOfferingRequest	true	"Offering data"
//	@Success		200			{object}	handler.GenericDataResponse[relational.SSPExportOffering]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId} [put]
func (h *SSPExportOfferingHandler) UpdateOffering(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}

	var req createExportOfferingRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.Title == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("title is required")))
	}

	offering.Title = req.Title
	offering.Description = req.Description
	if err := h.db.Model(&relational.SSPExportOffering{}).
		Where("id = ?", offering.ID).
		Updates(map[string]any{"title": offering.Title, "description": offering.Description}).Error; err != nil {
		h.sugar.Errorf("Failed to update export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPExportOffering]{Data: *offering})
}

// DeleteOffering godoc
//
//	@Summary		Delete an export offering
//	@Description	Deletes an export offering and its items.
//	@Tags			SSP Export Offerings
//	@Param			id			path	string	true	"SSP ID"
//	@Param			offeringId	path	string	true	"Offering ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId} [delete]
func (h *SSPExportOfferingHandler) DeleteOffering(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}

	// Items are deleted explicitly rather than relying on a DB-level cascade: this
	// codebase's DB connector disables FK constraint creation during AutoMigrate
	// (DisableForeignKeyConstraintWhenMigrating), so the item's OnDelete:CASCADE tag
	// documents intent but is not itself enforced by Postgres.
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("offering_id = ?", offering.ID).Delete(&relational.SSPExportOfferingItem{}).Error; err != nil {
			return err
		}
		return tx.Delete(offering).Error
	}); err != nil {
		h.sugar.Errorf("Failed to delete export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

type createExportOfferingItemRequest struct {
	ControlID string `json:"controlId"`
	// StatementID is required on every write. The statement is the canonical anchor for
	// shared responsibility: a control is too coarse to attribute a provided capability
	// against, and a requirement-anchored item leaves the downstream unable to say which
	// clause the upstream discharges. Still a *string (not string) because the DB column
	// stays nullable for legacy rows that pre-date this constraint — see
	// migrateBackfillOfferingItemStatementIDs.
	StatementID   *string `json:"statementId"`
	ComponentUUID string  `json:"componentUuid"`
	ProvidedUUID  string  `json:"providedUuid"`
}

func (r createExportOfferingItemRequest) validate() error {
	if r.ControlID == "" {
		return fmt.Errorf("controlId is required")
	}
	if r.StatementID == nil || strings.TrimSpace(*r.StatementID) == "" {
		return fmt.Errorf("statementId is required: shared responsibility is tracked per statement — pick the statement this provided capability is exported from")
	}
	if _, err := uuid.Parse(r.ComponentUUID); err != nil {
		return fmt.Errorf("componentUuid must be a valid UUID")
	}
	if _, err := uuid.Parse(r.ProvidedUUID); err != nil {
		return fmt.Errorf("providedUuid must be a valid UUID")
	}
	return nil
}

// validateOfferingItemCoherence checks that the item's (ControlID, StatementID,
// ComponentUUID, ProvidedUUID) tuple actually describes one real statement-anchored
// by-component inside the offering's own SSP, rather than four independently-plausible
// identifiers. Nothing validated this before: an item could name a provided-uuid from a
// different SSP entirely, or pair it with a control/statement/component it has no relation
// to, and the incoherence only surfaced downstream at subscribe time (or never).
//
// It walks the ownership chain the offering item is a by-value pointer into:
//
//	Provided -> Export -> ByComponent (must be statement-anchored)
//	         -> Statement (statement-id must match) -> ImplementedRequirement (control-id must match)
//	         -> ControlImplementation (must be this SSP's)
//
// resolveItemImplementationStatuses walks the first half of the same chain, but only ever
// projects the ByComponent's implementation-status out of it — it discards the parent
// identities this check exists to compare — so the walk is done explicitly here.
func (h *SSPExportOfferingHandler) validateOfferingItemCoherence(sspID uuid.UUID, req createExportOfferingItemRequest) error {
	providedUUID := uuid.MustParse(req.ProvidedUUID)
	componentUUID := uuid.MustParse(req.ComponentUUID)

	var provided relational.ProvidedControlImplementation
	if err := h.db.First(&provided, "id = ?", providedUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("providedUuid %q does not exist", req.ProvidedUUID)
		}
		return err
	}

	var export relational.Export
	if err := h.db.First(&export, "id = ?", provided.ExportId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("providedUuid %q has no export", req.ProvidedUUID)
		}
		return err
	}

	var byComponent relational.ByComponent
	if err := h.db.First(&byComponent, "id = ?", export.ByComponentId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("providedUuid %q has no by-component", req.ProvidedUUID)
		}
		return err
	}

	if byComponent.ParentType == nil || *byComponent.ParentType != "statements" || byComponent.ParentID == nil {
		return fmt.Errorf("providedUuid %q is exported from a requirement-anchored by-component; shared responsibility is tracked per statement", req.ProvidedUUID)
	}
	if byComponent.ComponentUUID != componentUUID {
		return fmt.Errorf("componentUuid %q does not match the component exporting providedUuid %q", req.ComponentUUID, req.ProvidedUUID)
	}

	var statement relational.Statement
	if err := h.db.First(&statement, "id = ?", *byComponent.ParentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("providedUuid %q has no statement", req.ProvidedUUID)
		}
		return err
	}
	if statement.StatementId != *req.StatementID {
		return fmt.Errorf("statementId %q does not match the statement exporting providedUuid %q", *req.StatementID, req.ProvidedUUID)
	}

	var requirement relational.ImplementedRequirement
	if err := h.db.First(&requirement, "id = ?", statement.ImplementedRequirementId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("providedUuid %q has no implemented requirement", req.ProvidedUUID)
		}
		return err
	}
	if !strings.EqualFold(requirement.ControlId, req.ControlID) {
		return fmt.Errorf("controlId %q does not match the control exporting providedUuid %q", req.ControlID, req.ProvidedUUID)
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		return err
	}
	if ssp.ControlImplementation.ID == nil || *ssp.ControlImplementation.ID != requirement.ControlImplementationId {
		return fmt.Errorf("providedUuid %q does not resolve inside this SSP", req.ProvidedUUID)
	}

	return nil
}

// CreateItem godoc
//
//	@Summary		Add an item to an export offering
//	@Description	Adds one offered capability (a control, optionally scoped to a statement, implemented by a component) to a draft export offering.
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"SSP ID"
//	@Param			offeringId	path		string							true	"Offering ID"
//	@Param			item		body		createExportOfferingItemRequest	true	"Item data"
//	@Success		201			{object}	handler.GenericDataResponse[relational.SSPExportOfferingItem]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/items [post]
func (h *SSPExportOfferingHandler) CreateItem(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}
	if offering.Status == relational.SSPExportOfferingStatusRevoked {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("cannot modify a revoked offering")))
	}

	var req createExportOfferingItemRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := req.validate(); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.validateOfferingItemCoherence(offering.SSPID, req); err != nil {
		h.sugar.Warnw("Incoherent export offering item", "offeringId", offering.ID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	item := relational.SSPExportOfferingItem{
		OfferingID:    *offering.ID,
		ControlID:     req.ControlID,
		StatementID:   req.StatementID,
		ComponentUUID: uuid.MustParse(req.ComponentUUID),
		ProvidedUUID:  uuid.MustParse(req.ProvidedUUID),
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&item).Error; err != nil {
			return err
		}
		return touchOfferingUpdatedAt(tx, *offering.ID)
	}); err != nil {
		h.sugar.Errorf("Failed to create export offering item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[relational.SSPExportOfferingItem]{Data: item})
}

// UpdateItem godoc
//
//	@Summary		Update an export offering item
//	@Description	Updates one item of an export offering.
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"SSP ID"
//	@Param			offeringId	path		string							true	"Offering ID"
//	@Param			itemId		path		string							true	"Item ID"
//	@Param			item		body		createExportOfferingItemRequest	true	"Item data"
//	@Success		200			{object}	handler.GenericDataResponse[relational.SSPExportOfferingItem]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/items/{itemId} [put]
func (h *SSPExportOfferingHandler) UpdateItem(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}
	if offering.Status == relational.SSPExportOfferingStatusRevoked {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("cannot modify a revoked offering")))
	}

	itemIdParam := ctx.Param("itemId")
	itemID, err := uuid.Parse(itemIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid item id", "itemId", itemIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req createExportOfferingItemRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := req.validate(); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.validateOfferingItemCoherence(offering.SSPID, req); err != nil {
		h.sugar.Warnw("Incoherent export offering item", "offeringId", offering.ID, "itemId", itemID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var rowsAffected int64
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&relational.SSPExportOfferingItem{}).
			Where("id = ? AND offering_id = ?", itemID, offering.ID).
			Updates(map[string]any{
				"control_id":     req.ControlID,
				"statement_id":   req.StatementID,
				"component_uuid": uuid.MustParse(req.ComponentUUID),
				"provided_uuid":  uuid.MustParse(req.ProvidedUUID),
			})
		if result.Error != nil {
			return result.Error
		}
		rowsAffected = result.RowsAffected
		if rowsAffected == 0 {
			return nil
		}
		return touchOfferingUpdatedAt(tx, *offering.ID)
	}); err != nil {
		h.sugar.Errorf("Failed to update export offering item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if rowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering item not found")))
	}

	var updated relational.SSPExportOfferingItem
	if err := h.db.First(&updated, "id = ?", itemID).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPExportOfferingItem]{Data: updated})
}

// DeleteItem godoc
//
//	@Summary		Delete an export offering item
//	@Description	Removes one item from an export offering.
//	@Tags			SSP Export Offerings
//	@Param			id			path	string	true	"SSP ID"
//	@Param			offeringId	path	string	true	"Offering ID"
//	@Param			itemId		path	string	true	"Item ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/items/{itemId} [delete]
func (h *SSPExportOfferingHandler) DeleteItem(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}
	if offering.Status == relational.SSPExportOfferingStatusRevoked {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("cannot modify a revoked offering")))
	}

	itemIdParam := ctx.Param("itemId")
	itemID, err := uuid.Parse(itemIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid item id", "itemId", itemIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var rowsAffected int64
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Where("id = ? AND offering_id = ?", itemID, offering.ID).Delete(&relational.SSPExportOfferingItem{})
		if result.Error != nil {
			return result.Error
		}
		rowsAffected = result.RowsAffected
		if rowsAffected == 0 {
			return nil
		}
		return touchOfferingUpdatedAt(tx, *offering.ID)
	}); err != nil {
		h.sugar.Errorf("Failed to delete export offering item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if rowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering item not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

type allowedDownstreamRequest struct {
	DownstreamSSPID string `json:"downstreamSspId"`
}

func (r allowedDownstreamRequest) validate() error {
	if _, err := uuid.Parse(r.DownstreamSSPID); err != nil {
		return fmt.Errorf("downstreamSspId must be a valid UUID")
	}
	return nil
}

// ListAllowedDownstreams godoc
//
//	@Summary		List an export offering's downstream-SSP allow-list
//	@Description	Returns every downstream SSP allow-listed to subscribe to this offering
//	@Description	(BCH-1342). An empty list means the offering has no allow-list set — any
//	@Description	downstream may subscribe (subject to the existing ssp:update and
//	@Description	contributor-role checks), the type-level default.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id			path		string	true	"SSP ID"
//	@Param			offeringId	path		string	true	"Offering ID"
//	@Success		200			{object}	handler.GenericDataListResponse[relational.SSPExportOfferingAllowedDownstream]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/allowed-downstreams [get]
func (h *SSPExportOfferingHandler) ListAllowedDownstreams(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}

	var allowed []relational.SSPExportOfferingAllowedDownstream
	if err := h.db.Where("offering_id = ?", offering.ID).Find(&allowed).Error; err != nil {
		h.sugar.Errorf("Failed to list offering allow-list: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[relational.SSPExportOfferingAllowedDownstream]{Data: allowed})
}

// AddAllowedDownstream godoc
//
//	@Summary		Add a downstream SSP to an export offering's allow-list
//	@Description	Once an offering has at least one allow-list entry, only listed downstream
//	@Description	SSPs may subscribe to it (BCH-1342) — enforced by a handler-level check in
//	@Description	Subscribe, not by the PDP.
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			offeringId	path		string						true	"Offering ID"
//	@Param			body		body		allowedDownstreamRequest	true	"Downstream SSP to allow"
//	@Success		201			{object}	handler.GenericDataResponse[relational.SSPExportOfferingAllowedDownstream]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/allowed-downstreams [post]
func (h *SSPExportOfferingHandler) AddAllowedDownstream(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}

	var req allowedDownstreamRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := req.validate(); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	downstreamSSPID, err := uuid.Parse(req.DownstreamSSPID)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	allowed := relational.SSPExportOfferingAllowedDownstream{
		OfferingID:      *offering.ID,
		DownstreamSSPID: downstreamSSPID,
	}
	if err := h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&allowed).Error; err != nil {
		h.sugar.Errorf("Failed to add offering allow-list entry: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[relational.SSPExportOfferingAllowedDownstream]{Data: allowed})
}

// RemoveAllowedDownstream godoc
//
//	@Summary		Remove a downstream SSP from an export offering's allow-list
//	@Description	If this removes the offering's last allow-list entry, the offering
//	@Description	reverts to the type-level default (any downstream may subscribe,
//	@Description	subject to the existing ssp:update and contributor-role checks).
//	@Tags			SSP Export Offerings
//	@Param			id				path	string	true	"SSP ID"
//	@Param			offeringId		path	string	true	"Offering ID"
//	@Param			downstreamSspId	path	string	true	"Downstream SSP ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/allowed-downstreams/{downstreamSspId} [delete]
func (h *SSPExportOfferingHandler) RemoveAllowedDownstream(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}

	downstreamSspIdParam := ctx.Param("downstreamSspId")
	downstreamSSPID, err := uuid.Parse(downstreamSspIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid downstream SSP id", "downstreamSspId", downstreamSspIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	result := h.db.Where("offering_id = ? AND downstream_ssp_id = ?", offering.ID, downstreamSSPID).
		Delete(&relational.SSPExportOfferingAllowedDownstream{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to remove offering allow-list entry: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("allow-list entry not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// Publish godoc
//
//	@Summary		Publish an export offering
//	@Description	Transitions a draft export offering to published (or republishes a
//	@Description	published one), recomputing content_hash via SyncExportOffering and
//	@Description	bumping version only if the content actually changed since the last publish.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id			path		string	true	"SSP ID"
//	@Param			offeringId	path		string	true	"Offering ID"
//	@Success		200			{object}	handler.GenericDataResponse[relational.SSPExportOffering]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/publish [post]
func (h *SSPExportOfferingHandler) Publish(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}

	if offering.Status == relational.SSPExportOfferingStatusDeprecated || offering.Status == relational.SSPExportOfferingStatusRevoked {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("cannot publish an offering with status %q", offering.Status)))
	}

	now := time.Now()
	var driftedLinks []driftedLinkInfo
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		links, err := SyncExportOffering(tx, *offering.ID)
		if err != nil {
			return err
		}
		driftedLinks = links
		return tx.Model(&relational.SSPExportOffering{}).
			Where("id = ?", offering.ID).
			Updates(map[string]any{"status": relational.SSPExportOfferingStatusPublished, "published_at": &now}).Error
	}); err != nil {
		h.sugar.Errorf("Failed to publish export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	enqueueLeverageDriftNotificationsAsync(ctx, h.sugar, h.jobEnqueuer, driftedLinks)

	var published relational.SSPExportOffering
	if err := h.db.Preload("Items").First(&published, "id = ?", offering.ID).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPExportOffering]{Data: published})
}

// updateOfferingStatusRequest is the body for UpdateOfferingStatus: only the two
// terminal, drift-triggering transitions are allowed here — draft/published stay owned
// by CreateOffering/Publish.
type updateOfferingStatusRequest struct {
	Status string `json:"status" binding:"required" enums:"deprecated,revoked"`
}

func (r updateOfferingStatusRequest) validate() error {
	switch relational.SSPExportOfferingStatus(r.Status) {
	case relational.SSPExportOfferingStatusDeprecated, relational.SSPExportOfferingStatusRevoked:
		return nil
	default:
		return fmt.Errorf("status must be %q or %q", relational.SSPExportOfferingStatusDeprecated, relational.SSPExportOfferingStatusRevoked)
	}
}

// UpdateOfferingStatus godoc
//
//	@Summary		Deprecate or revoke an export offering
//	@Description	Transitions a published export offering to deprecated or revoked,
//	@Description	which — independent of any content change — drifts every active
//	@Description	leverage link pointing at it (BCH-1341 Phase 5).
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			offeringId	path		string						true	"Offering ID"
//	@Param			body		body		updateOfferingStatusRequest	true	"New status"
//	@Success		200			{object}	handler.GenericDataResponse[relational.SSPExportOffering]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/export-offerings/{offeringId}/status [patch]
func (h *SSPExportOfferingHandler) UpdateOfferingStatus(ctx echo.Context) error {
	offering, ok := h.resolveOfferingForSSP(ctx)
	if !ok {
		return nil
	}

	var req updateOfferingStatusRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := req.validate(); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if offering.Status != relational.SSPExportOfferingStatusPublished {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("cannot transition an offering with status %q", offering.Status)))
	}

	newStatus := relational.SSPExportOfferingStatus(req.Status)
	var driftedLinks []driftedLinkInfo
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&relational.SSPExportOffering{}).
			Where("id = ?", offering.ID).
			Update("status", newStatus).Error; err != nil {
			return err
		}

		updated := *offering
		updated.Status = newStatus
		links, err := evaluateLeverageDriftForOffering(tx, updated)
		if err != nil {
			return err
		}
		driftedLinks = links
		return nil
	}); err != nil {
		h.sugar.Errorf("Failed to update export offering status: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	enqueueLeverageDriftNotificationsAsync(ctx, h.sugar, h.jobEnqueuer, driftedLinks)

	var updated relational.SSPExportOffering
	if err := h.db.Preload("Items").First(&updated, "id = ?", offering.ID).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPExportOffering]{Data: updated})
}

const (
	defaultExportOfferingCatalogLimit = 100
	maxExportOfferingCatalogLimit     = 1000
)

// catalogOfferingItem is an SSPExportOfferingItem as seen through the flat, cross-SSP
// catalog: it adds the upstream's responsibility UUIDs + descriptions for the item's
// ProvidedUUID (BCH-1338), resolved server-side via resolveUpstreamResponsibilities, so
// a downstream subscriber has real responsibility UUIDs to select without needing
// ssp:read on the upstream SSP — this is an internal DB read behind the existing
// ssp-export-offering:read guard, not a read of the upstream SSP resource. The
// SSP-nested curation routes (ListForSSP/GetOffering) don't need this: the offering's
// own curator already has full access to the upstream SSP's data.
type catalogOfferingItem struct {
	relational.SSPExportOfferingItem
	Responsibilities []upstreamResponsibility `json:"responsibilities"`
}

type catalogOffering struct {
	relational.SSPExportOffering
	Items []catalogOfferingItem `json:"items,omitempty"`
}

// withResolvedResponsibilities wraps offerings for the flat catalog response, resolving
// every item's upstream responsibility set in one batched lookup (two queries total)
// rather than per-item, since ListAll can return up to maxExportOfferingCatalogLimit
// offerings each with their own items.
func (h *SSPExportOfferingHandler) withResolvedResponsibilities(offerings []relational.SSPExportOffering) ([]catalogOffering, error) {
	var allItems []relational.SSPExportOfferingItem
	for _, offering := range offerings {
		allItems = append(allItems, offering.Items...)
	}
	providedUUIDs := uniqueUUIDs(allItems, func(item relational.SSPExportOfferingItem) uuid.UUID { return item.ProvidedUUID })

	responsibilitiesByProvided, err := bulkResolveUpstreamResponsibilities(h.db, providedUUIDs)
	if err != nil {
		return nil, err
	}

	result := make([]catalogOffering, 0, len(offerings))
	for _, offering := range offerings {
		items := make([]catalogOfferingItem, 0, len(offering.Items))
		for _, item := range offering.Items {
			items = append(items, catalogOfferingItem{
				SSPExportOfferingItem: item,
				Responsibilities:      responsibilitiesByProvided[item.ProvidedUUID],
			})
		}
		result = append(result, catalogOffering{SSPExportOffering: offering, Items: items})
	}
	return result, nil
}

// ListAll godoc
//
//	@Summary		List export offerings
//	@Description	Retrieves published export offerings across all system security plans. Draft/deprecated/revoked offerings are only visible via the SSP-nested curation routes.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			limit	query		int	false	"Max number of offerings to return (default 100, max 1000)"
//	@Param			offset	query		int	false	"Number of offerings to skip"
//	@Success		200		{object}	handler.GenericDataListResponse[catalogOffering]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/ssp-export-offerings [get]
func (h *SSPExportOfferingHandler) ListAll(ctx echo.Context) error {
	limit := defaultExportOfferingCatalogLimit
	if raw := strings.TrimSpace(ctx.QueryParam("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid limit parameter")))
		}
		if parsed > maxExportOfferingCatalogLimit {
			parsed = maxExportOfferingCatalogLimit
		}
		limit = parsed
	}

	offset := 0
	if raw := strings.TrimSpace(ctx.QueryParam("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid offset parameter")))
		}
		offset = parsed
	}

	var offerings []relational.SSPExportOffering
	if err := h.db.Preload("Items").
		Where("status = ?", relational.SSPExportOfferingStatusPublished).
		Order("published_at DESC, id ASC").
		Limit(limit).Offset(offset).
		Find(&offerings).Error; err != nil {
		h.sugar.Errorf("Failed to list export offerings: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	withResponsibilities, err := h.withResolvedResponsibilities(offerings)
	if err != nil {
		h.sugar.Errorf("Failed to resolve offering responsibilities: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[catalogOffering]{Data: withResponsibilities})
}

// GetByID godoc
//
//	@Summary		Get an export offering
//	@Description	Retrieves a single published export offering by its own ID (no parent SSP scoping). Draft/deprecated/revoked offerings are only visible via the SSP-nested curation routes.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id	path		string	true	"Offering ID"
//	@Success		200	{object}	handler.GenericDataResponse[catalogOffering]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/ssp-export-offerings/{id} [get]
func (h *SSPExportOfferingHandler) GetByID(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid offering id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var offering relational.SSPExportOffering
	if err := h.db.Preload("Items").
		Where("status = ?", relational.SSPExportOfferingStatusPublished).
		First(&offering, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering not found")))
		}
		h.sugar.Errorf("Failed to load export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	withResponsibilities, err := h.withResolvedResponsibilities([]relational.SSPExportOffering{offering})
	if err != nil {
		h.sugar.Errorf("Failed to resolve offering responsibilities: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[catalogOffering]{Data: withResponsibilities[0]})
}

// controlExportProvided is the provided capability behind one ControlExportOffer, resolved
// by value so the Controls UI never has to walk into the upstream's Export subtree.
type controlExportProvided struct {
	UUID        uuid.UUID `json:"uuid"`
	Description string    `json:"description"`
}

// controlExportResponsibility is one responsibility the upstream makes the downstream
// answerable for under the offered provided capability.
type controlExportResponsibility struct {
	UUID         uuid.UUID `json:"uuid"`
	Description  string    `json:"description"`
	ProvidedUUID uuid.UUID `json:"providedUuid"`
}

// ControlExportOffer answers "for control X, what is exported, by whom, against which
// statement?" — one published offering item, with every pointer it carries already resolved
// (offering, upstream SSP, component, provided, responsibilities). This is what the Controls
// page reads and what "import an implementation" picks from, so a consumer needs no further
// round-trips and — critically — no ssp:read on the upstream SSP.
type ControlExportOffer struct {
	OfferingID      uuid.UUID                          `json:"offeringId"`
	OfferingTitle   string                             `json:"offeringTitle"`
	OfferingVersion int                                `json:"offeringVersion"`
	OfferingStatus  relational.SSPExportOfferingStatus `json:"offeringStatus"`

	UpstreamSSPID    uuid.UUID `json:"upstreamSspId"`
	UpstreamSSPTitle string    `json:"upstreamSspTitle"`

	ItemID uuid.UUID `json:"itemId"`

	ControlID   string  `json:"controlId"`
	StatementID *string `json:"statementId,omitempty"`

	ComponentUUID  uuid.UUID `json:"componentUuid"`
	ComponentTitle string    `json:"componentTitle"`

	Provided         *controlExportProvided        `json:"provided"`
	Responsibilities []controlExportResponsibility `json:"responsibilities"`
}

// ByControl godoc
//
//	@Summary		List every published export offering for one control
//	@Description	Cross-SSP catalog of what is exported for a control, by whom, and against
//	@Description	which statement — every published offering item whose control-id matches
//	@Description	(case-insensitively), with the offering, upstream SSP, component, provided
//	@Description	capability and responsibility set all resolved server-side. Honours the same
//	@Description	trust boundary as the flat catalog: gated by ssp-export-offering:read only,
//	@Description	never ssp:read on the upstream SSP. Pass downstreamSspId to narrow the result
//	@Description	to offerings that SSP is actually allow-listed to subscribe to (BCH-1342).
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			controlId		path		string	true	"Control ID (e.g. AC-2)"
//	@Param			downstreamSspId	query		string	false	"Only return offerings this downstream SSP may subscribe to"
//	@Success		200				{object}	handler.GenericDataListResponse[ControlExportOffer]
//	@Failure		400				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/ssp-export-offerings/by-control/{controlId} [get]
func (h *SSPExportOfferingHandler) ByControl(ctx echo.Context) error {
	controlID := strings.TrimSpace(ctx.Param("controlId"))
	if controlID == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("controlId is required")))
	}

	var downstreamSSPID *uuid.UUID
	if raw := strings.TrimSpace(ctx.QueryParam("downstreamSspId")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("downstreamSspId must be a valid UUID")))
		}
		downstreamSSPID = &parsed
	}

	// Control ids are stored in their catalog-canonical casing but referenced in mixed
	// casing across the codebase (fixtures use "ac-2", catalogs "AC-2"), so match the way
	// every other control lookup here does: fold case rather than compare bytes.
	var items []relational.SSPExportOfferingItem
	if err := h.db.
		Joins("JOIN ssp_export_offerings ON ssp_export_offerings.id = ssp_export_offering_items.offering_id").
		Where("ssp_export_offerings.status = ? AND UPPER(ssp_export_offering_items.control_id) = UPPER(?)",
			relational.SSPExportOfferingStatusPublished, controlID).
		Order("ssp_export_offering_items.id ASC").
		Find(&items).Error; err != nil {
		h.sugar.Errorf("Failed to list export offering items by control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if len(items) == 0 {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[ControlExportOffer]{Data: []ControlExportOffer{}})
	}

	offeringIDs := uniqueUUIDs(items, func(i relational.SSPExportOfferingItem) uuid.UUID { return i.OfferingID })
	var offerings []relational.SSPExportOffering
	if err := h.db.Where("id IN ?", offeringIDs).Find(&offerings).Error; err != nil {
		h.sugar.Errorf("Failed to load offerings by control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	offeringByID := make(map[uuid.UUID]relational.SSPExportOffering, len(offerings))
	for _, o := range offerings {
		offeringByID[*o.ID] = o
	}

	// Drop items whose offering the downstream isn't allow-listed for, before spending any
	// further resolution on them.
	if downstreamSSPID != nil {
		allowedOfferings, err := bulkAllowedOfferings(h.db, offeringIDs, *downstreamSSPID)
		if err != nil {
			h.sugar.Errorf("Failed to check offering allow-list: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		filtered := make([]relational.SSPExportOfferingItem, 0, len(items))
		for _, item := range items {
			if allowedOfferings[item.OfferingID] {
				filtered = append(filtered, item)
			}
		}
		items = filtered
		if len(items) == 0 {
			return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[ControlExportOffer]{Data: []ControlExportOffer{}})
		}
	}

	sspIDs := uniqueUUIDs(offerings, func(o relational.SSPExportOffering) uuid.UUID { return o.SSPID })
	var ssps []relational.SystemSecurityPlan
	if err := h.db.Preload("Metadata").Where("id IN ?", sspIDs).Find(&ssps).Error; err != nil {
		h.sugar.Errorf("Failed to load upstream SSPs by control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	sspTitleByID := make(map[uuid.UUID]string, len(ssps))
	for _, s := range ssps {
		sspTitleByID[*s.ID] = s.Metadata.Title
	}

	componentUUIDs := uniqueUUIDs(items, func(i relational.SSPExportOfferingItem) uuid.UUID { return i.ComponentUUID })
	var components []relational.SystemComponent
	if err := h.db.Where("id IN ?", componentUUIDs).Find(&components).Error; err != nil {
		h.sugar.Errorf("Failed to load components by control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	componentTitleByID := make(map[uuid.UUID]string, len(components))
	for _, c := range components {
		componentTitleByID[*c.ID] = c.Title
	}

	providedUUIDs := uniqueUUIDs(items, func(i relational.SSPExportOfferingItem) uuid.UUID { return i.ProvidedUUID })
	var providedRows []relational.ProvidedControlImplementation
	if err := h.db.Where("id IN ?", providedUUIDs).Find(&providedRows).Error; err != nil {
		h.sugar.Errorf("Failed to load provided implementations by control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	providedByID := make(map[uuid.UUID]relational.ProvidedControlImplementation, len(providedRows))
	for _, p := range providedRows {
		providedByID[*p.ID] = p
	}

	// Same batched (export_id, provided_uuid)-scoped resolution the flat catalog uses — the
	// only correct way to map a provided-uuid to its responsibilities, since provided-uuid
	// values are only unique within one upstream's Export.
	responsibilitiesByProvided, err := bulkResolveUpstreamResponsibilities(h.db, providedUUIDs)
	if err != nil {
		h.sugar.Errorf("Failed to resolve responsibilities by control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	result := make([]ControlExportOffer, 0, len(items))
	for _, item := range items {
		offering := offeringByID[item.OfferingID]

		var provided *controlExportProvided
		if p, ok := providedByID[item.ProvidedUUID]; ok {
			provided = &controlExportProvided{UUID: *p.ID, Description: p.Description}
		}

		responsibilities := make([]controlExportResponsibility, 0, len(responsibilitiesByProvided[item.ProvidedUUID]))
		for _, r := range responsibilitiesByProvided[item.ProvidedUUID] {
			responsibilities = append(responsibilities, controlExportResponsibility{
				UUID:         r.ResponsibilityUUID,
				Description:  r.Description,
				ProvidedUUID: item.ProvidedUUID,
			})
		}

		result = append(result, ControlExportOffer{
			OfferingID:       item.OfferingID,
			OfferingTitle:    offering.Title,
			OfferingVersion:  offering.Version,
			OfferingStatus:   offering.Status,
			UpstreamSSPID:    offering.SSPID,
			UpstreamSSPTitle: sspTitleByID[offering.SSPID],
			ItemID:           *item.ID,
			ControlID:        item.ControlID,
			StatementID:      item.StatementID,
			ComponentUUID:    item.ComponentUUID,
			ComponentTitle:   componentTitleByID[item.ComponentUUID],
			Provided:         provided,
			Responsibilities: responsibilities,
		})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[ControlExportOffer]{Data: result})
}
