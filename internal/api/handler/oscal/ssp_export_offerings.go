package oscal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

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
	ControlID     string `json:"control_id"`
	StatementID   string `json:"statement_id"`
	ComponentUUID string `json:"component_uuid"`
	ProvidedUUID  string `json:"provided_uuid"`
}

// computeOfferingContentHash returns a deterministic sha256 hex digest over an
// offering's curatorial content — title, description, and its items — so that two
// offerings (or the same offering re-read in a different item order) with identical
// content always hash identically, and any real content change always changes it.
func computeOfferingContentHash(title, description string, items []relational.SSPExportOfferingItem) string {
	canon := make([]canonicalOfferingItem, 0, len(items))
	for _, item := range items {
		statementID := ""
		if item.StatementID != nil {
			statementID = *item.StatementID
		}
		canon = append(canon, canonicalOfferingItem{
			ControlID:     item.ControlID,
			StatementID:   statementID,
			ComponentUUID: item.ComponentUUID.String(),
			ProvidedUUID:  item.ProvidedUUID.String(),
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
func SyncExportOffering(db *gorm.DB, offeringID uuid.UUID) error {
	var offering relational.SSPExportOffering
	if err := db.Preload("Items").First(&offering, "id = ?", offeringID).Error; err != nil {
		return err
	}
	originalUpdatedAt := offering.UpdatedAt

	newHash := computeOfferingContentHash(offering.Title, offering.Description, offering.Items)

	return db.Transaction(func(tx *gorm.DB) error {
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
		return tx.Save(&current).Error
	})
}

// SSPExportOfferingHandler serves both the SSP-nested curation surface (create/edit/
// delete/publish, gated by ssp:export) and the top-level read-only ssp-export-offering
// catalog (gated by ssp-export-offering:read).
type SSPExportOfferingHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewSSPExportOfferingHandler(l *zap.SugaredLogger, db *gorm.DB) *SSPExportOfferingHandler {
	return &SSPExportOfferingHandler{sugar: l, db: db}
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
}

// Register mounts the top-level, cross-SSP read-only catalog: list and get any
// offering by its own ID, gated by ssp-export-offering:read.
func (h *SSPExportOfferingHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("", h.ListAll, guard.Read())
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
	ControlID     string  `json:"controlId"`
	StatementID   *string `json:"statementId,omitempty"`
	ComponentUUID string  `json:"componentUuid"`
	ProvidedUUID  string  `json:"providedUuid"`
}

func (r createExportOfferingItemRequest) validate() error {
	if r.ControlID == "" {
		return fmt.Errorf("controlId is required")
	}
	if _, err := uuid.Parse(r.ComponentUUID); err != nil {
		return fmt.Errorf("componentUuid must be a valid UUID")
	}
	if _, err := uuid.Parse(r.ProvidedUUID); err != nil {
		return fmt.Errorf("providedUuid must be a valid UUID")
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

	item := relational.SSPExportOfferingItem{
		OfferingID:    *offering.ID,
		ControlID:     req.ControlID,
		StatementID:   req.StatementID,
		ComponentUUID: uuid.MustParse(req.ComponentUUID),
		ProvidedUUID:  uuid.MustParse(req.ProvidedUUID),
	}
	if err := h.db.Create(&item).Error; err != nil {
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

	result := h.db.Model(&relational.SSPExportOfferingItem{}).
		Where("id = ? AND offering_id = ?", itemID, offering.ID).
		Updates(map[string]any{
			"control_id":     req.ControlID,
			"statement_id":   req.StatementID,
			"component_uuid": uuid.MustParse(req.ComponentUUID),
			"provided_uuid":  uuid.MustParse(req.ProvidedUUID),
		})
	if result.Error != nil {
		h.sugar.Errorf("Failed to update export offering item: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
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

	result := h.db.Where("id = ? AND offering_id = ?", itemID, offering.ID).Delete(&relational.SSPExportOfferingItem{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete export offering item: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering item not found")))
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

	if err := SyncExportOffering(h.db, *offering.ID); err != nil {
		h.sugar.Errorf("Failed to sync export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	now := time.Now()
	if err := h.db.Model(&relational.SSPExportOffering{}).
		Where("id = ?", offering.ID).
		Updates(map[string]any{"status": relational.SSPExportOfferingStatusPublished, "published_at": &now}).Error; err != nil {
		h.sugar.Errorf("Failed to mark export offering published: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var published relational.SSPExportOffering
	if err := h.db.Preload("Items").First(&published, "id = ?", offering.ID).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPExportOffering]{Data: published})
}

// ListAll godoc
//
//	@Summary		List export offerings
//	@Description	Retrieves every export offering across all system security plans.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[relational.SSPExportOffering]
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/ssp-export-offerings [get]
func (h *SSPExportOfferingHandler) ListAll(ctx echo.Context) error {
	var offerings []relational.SSPExportOffering
	if err := h.db.Preload("Items").Find(&offerings).Error; err != nil {
		h.sugar.Errorf("Failed to list export offerings: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[relational.SSPExportOffering]{Data: offerings})
}

// GetByID godoc
//
//	@Summary		Get an export offering
//	@Description	Retrieves a single export offering by its own ID (no parent SSP scoping).
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id	path		string	true	"Offering ID"
//	@Success		200	{object}	handler.GenericDataResponse[relational.SSPExportOffering]
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
	if err := h.db.Preload("Items").First(&offering, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering not found")))
		}
		h.sugar.Errorf("Failed to load export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPExportOffering]{Data: offering})
}
