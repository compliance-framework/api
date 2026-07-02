package handler

import (
	"errors"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ControlLinkHandler exposes CRUD over the control_links edge table: the typed
// links (implements/documents) that the lineage API walks.
type ControlLinkHandler struct {
	sugar      *zap.SugaredLogger
	db         *gorm.DB
	pagination *svc.PaginationConfig
}

func NewControlLinkHandler(l *zap.SugaredLogger, db *gorm.DB) *ControlLinkHandler {
	return &ControlLinkHandler{
		sugar:      l,
		db:         db,
		pagination: svc.NewPaginationConfig(),
	}
}

func (h *ControlLinkHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("", h.List, guard.Read())
	api.POST("", h.Create, guard.Create())
	api.POST("/bulk", h.BulkCreate, guard.Create())
	api.DELETE("", h.Delete, guard.Delete())
}

type controlRefRequest struct {
	CatalogID uuid.UUID `json:"catalogId"`
	ControlID string    `json:"controlId"`
}

func (r controlRefRequest) ref() relational.ControlRef {
	return relational.ControlRef{CatalogID: r.CatalogID, ControlID: r.ControlID}
}

type createControlLinkRequest struct {
	Source           controlRefRequest `json:"source"`
	Target           controlRefRequest `json:"target"`
	RelationshipType string            `json:"relationshipType"`
}

type bulkControlLinkRequest struct {
	Links []createControlLinkRequest `json:"links"`
}

type bulkControlLinkResponse struct {
	Created int `json:"created"`
	Skipped int `json:"skipped"`
}

// List godoc
//
//	@Summary		List control links
//	@Description	Lists typed control-to-control links, filterable by either endpoint, paginated.
//	@Tags			ControlLink
//	@Produce		json
//	@Param			sourceCatalogId	query	string	false	"Filter by source catalog id"
//	@Param			sourceControlId	query	string	false	"Filter by source control id"
//	@Param			targetCatalogId	query	string	false	"Filter by target catalog id"
//	@Param			targetControlId	query	string	false	"Filter by target control id"
//	@Param			page			query	int		false	"Page number"
//	@Param			limit			query	int		false	"Page size"
//	@Success		200	{object}	service.ListResponse[relational.ControlLink]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/control-links [get]
func (h *ControlLinkHandler) List(ctx echo.Context) error {
	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	query := h.db.Model(&relational.ControlLink{})
	if v := ctx.QueryParam("sourceCatalogId"); v != "" {
		id, parseErr := uuid.Parse(v)
		if parseErr != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}
		query = query.Where("source_catalog_id = ?", id)
	}
	if v := ctx.QueryParam("sourceControlId"); v != "" {
		query = query.Where("source_control_id = ?", v)
	}
	if v := ctx.QueryParam("targetCatalogId"); v != "" {
		id, parseErr := uuid.Parse(v)
		if parseErr != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}
		query = query.Where("target_catalog_id = ?", id)
	}
	if v := ctx.QueryParam("targetControlId"); v != "" {
		query = query.Where("target_control_id = ?", v)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.sugar.Errorw("failed to count control links", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	links := []relational.ControlLink{}
	if err := query.
		Order("source_catalog_id, source_control_id, target_catalog_id, target_control_id, relationship_type").
		Limit(pagination.Limit).
		Offset(pagination.Offset).
		Find(&links).Error; err != nil {
		h.sugar.Errorw("failed to list control links", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, svc.NewListResponse(links, total, pagination.Page, pagination.Limit))
}

// Create godoc
//
//	@Summary		Create a control link
//	@Description	Creates one typed control-to-control link after validating endpoint existence, the relationship vocabulary matrix, and acyclicity.
//	@Tags			ControlLink
//	@Accept			json
//	@Produce		json
//	@Param			link	body		createControlLinkRequest	true	"Control link"
//	@Success		201		{object}	handler.GenericDataResponse[relational.ControlLink]
//	@Failure		409		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/control-links [post]
func (h *ControlLinkHandler) Create(ctx echo.Context) error {
	var req createControlLinkRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Vocabulary + existence validation (422 on any violation).
	if err := h.validateLink(req); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	source := req.Source.ref()
	target := req.Target.ref()

	// Acyclicity: reject if target already reaches source (409).
	edges, err := h.loadEdges()
	if err != nil {
		h.sugar.Errorw("failed to load control links for cycle check", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if relational.NewControlLinkGraph(edges).WouldCreateCycle(source, target) {
		return ctx.JSON(http.StatusConflict, api.NewError(errors.New("link would introduce a cycle in the control graph")))
	}

	// Duplicate composite key => 409.
	var existing int64
	if err := h.db.Model(&relational.ControlLink{}).
		Where("source_catalog_id = ? AND source_control_id = ? AND target_catalog_id = ? AND target_control_id = ? AND relationship_type = ?",
			source.CatalogID, source.ControlID, target.CatalogID, target.ControlID, req.RelationshipType).
		Count(&existing).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if existing > 0 {
		return ctx.JSON(http.StatusConflict, api.NewError(errors.New("control link already exists")))
	}

	link := relational.ControlLink{
		SourceCatalogID:  source.CatalogID,
		SourceControlID:  source.ControlID,
		TargetCatalogID:  target.CatalogID,
		TargetControlID:  target.ControlID,
		RelationshipType: req.RelationshipType,
		CreatedByID:      actorUserID(ctx),
	}
	if err := h.db.Create(&link).Error; err != nil {
		h.sugar.Errorw("failed to create control link", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[relational.ControlLink]{Data: link})
}

// BulkCreate godoc
//
//	@Summary		Bulk create control links
//	@Description	Idempotently upserts many control links (ON CONFLICT DO NOTHING). Invalid vocabulary/existence rejects the batch; cycles and duplicates are skipped.
//	@Tags			ControlLink
//	@Accept			json
//	@Produce		json
//	@Param			links	body		bulkControlLinkRequest	true	"Control links"
//	@Success		200		{object}	handler.GenericDataResponse[bulkControlLinkResponse]
//	@Failure		422		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/control-links/bulk [post]
func (h *ControlLinkHandler) BulkCreate(ctx echo.Context) error {
	var req bulkControlLinkRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if len(req.Links) == 0 {
		return ctx.JSON(http.StatusOK, GenericDataResponse[bulkControlLinkResponse]{Data: bulkControlLinkResponse{}})
	}

	// Validate every link up front; a bad vocabulary/existence fails the whole batch.
	for _, l := range req.Links {
		if err := h.validateLink(l); err != nil {
			return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
		}
	}

	edges, err := h.loadEdges()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	actor := actorUserID(ctx)
	skipped := 0
	accepted := make([]relational.ControlLink, 0, len(req.Links))
	working := append([]relational.ControlLink(nil), edges...)
	for _, l := range req.Links {
		source := l.Source.ref()
		target := l.Target.ref()
		// Cycle check against existing edges plus everything accepted so far.
		if relational.NewControlLinkGraph(working).WouldCreateCycle(source, target) {
			skipped++
			continue
		}
		link := relational.ControlLink{
			SourceCatalogID:  source.CatalogID,
			SourceControlID:  source.ControlID,
			TargetCatalogID:  target.CatalogID,
			TargetControlID:  target.ControlID,
			RelationshipType: l.RelationshipType,
			CreatedByID:      actor,
		}
		accepted = append(accepted, link)
		working = append(working, link)
	}

	created := 0
	if len(accepted) > 0 {
		res := h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&accepted)
		if res.Error != nil {
			h.sugar.Errorw("failed to bulk create control links", "error", res.Error)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(res.Error))
		}
		created = int(res.RowsAffected)
	}
	// Anything accepted but not newly inserted was an existing duplicate.
	skipped += len(accepted) - created

	return ctx.JSON(http.StatusOK, GenericDataResponse[bulkControlLinkResponse]{
		Data: bulkControlLinkResponse{Created: created, Skipped: skipped},
	})
}

// Delete godoc
//
//	@Summary		Delete a control link
//	@Description	Deletes the control link identified by its full composite key (all query params required).
//	@Tags			ControlLink
//	@Param			sourceCatalogId	query	string	true	"Source catalog id"
//	@Param			sourceControlId	query	string	true	"Source control id"
//	@Param			targetCatalogId	query	string	true	"Target catalog id"
//	@Param			targetControlId	query	string	true	"Target control id"
//	@Param			relationshipType	query	string	true	"Relationship type"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/control-links [delete]
func (h *ControlLinkHandler) Delete(ctx echo.Context) error {
	sourceCatalogID, err := uuid.Parse(ctx.QueryParam("sourceCatalogId"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("valid sourceCatalogId is required")))
	}
	targetCatalogID, err := uuid.Parse(ctx.QueryParam("targetCatalogId"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("valid targetCatalogId is required")))
	}
	sourceControlID := ctx.QueryParam("sourceControlId")
	targetControlID := ctx.QueryParam("targetControlId")
	relationshipType := ctx.QueryParam("relationshipType")
	if sourceControlID == "" || targetControlID == "" || relationshipType == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("sourceControlId, targetControlId and relationshipType are required")))
	}

	res := h.db.
		Where("source_catalog_id = ? AND source_control_id = ? AND target_catalog_id = ? AND target_control_id = ? AND relationship_type = ?",
			sourceCatalogID, sourceControlID, targetCatalogID, targetControlID, relationshipType).
		Delete(&relational.ControlLink{})
	if res.Error != nil {
		h.sugar.Errorw("failed to delete control link", "error", res.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(res.Error))
	}
	if res.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("control link not found")))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// validateLink checks endpoint existence and the vocabulary matrix. A returned
// error is a validation failure the caller maps to 422.
func (h *ControlLinkHandler) validateLink(req createControlLinkRequest) error {
	sourceType, err := h.resolveControlType(req.Source.ref())
	if err != nil {
		return err
	}
	targetType, err := h.resolveControlType(req.Target.ref())
	if err != nil {
		return err
	}
	return relational.ValidateRelationship(req.RelationshipType, sourceType, targetType)
}

// resolveControlType verifies the control exists and returns its catalog's type.
func (h *ControlLinkHandler) resolveControlType(ref relational.ControlRef) (string, error) {
	var cat relational.Catalog
	if err := h.db.Select("id", "catalog_type").First(&cat, "id = ?", ref.CatalogID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errors.New("catalog " + ref.CatalogID.String() + " does not exist")
		}
		return "", err
	}
	var count int64
	if err := h.db.Model(&relational.Control{}).
		Where("catalog_id = ? AND id = ?", ref.CatalogID, ref.ControlID).
		Count(&count).Error; err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("control " + ref.ControlID + " does not exist in catalog " + ref.CatalogID.String())
	}
	catalogType := cat.CatalogType
	if catalogType == "" {
		catalogType = relational.CatalogTypeStandard
	}
	return catalogType, nil
}

func (h *ControlLinkHandler) loadEdges() ([]relational.ControlLink, error) {
	edges := []relational.ControlLink{}
	if err := h.db.Find(&edges).Error; err != nil {
		return nil, err
	}
	return edges, nil
}

// actorUserID extracts the authenticated user's primary-key UUID from the JWT
// claims for CreatedByID attribution; nil when unavailable.
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
