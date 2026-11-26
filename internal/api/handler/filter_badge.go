package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/badge"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
)

const (
	maxBadgeSlugLen = 63

	badgeContentType         = "image/svg+xml; charset=utf-8"
	badgeContentSecurity     = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
	badgePreviewCacheControl = "private, no-store"
	badgePublicCacheControl  = "public, no-cache, max-age=0, must-revalidate"
	badgeErrorCacheControl   = "no-store"
	badgeFileSuffix          = ".svg"
)

var (
	badgeSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

	errPublishForbidden  = errors.New("changing a filter's badge, or the selection of a published filter, requires the filter:publish permission")
	errBadgeSlugTaken    = errors.New("badge slug is already in use by another filter")
	errBadgeNeedsSlug    = errors.New("badge.enabled requires badge.slug")
	errBadgeQueryParams  = errors.New("badge URLs take no query parameters")
	errBadgeLabelLength  = fmt.Errorf("badge.label must be 1-%d characters after trimming", badge.MaxLabelRunes)
	errBadgeLabelControl = errors.New("badge.label must not contain control characters")
	errBadgeSlugFormat   = fmt.Errorf("badge.slug must be 1-%d lowercase letters, digits and single hyphens, not starting or ending with a hyphen", maxBadgeSlugLen)
)

// filterHTTPError carries a status and client-safe error out of a filter write
// transaction.
type filterHTTPError struct {
	status int
	err    error
}

func (e *filterHTTPError) Error() string { return e.err.Error() }
func (e *filterHTTPError) Unwrap() error { return e.err }

func badRequest(err error) error { return &filterHTTPError{status: http.StatusBadRequest, err: err} }

func normalizeBadgeLabel(label string) (string, error) {
	label = strings.TrimSpace(label)
	if n := utf8.RuneCountInString(label); n == 0 || n > badge.MaxLabelRunes {
		return "", errBadgeLabelLength
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return "", errBadgeLabelControl
		}
	}
	return label, nil
}

func validBadgeSlug(slug string) bool {
	return len(slug) <= maxBadgeSlugLen && badgeSlugPattern.MatchString(slug)
}

// resolveFilterBadge applies a request's badge settings to the current ones. set reports
// whether the body had a badge key at all; a nil req with set means badge: null.
func resolveFilterBadge(current relational.FilterBadge, req *filterBadgeRequest, set bool) (relational.FilterBadge, error) {
	if !set {
		return current, nil
	}
	if req == nil {
		return relational.DefaultFilterBadge(), nil
	}
	next := current
	if current.Slug != nil {
		slug := *current.Slug
		next.Slug = &slug
	}
	if req.Label != nil {
		label, err := normalizeBadgeLabel(*req.Label)
		if err != nil {
			return current, err
		}
		next.Label = label
	}
	if req.slugSet {
		if req.Slug == nil {
			// Clearing the slug unpublishes; only an explicit enabled: true below can
			// contradict that, and is rejected.
			next.Slug = nil
			next.Enabled = false
		} else {
			if !validBadgeSlug(*req.Slug) {
				return current, errBadgeSlugFormat
			}
			slug := *req.Slug
			next.Slug = &slug
		}
	}
	if req.Enabled != nil {
		next.Enabled = *req.Enabled
	}
	if next.Enabled && next.Slug == nil {
		return current, errBadgeNeedsSlug
	}
	return next, nil
}

func badgeEqual(a, b relational.FilterBadge) bool {
	if a.Enabled != b.Enabled || a.Label != b.Label || (a.Slug == nil) != (b.Slug == nil) {
		return false
	}
	return a.Slug == nil || *a.Slug == *b.Slug
}

// filterSelection is what decides a filter's badge state: its effective predicate, SSP
// binding and scope-following base.
type filterSelection struct {
	sspID, filter, scopeBase string
}

func selectionOf(f *relational.Filter) (filterSelection, error) {
	var sel filterSelection
	if f.SSPID != nil {
		sel.sspID = f.SSPID.String()
	}
	predicate, err := json.Marshal(f.Filter.Data())
	if err != nil {
		return sel, err
	}
	sel.filter = string(predicate)
	if f.ScopeBase != nil {
		base, err := json.Marshal(f.ScopeBase.Data())
		if err != nil {
			return sel, err
		}
		sel.scopeBase = string(base)
	}
	return sel, nil
}

// authorizePublish checks filter:publish for the caller. It fails closed whatever the
// PEP's fail mode: an unavailable PDP denies; any other evaluation error is a 500.
func (h *FilterHandler) authorizePublish(ctx *echo.Context, filterID string) error {
	if h.pdp == nil {
		return errPublishForbidden
	}
	subject := middleware.SubjectFromContext(ctx)
	resource := authz.Resource{Type: authz.ResourceFilter, ID: filterID}
	reqCtx := map[string]any{"method": ctx.Request().Method, "path": ctx.Path()}
	decision, err := h.pdp.Evaluate(ctx.Request().Context(), subject, authz.ActionPublish, resource, reqCtx)
	if err != nil {
		if errors.Is(err, authz.ErrUnavailable) {
			h.sugar.Warnw("authz PDP unavailable; denying filter:publish", "filterID", filterID, "error", err)
			return errPublishForbidden
		}
		return fmt.Errorf("filter:publish check: %w", err)
	}
	h.sugar.Infow("authz decision",
		"audit", true,
		"decision", map[bool]string{true: "allow", false: "deny"}[decision.Allow],
		"subjectType", subject.Type,
		"subjectID", subject.ID,
		"resource", resource.Type,
		"resourceID", resource.ID,
		"action", authz.ActionPublish,
		"reason", decision.Reason,
	)
	if !decision.Allow {
		return errPublishForbidden
	}
	return nil
}

// checkBadgeSlugAvailable reports a conflict when another filter holds slug. The
// partial unique index still decides races; isBadgeSlugConflict maps those.
func checkBadgeSlugAvailable(tx *gorm.DB, id *uuid.UUID, slug *string) error {
	if slug == nil {
		return nil
	}
	q := tx.Model(&relational.Filter{}).Where("badge_slug = ?", *slug)
	if id != nil {
		q = q.Where("id <> ?", *id)
	}
	var count int64
	if err := q.Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return errBadgeSlugTaken
	}
	return nil
}

func isBadgeSlugConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == relational.FilterBadgeSlugIndex
}

// RegisterBadgePreview registers the authenticated badge preview. It discloses evidence-
// derived state, so it needs evidence read as well as filter read, exactly like
// /evidence/compliance-by-filter/:id (whose resource ID is also the filter ID).
func (h *FilterHandler) RegisterBadgePreview(group *echo.Group, filterGuard, evidenceGuard middleware.ResourceGuard) {
	group.GET("/:id/badge.svg", h.BadgePreview, filterGuard.Read(), evidenceGuard.Read())
}

// RegisterPublicBadges registers the anonymous published-badge route on a group that must
// carry no authentication: publication is the access gate. Every other path in the group
// gets the same 404 as an unknown slug.
func (h *FilterHandler) RegisterPublicBadges(group *echo.Group) {
	group.Use(badgeErrorNoStore)
	group.GET("/:file", h.PublicBadge)
	notFound := func(ctx *echo.Context) error {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}
	group.RouteNotFound("", notFound)
	group.RouteNotFound("/*", notFound)
}

// badgeErrorNoStore marks a response uncacheable until a badge handler replaces the
// header on success, so error responses, including those from middleware that runs
// before the handler, are never cached.
func badgeErrorNoStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx *echo.Context) error {
		ctx.Response().Header().Set("Cache-Control", badgeErrorCacheControl)
		return next(ctx)
	}
}

// filterBadgeErrorNoStore is badgeErrorNoStore for the badge routes of a group that also
// serves cacheable JSON.
func filterBadgeErrorNoStore(next echo.HandlerFunc) echo.HandlerFunc {
	noStore := badgeErrorNoStore(next)
	return func(ctx *echo.Context) error {
		if strings.HasSuffix(ctx.Request().URL.Path, "/badge.svg") {
			return noStore(ctx)
		}
		return next(ctx)
	}
}

// BadgePreview godoc
//
//	@Summary		Preview a filter's badge
//	@Description	Renders the SVG badge of a saved filter by ID, whether or not it is published.
//	@Description	Requires filter read and the evidence read authorization of
//	@Description	/evidence/compliance-by-filter/{id}. Takes no query parameters.
//	@Tags			Filters
//	@Produce		image/svg+xml
//	@Produce		json
//	@Param			id	path		string	true	"Filter ID"
//	@Success		200	{string}	string	"SVG badge"
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		403	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/filters/{id}/badge.svg [get]
func (h *FilterHandler) BadgePreview(ctx *echo.Context) error {
	if ctx.Request().URL.RawQuery != "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errBadgeQueryParams))
	}
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var filter relational.Filter
	if err := h.db.First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NotFound())
		}
		h.sugar.Errorw("Failed to load filter for badge preview", "filterID", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return h.renderBadge(ctx, &filter, badgePreviewCacheControl)
}

// PublicBadge godoc
//
//	@Summary		Get a published filter badge
//	@Description	Renders the SVG badge published under a slug. Anonymous: no token is needed.
//	@Description	Only the badge label and aggregate state (passing, failing, unknown or no
//	@Description	evidence) are disclosed. Unknown, invalid and unpublished slugs all return the
//	@Description	same 404. Takes no query parameters.
//	@Tags			Filters
//	@Produce		image/svg+xml
//	@Produce		json
//	@Param			file	path		string	true	"Badge slug followed by .svg, e.g. payments-service.svg"
//	@Success		200		{string}	string	"SVG badge"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/public/badges/{file} [get]
func (h *FilterHandler) PublicBadge(ctx *echo.Context) error {
	if ctx.Request().URL.RawQuery != "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errBadgeQueryParams))
	}
	slug, ok := strings.CutSuffix(ctx.Param("file"), badgeFileSuffix)
	if !ok || !validBadgeSlug(slug) {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	var filter relational.Filter
	if err := h.db.First(&filter, "badge_slug = ? AND badge_enabled", slug).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NotFound())
		}
		h.sugar.Errorw("Failed to look up published badge", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return h.renderBadge(ctx, &filter, badgePublicCacheControl)
}

// renderBadge is the lookup-independent path both badge routes share: one grouped query
// over the latest evidence matching the filter's effective predicate, as
// /evidence/compliance-by-filter/:id runs, then the SVG.
func (h *FilterHandler) renderBadge(ctx *echo.Context, filter *relational.Filter, cacheControl string) error {
	if h.evidenceService == nil {
		h.sugar.Errorw("Badge requested but no evidence service is configured")
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	rows, err := h.evidenceService.GetStatusCountsByFilters(filter.Filter.Data())
	if err != nil {
		h.sugar.Errorw("Failed to aggregate badge evidence", "filterID", filter.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	counts := make([]badge.Count, 0, len(rows))
	for _, row := range rows {
		counts = append(counts, badge.Count{State: row.Status, Count: row.Count})
	}
	svg := badge.Render(filter.Badge.Label, badge.Aggregate(counts))

	header := ctx.Response().Header()
	header.Set("Cache-Control", cacheControl)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", badgeContentSecurity)
	return ctx.Blob(http.StatusOK, badgeContentType, svg)
}
