package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	// agentConfigBodyLimit bounds PUT/preview/revert bodies. agentconfig.MaxOverlayBytes
	// (256 KiB) is measured on the compact overlay, but clients may send it pretty-printed,
	// which can roughly double or triple it, inside an envelope with a comment of up to
	// maxRevisionCommentLen characters (at most ~12 KiB JSON-escaped). Four times the overlay
	// limit (1 MiB) leaves room for that, so an overlay is rejected by ValidateOverlay with a
	// precise 422 rather than by the transport with a 413. agentConfigBodyLimitStr is the
	// same limit for echo's BodyLimit middleware.
	agentConfigBodyLimit    = 4 * agentconfig.MaxOverlayBytes
	agentConfigBodyLimitStr = "1M"
	maxRevisionCommentLen   = 2000
)

// AgentConfigHandler serves the admin routes for agent remote configuration: the current
// overlay, its revisions, preview/validation and the reporting instances.
type AgentConfigHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
	svc   *agentcfg.Service
	// pdp decides whether a reader also holds agent:configure, which gets overlays
	// unredacted. nil means nobody does (fail closed).
	pdp authz.PDP
}

func NewAgentConfigHandler(sugar *zap.SugaredLogger, db *gorm.DB, svc *agentcfg.Service, pdp authz.PDP) *AgentConfigHandler {
	return &AgentConfigHandler{sugar: sugar, db: db, svc: svc, pdp: pdp}
}

// Register mounts the routes on an /admin/agents group of their own (so they inherit no
// group guard). Writes need agent:configure.
func (h *AgentConfigHandler) Register(g *echo.Group, guard middleware.ResourceGuard) {
	write := guard.Do(authz.ActionConfigure)
	g.GET("/:id/config", h.Get, guard.Read())
	g.PUT("/:id/config", h.Put, write, echomiddleware.BodyLimit(agentConfigBodyLimitStr))
	g.GET("/:id/config/revisions/:rev", h.GetRevision, guard.Read())
}

// ---- DTOs (A4.4) ----

type agentConfigRevisionResponse struct {
	AgentID     string          `json:"agent-id"`
	Revision    int64           `json:"revision"`
	Overlay     json.RawMessage `json:"overlay,omitempty" swaggertype:"object"` // omitted in lists
	OverlaySize int             `json:"overlay-size"`
	Comment     *string         `json:"comment"`
	CreatedBy   *string         `json:"created-by"`
	CreatedAt   *time.Time      `json:"created-at"`
	RevertOf    *int64          `json:"revert-of"`
}

// instanceValidationErrors groups the errors of one validated instance in a 422 body.
// Errors are the ones the overlay introduces (they block); Warnings are already present in
// Merge(base, {}), i.e. they come from the host file, and do not block (R59).
type instanceValidationErrors struct {
	InstanceID string                   `json:"instance-id"`
	Hostname   *string                  `json:"hostname"`
	Errors     []agentconfig.FieldError `json:"errors"`
	Warnings   []agentconfig.FieldError `json:"warnings"`
}

// agentConfigPutRequest is the PUT body.
type agentConfigPutRequest struct {
	Overlay json.RawMessage `json:"overlay" swaggertype:"object"`
	Comment *string         `json:"comment"`
}

// ---- Handlers ----

// Get godoc
//
//	@Summary		Get an agent's configuration overlay
//	@Description	Returns the current configuration revision (overlay as an RFC 7396 merge patch, snake_case). Revision 0 means no overlay. The ETag is the plain revision number; send it as If-Match when saving. The overlay is verbatim for callers that also hold agent:configure; for every other caller it is redacted like an instance report (secret-like keys and values become ••••), and it is redacted whenever that check cannot be evaluated. Prefer ${env:NAME} placeholders to literal secrets.
//	@Tags			Agent Configuration
//	@Produce		json
//	@Param			id	path		string	true	"Agent ID"
//	@Success		200	{object}	handler.GenericDataResponse[handler.agentConfigRevisionResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		403	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/agents/{id}/config [get]
func (h *AgentConfigHandler) Get(ctx echo.Context) error {
	agent, errResp := h.resolveAgent(ctx)
	if agent == nil {
		return errResp
	}
	cur, err := h.svc.Current(ctx.Request().Context(), *agent.ID)
	if err != nil {
		return h.internalError(ctx, "load agent configuration", err)
	}
	resp := revisionResponse(*agent.ID, cur, true)
	if err := h.redactForReader(ctx, &resp); err != nil {
		return h.internalError(ctx, "redact overlay", err)
	}
	ctx.Response().Header().Set(headerETag, agentconfig.AdminETag(resp.Revision))
	return ctx.JSON(http.StatusOK, GenericDataResponse[agentConfigRevisionResponse]{Data: resp})
}

// Put godoc
//
//	@Summary		Save an agent's configuration overlay
//	@Description	Creates the next configuration revision. Requires If-Match with the current revision ("0" for the first save): missing is 428, stale is 409 with current-revision. A semantically unchanged overlay returns 200 with the current revision and creates nothing. The overlay is validated on its own, and the merged config is validated against every fresh apply-mode instance's reported base (or the latest reported one); only errors the overlay introduces block (errors already present in the instance's own file are ignored, R59). Errors are a 422 with overlay and instances (errors plus non-blocking warnings) lists. Needs agent:configure.
//	@Tags			Agent Configuration
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"Agent ID"
//	@Param			If-Match	header		string							true	"Current revision, e.g. \"7\""
//	@Param			body		body		handler.agentConfigPutRequest	true	"Overlay and optional comment"
//	@Success		200			{object}	handler.GenericDataResponse[handler.agentConfigRevisionResponse]
//	@Success		201			{object}	handler.GenericDataResponse[handler.agentConfigRevisionResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		403			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		413			{object}	api.Error
//	@Failure		415			{object}	api.Error
//	@Failure		422			{object}	api.Error
//	@Failure		428			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/agents/{id}/config [put]
func (h *AgentConfigHandler) Put(ctx echo.Context) error {
	agent, errResp := h.resolveAgent(ctx)
	if agent == nil {
		return errResp
	}
	expected, ok := agentconfig.ParseRevisionIfMatch(ctx.Request().Header.Get(headerIfMatch))
	if !ok {
		return preconditionRequired(ctx)
	}
	body, bodyErr := readJSONBody(ctx, agentConfigBodyLimit)
	if bodyErr != nil {
		return bodyErr.respond(ctx)
	}
	var req agentConfigPutRequest
	if err := decodeStrict(body, &req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if isNullOrEmpty(req.Overlay) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("overlay is required")))
	}
	comment, err := normalizeComment(req.Comment)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return h.save(ctx, agent, expected, req.Overlay, comment, nil)
}

// save implements PUT/revert steps 3-7 (A4.3).
func (h *AgentConfigHandler) save(ctx echo.Context, agent *relational.Agent, expected int64, overlay json.RawMessage, comment *string, revertOf *int64) error {
	reqCtx := ctx.Request().Context()
	agentID := *agent.ID

	cur, err := h.svc.Current(reqCtx, agentID)
	if err != nil {
		return h.internalError(ctx, "load agent configuration", err)
	}
	curRev, curOverlay := int64(0), json.RawMessage(`{}`)
	if cur != nil {
		curRev, curOverlay = cur.Revision, json.RawMessage(cur.Overlay)
	}
	if expected != curRev {
		return revisionConflict(ctx, curRev)
	}

	// R14: a semantically unchanged overlay creates no revision. Only a valid JSON object
	// can be a no-op; anything else falls through to validation.
	if diff, err := agentconfig.DiffJSON(curOverlay, overlay); err == nil && len(diff) == 0 {
		ctx.Response().Header().Set(headerETag, agentconfig.AdminETag(curRev))
		return ctx.JSON(http.StatusOK, GenericDataResponse[agentConfigRevisionResponse]{Data: revisionResponse(agentID, cur, true)})
	}

	bases, _, err := h.svc.ValidationBases(reqCtx, agentID)
	if err != nil {
		return h.internalError(ctx, "load validation bases", err)
	}

	result := validateCandidate(overlay, bases)
	if result.blocking() {
		return ctx.JSON(http.StatusUnprocessableEntity, result.errorBody())
	}

	compact, err := compactJSON(overlay)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	createdBy, createdByID := revisionAuthor(ctx)
	rev, err := h.svc.CreateRevision(reqCtx, agentcfg.CreateRevisionParams{
		AgentID:          agentID,
		ExpectedRevision: expected,
		Overlay:          compact,
		Comment:          comment,
		CreatedBy:        createdBy,
		CreatedByID:      createdByID,
		RevertOf:         revertOf,
	})
	if err != nil {
		var conflict *agentcfg.RevisionConflictError
		switch {
		case errors.As(err, &conflict):
			return revisionConflict(ctx, conflict.Current)
		case errors.Is(err, agentcfg.ErrNotFound):
			return ctx.JSON(http.StatusNotFound, api.NotFound())
		default:
			return h.internalError(ctx, "create revision", err)
		}
	}
	ctx.Response().Header().Set(headerETag, agentconfig.AdminETag(rev.Revision))
	return ctx.JSON(http.StatusCreated, GenericDataResponse[agentConfigRevisionResponse]{Data: revisionResponse(agentID, rev, true)})
}

// candidateResult is the outcome of the candidate validation pipeline (A4.2).
type candidateResult struct {
	overlay   []agentconfig.FieldError
	instances []instanceValidationErrors
}

// blocking reports whether a save must be refused (422): overlay errors, or errors the
// overlay introduces on a validated instance (R6, R48, R59). File-origin errors never block.
func (r candidateResult) blocking() bool {
	return len(r.overlay) > 0 || len(r.instances) > 0
}

func (r candidateResult) errorBody() api.Error {
	return api.Error{Errors: map[string]any{
		"body":      "configuration overlay is invalid",
		"overlay":   nonNil(r.overlay),
		"instances": nonNil(r.instances),
	}}
}

// validateCandidate runs the pipeline shared by PUT, revert and preview:
//  1. ValidateOverlay (the overlay on its own);
//  2. when (1) passed: Merge(base, overlay).ValidateEditable() for every validation base,
//     grouped by instance. Only errors the overlay introduces are kept (R59, see
//     splitIntroduced); an instance is listed only when it has at least one. With no bases
//     (standalone) only (1) runs.
func validateCandidate(overlay json.RawMessage, bases []agentcfg.InstanceBase) candidateResult {
	var r candidateResult
	if err := agentconfig.ValidateOverlay(overlay); err != nil {
		var verrs agentconfig.ValidationErrors
		if errors.As(err, &verrs) {
			r.overlay = verrs
		} else {
			r.overlay = []agentconfig.FieldError{{Path: "", Code: agentconfig.FieldCodeParse, Message: err.Error()}}
		}
	}
	if len(r.overlay) > 0 {
		return r
	}
	for _, b := range bases {
		if _, introduced, fileOrigin := splitIntroduced(b.Base, overlay); len(introduced) > 0 {
			r.instances = append(r.instances, instanceValidationErrors{
				InstanceID: b.Instance.InstanceID.String(),
				Hostname:   b.Instance.Hostname,
				Errors:     introduced,
				Warnings:   nonNil(fileOrigin),
			})
		}
	}
	return r
}

// splitIntroduced validates Merge(base, overlay) and splits its errors into the ones the
// overlay introduces and the ones already present in Merge(base, {}) (file-origin, R59).
// Errors are matched on (Path, Code, Message), so an overlay that replaces a bad value
// with a different bad value still introduces an error.
func splitIntroduced(base agentconfig.Config, overlay json.RawMessage) (eff *agentconfig.Config, introduced, fileOrigin []agentconfig.FieldError) {
	eff, all := mergeAndValidate(base, overlay)
	if len(all) == 0 {
		return eff, nil, nil
	}
	_, baseline := mergeAndValidate(base, json.RawMessage(`{}`))
	type key struct{ path, code, message string }
	seen := make(map[key]bool, len(baseline))
	for _, e := range baseline {
		seen[key{e.Path, e.Code, e.Message}] = true
	}
	for _, e := range all {
		if seen[key{e.Path, e.Code, e.Message}] {
			fileOrigin = append(fileOrigin, e)
		} else {
			introduced = append(introduced, e)
		}
	}
	return eff, introduced, fileOrigin
}

// mergeAndValidate merges the overlay onto a base and validates the editable part.
func mergeAndValidate(base agentconfig.Config, overlay json.RawMessage) (*agentconfig.Config, []agentconfig.FieldError) {
	eff, err := agentconfig.Merge(base, overlay)
	if err != nil {
		return nil, []agentconfig.FieldError{{Path: "", Code: agentconfig.FieldCodeParse, Message: err.Error()}}
	}
	if err := eff.ValidateEditable(); err != nil {
		var verrs agentconfig.ValidationErrors
		if errors.As(err, &verrs) {
			return &eff, verrs
		}
		return &eff, []agentconfig.FieldError{{Path: "", Code: agentconfig.FieldCodeInvalidValue, Message: err.Error()}}
	}
	return &eff, nil
}

// GetRevision godoc
//
//	@Summary		Get one configuration revision
//	@Description	The overlay is verbatim for callers that also hold agent:configure and redacted (secret-like keys and values become ••••) for every other caller, as on GET config.
//	@Tags			Agent Configuration
//	@Produce		json
//	@Param			id	path		string	true	"Agent ID"
//	@Param			rev	path		integer	true	"Revision number"
//	@Success		200	{object}	handler.GenericDataResponse[handler.agentConfigRevisionResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		403	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/agents/{id}/config/revisions/{rev} [get]
func (h *AgentConfigHandler) GetRevision(ctx echo.Context) error {
	agent, errResp := h.resolveAgent(ctx)
	if agent == nil {
		return errResp
	}
	revNumber, err := parseRevisionParam(ctx.Param("rev"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	rev, err := h.svc.GetRevision(ctx.Request().Context(), *agent.ID, revNumber)
	if errors.Is(err, agentcfg.ErrNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NotFoundCustomMsg("revision not found"))
	}
	if err != nil {
		return h.internalError(ctx, "load revision", err)
	}
	resp := revisionResponse(*agent.ID, rev, true)
	if err := h.redactForReader(ctx, &resp); err != nil {
		return h.internalError(ctx, "redact overlay", err)
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[agentConfigRevisionResponse]{Data: resp})
}

// ---- helpers ----

// resolveAgent loads :id. On failure it returns nil and the already-written error response.
func (h *AgentConfigHandler) resolveAgent(ctx echo.Context) (*relational.Agent, error) {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return nil, ctx.JSON(http.StatusBadRequest, api.InvalidUUID())
	}
	var agent relational.Agent
	if err := h.db.WithContext(ctx.Request().Context()).First(&agent, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ctx.JSON(http.StatusNotFound, api.NotFoundCustomMsg("agent not found"))
		}
		return nil, h.internalError(ctx, "load agent", err)
	}
	return &agent, nil
}

// canConfigure reports whether the caller holds agent:configure on the agent in :id,
// evaluated against the PDP like the route guard does. It fails closed: no PDP, an
// unavailable PDP or an evaluation error all count as no.
func (h *AgentConfigHandler) canConfigure(ctx echo.Context) bool {
	if h.pdp == nil {
		return false
	}
	subject := middleware.SubjectFromContext(ctx)
	resource := authz.Resource{Type: authz.ResourceAgent, ID: ctx.Param("id")}
	reqCtx := map[string]any{"method": ctx.Request().Method, "path": ctx.Path()}
	decision, err := h.pdp.Evaluate(ctx.Request().Context(), subject, authz.ActionConfigure, resource, reqCtx)
	if err != nil {
		h.sugar.Warnw("agent:configure check failed; returning the overlay redacted", "path", ctx.Path(), "error", err)
		return false
	}
	return decision.Allow
}

// redactForReader redacts resp.Overlay (agentconfig.RedactDocument) unless the caller holds
// agent:configure, so plain readers never see literal secrets typed into an overlay.
// OverlaySize stays the stored size.
func (h *AgentConfigHandler) redactForReader(ctx echo.Context, resp *agentConfigRevisionResponse) error {
	if len(resp.Overlay) == 0 || h.canConfigure(ctx) {
		return nil
	}
	redacted, _, err := agentconfig.RedactDocument(resp.Overlay)
	if err != nil {
		return err
	}
	resp.Overlay = redacted
	return nil
}

func (h *AgentConfigHandler) internalError(ctx echo.Context, what string, err error) error {
	h.sugar.Errorw("Agent configuration request failed", "operation", what, "path", ctx.Path(), "error", err)
	return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
}

func revisionResponse(agentID uuid.UUID, rev *relational.AgentConfigRevision, withOverlay bool) agentConfigRevisionResponse {
	if rev == nil {
		resp := agentConfigRevisionResponse{AgentID: agentID.String(), Revision: 0, OverlaySize: 2}
		if withOverlay {
			resp.Overlay = json.RawMessage(`{}`)
		}
		return resp
	}
	createdAt := rev.CreatedAt.UTC()
	createdBy := rev.CreatedBy
	resp := agentConfigRevisionResponse{
		AgentID:     agentID.String(),
		Revision:    rev.Revision,
		OverlaySize: len(rev.Overlay),
		Comment:     rev.Comment,
		CreatedBy:   &createdBy,
		CreatedAt:   &createdAt,
		RevertOf:    rev.RevertOf,
	}
	if withOverlay {
		resp.Overlay = json.RawMessage(rev.Overlay)
	}
	return resp
}

func preconditionRequired(ctx echo.Context) error {
	return ctx.JSON(http.StatusPreconditionRequired, api.NewError(errors.New("If-Match header with the current revision is required")))
}

func revisionConflict(ctx echo.Context, current int64) error {
	return ctx.JSON(http.StatusConflict, api.Error{Errors: map[string]any{
		"body":             agentcfg.ErrRevisionConflict.Error(),
		"current-revision": current,
	}})
}

// revisionAuthor returns the user subject (email) and user_uuid claim of the caller.
func revisionAuthor(ctx echo.Context) (string, *uuid.UUID) {
	claims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || claims == nil {
		return "", nil
	}
	var id *uuid.UUID
	if claims.UserUUID != "" {
		if parsed, err := uuid.Parse(claims.UserUUID); err == nil {
			id = &parsed
		}
	}
	return claims.Subject, id
}

// decodeStrict decodes a request envelope, rejecting unknown keys and trailing data.
func decodeStrict(body []byte, dst any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("request body is required")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	if dec.More() {
		return errors.New("invalid request body: unexpected data after the JSON object")
	}
	return nil
}

func normalizeComment(c *string) (*string, error) {
	if c == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*c)
	if trimmed == "" {
		return nil, nil
	}
	if len([]rune(trimmed)) > maxRevisionCommentLen {
		return nil, fmt.Errorf("comment must be at most %d characters", maxRevisionCommentLen)
	}
	return &trimmed, nil
}

func parseRevisionParam(s string) (int64, error) {
	rev, err := strconv.ParseInt(s, 10, 64)
	if err != nil || rev < 1 {
		return 0, errors.New("revision must be a positive integer")
	}
	return rev, nil
}

func isNullOrEmpty(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}

func compactJSON(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, fmt.Errorf("overlay is not valid JSON: %w", err)
	}
	return buf.Bytes(), nil
}

// nonNil returns an empty (non-nil) slice for nil, so JSON renders [] rather than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
