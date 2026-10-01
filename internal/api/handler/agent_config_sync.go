package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

const (
	// headerRemoteConfig marks responses from the remote-configuration routes, so an agent can
	// tell them apart from a proxy's.
	headerRemoteConfig = "X-CCF-Remote-Config"

	maxReportHostnameLen     = 255
	maxReportAgentVersionLen = 64
	maxReportErrorBytes      = 8 << 10
	maxReportWarnings        = 500

	// R76/R77: plugins and the plugin-facing policy path.
	maxReportPlugins          = 500
	maxReportPluginNameLen    = 255
	maxReportPluginSourceLen  = 2048
	maxReportPluginLibVersion = 64
	maxReportPluginPathLen    = 4096
)

var effectiveDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// AgentConfigSyncHandler serves the agent-facing remote-configuration routes. They accept
// agent JWTs only (never anonymous, even with public agent endpoints on) and act on the
// authenticated agent's own configuration.
type AgentConfigSyncHandler struct {
	sugar *zap.SugaredLogger
	svc   *agentcfg.Service
}

func NewAgentConfigSyncHandler(sugar *zap.SugaredLogger, svc *agentcfg.Service) *AgentConfigSyncHandler {
	return &AgentConfigSyncHandler{sugar: sugar, svc: svc}
}

// Register mounts GET /config and PUT /instances/:instanceId/config-report on the /agent
// group. Pass the strict agent JWT middleware and the agent:sync guard.
func (h *AgentConfigSyncHandler) Register(g *echo.Group, middlewares ...echo.MiddlewareFunc) {
	g.GET("/config", h.GetConfig, middlewares...)
	g.PUT("/instances/:instanceId/config-report", h.PutReport, middlewares...)
}

// agentAuthFrom returns the authenticated agent, or nil. The handler requires it even though
// the route middleware does too: Cedar grants the agent role to anonymous subjects when
// public agent endpoints are on (defence in depth).
func agentAuthFrom(ctx echo.Context) *middleware.AgentAuthContext {
	auth, _ := ctx.Get("agent_auth").(*middleware.AgentAuthContext)
	if auth == nil || auth.Agent == nil || auth.Agent.ID == nil {
		return nil
	}
	return auth
}

func setRemoteConfigHeaders(ctx echo.Context) {
	ctx.Response().Header().Set(headerRemoteConfig, "1")
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-cache")
}

// GetConfig godoc
//
//	@Summary		Get this agent's configuration overlay
//	@Description	Returns the authenticated agent's current remote-configuration overlay (an RFC 7396 merge patch over its local config file, snake_case) with an opaque ETag. Send the raw ETag back as If-None-Match to get a 304 when nothing changed; never construct one. Revision 0 means no overlay. Agent JWT only; a 404 means the API predates remote configuration.
//	@Tags			Agents
//	@Produce		json
//	@Param			If-None-Match	header		string	false	"ETag of the overlay the agent already has"
//	@Success		200				{object}	handler.GenericDataResponse[agentconfig.OverlayDocument]
//	@Success		304				"Not Modified"
//	@Failure		401				{object}	api.Error
//	@Failure		403				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/agent/config [get]
func (h *AgentConfigSyncHandler) GetConfig(ctx echo.Context) error {
	auth := agentAuthFrom(ctx)
	if auth == nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("agent authentication required")))
	}
	agentID := *auth.Agent.ID

	cur, err := h.svc.Current(ctx.Request().Context(), agentID)
	if err != nil {
		h.sugar.Errorw("Failed to load agent configuration", "agentID", agentID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	doc := agentconfig.OverlayDocument{Revision: 0, Overlay: json.RawMessage(`{}`)}
	rowID := uuid.Nil
	if cur != nil {
		doc.Revision = cur.Revision
		doc.Overlay = json.RawMessage(cur.Overlay)
		createdAt := cur.CreatedAt.UTC()
		doc.CreatedAt = &createdAt
		rowID = *cur.ID
	}
	etag := agentconfig.ETagForRevision(doc.Revision, rowID, agentID)

	setRemoteConfigHeaders(ctx)
	ctx.Response().Header().Set(headerETag, etag)
	if agentconfig.MatchIfNoneMatch(ctx.Request().Header.Get("If-None-Match"), etag) {
		return ctx.NoContent(http.StatusNotModified)
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[agentconfig.OverlayDocument]{Data: doc})
}

// PutReport godoc
//
//	@Summary		Report this instance's effective configuration
//	@Description	Stores the authenticated agent instance's config report: mode, applied/attempted revision, status (applied, rejected, failed or not-applicable; the server derives pending and unknown), the redacted base and effective configs (snake_case), the effective digest, loaded policy bundles, policy errors, unsafe changes, warnings and the normalized local remote_config block. The server re-redacts base and effective as a best effort and stores effective-digest as sent. Body limit 4 MiB. A 409 means the per-agent instance cap is reached; back off.
//	@Tags			Agents
//	@Accept			json
//	@Param			instanceId	path	string				true	"Agent instance ID (UUID)"
//	@Param			report		body	agentconfig.Report	true	"Config report"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		403			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		413			{object}	api.Error
//	@Failure		415			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/agent/instances/{instanceId}/config-report [put]
func (h *AgentConfigSyncHandler) PutReport(ctx echo.Context) error {
	auth := agentAuthFrom(ctx)
	if auth == nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("agent authentication required")))
	}
	setRemoteConfigHeaders(ctx)
	agentID := *auth.Agent.ID

	instanceID, err := uuid.Parse(ctx.Param("instanceId"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.InvalidUUID())
	}
	body, bodyErr := readJSONBody(ctx, agentconfig.MaxReportBytes)
	if bodyErr != nil {
		return bodyErr.respond(ctx)
	}
	var report agentconfig.Report
	if err := json.Unmarshal(body, &report); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid report body: %w", err)))
	}
	if err := normalizeReport(&report); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Best-effort server-side re-redaction; the digest is stored exactly as sent (R55).
	for _, doc := range []struct {
		name string
		raw  *json.RawMessage
	}{{"base", &report.Base}, {"effective", &report.Effective}} {
		redacted, changed, err := agentconfig.RedactDocument(*doc.raw)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("%s: %w", doc.name, err)))
		}
		if changed {
			h.sugar.Warnw("Agent config report was not fully redacted; re-redacted server-side",
				"agentID", agentID, "instanceID", instanceID, "document", doc.name)
		}
		*doc.raw = redacted
	}

	var credentialID *uuid.UUID
	if auth.Key != nil && auth.Key.ID != nil {
		id := *auth.Key.ID
		credentialID = &id
	}
	if err := h.svc.UpsertReport(ctx.Request().Context(), agentID, credentialID, instanceID, report); err != nil {
		if errors.Is(err, agentcfg.ErrInstanceLimit) {
			return ctx.JSON(http.StatusConflict, api.NewError(agentcfg.ErrInstanceLimit))
		}
		h.sugar.Errorw("Failed to store agent config report", "agentID", agentID, "instanceID", instanceID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return ctx.NoContent(http.StatusNoContent)
}

// normalizeReport validates the enums and shapes of a report and applies the length caps
// (truncating, not rejecting, the free-text fields).
func normalizeReport(r *agentconfig.Report) error {
	if !slices.Contains(agentconfig.Modes, r.Mode) {
		return fmt.Errorf("mode must be one of %s", strings.Join(agentconfig.Modes, ", "))
	}
	if !slices.Contains(agentconfig.AgentStatuses, r.Status) {
		return fmt.Errorf("status must be one of %s", strings.Join(agentconfig.AgentStatuses, ", "))
	}
	if r.Reason != "" && !slices.Contains(agentconfig.Reasons, r.Reason) {
		return fmt.Errorf("reason %q is not a known reason", r.Reason)
	}
	if r.AppliedRevision != nil && *r.AppliedRevision < 0 {
		return errors.New("applied-revision must not be negative")
	}
	if r.AttemptedRevision != nil && *r.AttemptedRevision < 0 {
		return errors.New("attempted-revision must not be negative")
	}
	if !isJSONObject(r.Base) {
		return errors.New("base must be a JSON object")
	}
	if !isJSONObject(r.Effective) {
		return errors.New("effective must be a JSON object")
	}
	if !effectiveDigestPattern.MatchString(r.EffectiveDigest) {
		return errors.New("effective-digest must match sha256:<64 lowercase hex>")
	}
	for i, b := range r.PolicyBundles {
		if b.ArtifactDigest != "" && !artifact.ValidDigest(b.ArtifactDigest) {
			return fmt.Errorf("policy-bundles[%d].artifact-digest must match sha256:<64 lowercase hex>", i)
		}
		if b.Extends != nil && b.Extends.ArtifactDigest != "" && !artifact.ValidDigest(b.Extends.ArtifactDigest) {
			return fmt.Errorf("policy-bundles[%d].extends.artifact-digest must match sha256:<64 lowercase hex>", i)
		}
		// A cut path would be a wrong one, and the UI writes policy_ids from it (R77), so an
		// oversized path is dropped rather than truncated.
		if len(b.PluginPath) > maxReportPluginPathLen {
			r.PolicyBundles[i].PluginPath = ""
			r.Truncated = true
		}
	}
	for i, p := range r.Plugins {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("plugins[%d].name is required", i)
		}
	}
	if len(r.Plugins) > maxReportPlugins {
		r.Plugins = r.Plugins[:maxReportPlugins]
		r.Truncated = true
	}
	for i := range r.Plugins {
		p := &r.Plugins[i]
		p.Name = truncateUTF8(p.Name, maxReportPluginNameLen)
		p.Source = truncateUTF8(p.Source, maxReportPluginSourceLen)
		p.LibVersion = truncateUTF8(strings.TrimSpace(p.LibVersion), maxReportPluginLibVersion)
	}
	if len(r.Warnings) > maxReportWarnings {
		r.Warnings = r.Warnings[:maxReportWarnings]
		r.Truncated = true
	}
	r.Hostname = truncateUTF8(strings.TrimSpace(r.Hostname), maxReportHostnameLen)
	r.AgentVersion = truncateUTF8(strings.TrimSpace(r.AgentVersion), maxReportAgentVersionLen)
	if r.Error != nil {
		msg := truncateUTF8(*r.Error, maxReportErrorBytes)
		r.Error = &msg
	}
	return nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
