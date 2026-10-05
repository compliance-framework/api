package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
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

// Register mounts GET /config on the /agent group. Pass the strict agent JWT middleware and
// the agent:sync guard.
func (h *AgentConfigSyncHandler) Register(g *echo.Group, middlewares ...echo.MiddlewareFunc) {
	g.GET("/config", h.GetConfig, middlewares...)
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
