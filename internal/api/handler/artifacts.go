package handler

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/config"
	artifactsvc "github.com/compliance-framework/api/internal/service/relational/artifacts"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// ArtifactHandler stores and serves the content-addressed artifacts a policy evaluation
// used: the policy bundle, the input data and the policy data. The API, not the uploader,
// canonicalises and hashes them.
type ArtifactHandler struct {
	sugar    *zap.SugaredLogger
	service  *artifactsvc.Service
	maxBytes int64
}

func NewArtifactHandler(sugar *zap.SugaredLogger, service *artifactsvc.Service, cfg *config.ArtifactConfig) *ArtifactHandler {
	if cfg == nil {
		cfg = config.DefaultArtifactConfig()
	}
	return &ArtifactHandler{sugar: sugar, service: service, maxBytes: cfg.MaxBytes}
}

// RegisterAgent registers the agent-facing upload route.
func (h *ArtifactHandler) RegisterAgent(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.POST("", h.Upload, middlewares...)
}

// RegisterRead registers the read route.
func (h *ArtifactHandler) RegisterRead(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.GET("/:digest", h.Get, middlewares...)
}

// Upload godoc
//
//	@Summary		Upload an artifact
//	@Description	Stores the request body as an immutable artifact and returns its digest. The API converts the body to its canonical form first, so equal content always gets one digest. Content-Type application/json accepts any JSON value; application/vnd.ccf.policy-bundle.v1+tar accepts a policy bundle as a tar or gzipped tar. Uploading content that is already stored returns 200 and changes nothing. Agent token required.
//	@Tags			Artifacts
//	@Accept			application/json
//	@Accept			application/vnd.ccf.policy-bundle.v1+tar
//	@Produce		json
//	@Success		200	{object}	artifact.Info	"Already stored"
//	@Success		201	{object}	artifact.Info	"Stored"
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		413	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/agent/artifacts [post]
func (h *ArtifactHandler) Upload(ctx echo.Context) error {
	// Read the whole body before any other work, so a slow upload holds nothing but its
	// own connection.
	content, err := io.ReadAll(http.MaxBytesReader(ctx.Response(), ctx.Request().Body, h.maxBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return ctx.JSON(http.StatusRequestEntityTooLarge, api.NewError(fmt.Errorf("artifact exceeds %d bytes", h.maxBytes)))
		}
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	mediaType, _, err := mime.ParseMediaType(ctx.Request().Header.Get(echo.HeaderContentType))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid Content-Type: %w", err)))
	}

	canonical, err := artifact.Canonical(mediaType, content, h.maxBytes)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stored, created, err := h.service.Put(ctx.Request().Context(), mediaType, canonical, uploaderAgentID(ctx))
	if err != nil {
		h.sugar.Errorw("Failed to store artifact", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
		h.sugar.Infow("Stored artifact", "digest", stored.Digest, "media_type", stored.MediaType, "size_bytes", stored.SizeBytes)
	}
	return ctx.JSON(status, stored)
}

// Get godoc
//
//	@Summary		Download an artifact
//	@Description	Returns the canonical bytes of the artifact with the digest, with its media type. Any logged-in user or agent may read artifacts.
//	@Tags			Artifacts
//	@Produce		application/json
//	@Produce		application/vnd.ccf.policy-bundle.v1+tar
//	@Param			digest	path		string	true	"Artifact digest, sha256:<64 hex>"
//	@Success		200		{file}		binary
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/artifacts/{digest} [get]
func (h *ArtifactHandler) Get(ctx echo.Context) error {
	digest := ctx.Param("digest")
	if !artifact.ValidDigest(digest) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid digest %q", digest)))
	}
	stored, err := h.service.Get(ctx.Request().Context(), digest)
	if errors.Is(err, artifactsvc.ErrNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	if err != nil {
		h.sugar.Errorw("Failed to load artifact", "digest", digest, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Content never changes for a digest.
	header := ctx.Response().Header()
	header.Set("ETag", strconv.Quote(stored.Digest))
	header.Set("Cache-Control", "private, max-age=31536000, immutable")
	return ctx.Blob(http.StatusOK, stored.MediaType, stored.Content)
}

func uploaderAgentID(ctx echo.Context) *uuid.UUID {
	auth, ok := ctx.Get("agent_auth").(*middleware.AgentAuthContext)
	if !ok || auth == nil || auth.Agent == nil {
		return nil
	}
	return auth.Agent.ID
}
