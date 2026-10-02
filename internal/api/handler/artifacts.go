package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	artifactsvc "github.com/compliance-framework/api/internal/service/relational/artifacts"
	"github.com/compliance-framework/api/pkg/agentconfig"
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
	// slots bounds uploads being canonicalised and stored at once, across all callers.
	slots chan struct{}
	// slotWait is how long an upload waits for a slot before getting 429. Agents upload at
	// the start of each scheduled run, so short bursts are expected and queue rather than fail.
	slotWait time.Duration
}

// artifactSlotWait is how long an upload waits for a free slot.
const artifactSlotWait = 10 * time.Second

func NewArtifactHandler(sugar *zap.SugaredLogger, service *artifactsvc.Service, cfg *config.ArtifactConfig) *ArtifactHandler {
	if cfg == nil {
		cfg = config.DefaultArtifactConfig()
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = config.DefaultArtifactConfig().MaxConcurrent
	}
	return &ArtifactHandler{
		sugar:    sugar,
		service:  service,
		maxBytes: cfg.MaxBytes,
		slots:    make(chan struct{}, maxConcurrent),
		slotWait: artifactSlotWait,
	}
}

// acquireSlot waits up to slotWait for an upload slot. It reports false if none frees up in
// time or the request ends first; otherwise the caller must call the returned release.
func (h *ArtifactHandler) acquireSlot(ctx context.Context) (release func(), ok bool) {
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, true
	default:
	}

	timer := time.NewTimer(h.slotWait)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, true
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

// RegisterAgent registers the agent-facing upload route.
func (h *ArtifactHandler) RegisterAgent(e *echo.Group, middlewares ...echo.MiddlewareFunc) {
	e.POST("", h.Upload, middlewares...)
}

// RegisterRead registers the read routes: the raw artifact, and the files of a policy
// bundle artifact.
func (h *ArtifactHandler) RegisterRead(e *echo.Group, middlewares ...echo.MiddlewareFunc) {
	e.GET("/:digest", h.Get, middlewares...)
	e.GET("/:digest/files", h.ListFiles, middlewares...)
	e.GET("/:digest/files/*", h.GetFile, middlewares...)
}

// Upload godoc
//
//	@Summary		Upload an artifact
//	@Description	Stores the request body as an immutable artifact and returns its digest. The API converts the body to its canonical form first, so equal content always gets one digest. Content-Type application/json accepts any JSON value; application/vnd.ccf.policy-bundle.v1+tar accepts a policy bundle as a tar or gzipped tar. Uploading content that is already stored returns 200 and changes nothing. Needs an agent token, or none while public agent endpoints are allowed.
//	@Tags			Artifacts
//	@Accept			application/json
//	@Accept			application/vnd.ccf.policy-bundle.v1+tar
//	@Produce		json
//	@Success		200	{object}	artifact.Info	"Already stored"
//	@Success		201	{object}	artifact.Info	"Stored"
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		413	{object}	api.Error
//	@Failure		429	{object}	api.Error
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

	// The slot covers canonicalising and storing, the work that multiplies memory and CPU
	// per upload. It is taken after the body is read, so a slow uploader cannot hold one.
	release, ok := h.acquireSlot(ctx.Request().Context())
	if !ok {
		return ctx.JSON(http.StatusTooManyRequests, api.NewError(errors.New("too many artifact uploads in progress, retry shortly")))
	}
	defer release()

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
	digest := pathParam(ctx, "digest")
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
	setImmutable(ctx, stored.Digest)
	return ctx.Blob(http.StatusOK, stored.MediaType, stored.Content)
}

// MaxArtifactFileSourceBytes caps the file GetFile returns as source text.
const MaxArtifactFileSourceBytes = 1 << 20

// ArtifactFileList is the body of GET /api/artifacts/{digest}/files.
type ArtifactFileList struct {
	// Digest is the artifact digest (canonical tar, sha256:<hex>).
	Digest string `json:"digest"`
	// TreeDigest is agentconfig.BundleTreeDigest over the files (tree:sha256:<hex>), the
	// digest agent config reports use for the same tree.
	TreeDigest string             `json:"treeDigest"`
	Files      []ArtifactFileInfo `json:"files"`
}

// ArtifactFileInfo is one file of a policy bundle artifact.
type ArtifactFileInfo struct {
	Path   string `json:"path"`   // relative to the bundle root
	SHA256 string `json:"sha256"` // lowercase hex, as in agent config reports
	Size   int64  `json:"size"`   // bytes
	// Package is the Rego package without "data.", for .rego files that parse.
	Package string `json:"package,omitempty"`
}

// ArtifactFileSource is the body of GET /api/artifacts/{digest}/files/{path}.
type ArtifactFileSource struct {
	Path    string `json:"path"`
	Package string `json:"package,omitempty"`
	SHA256  string `json:"sha256"`
	Source  string `json:"source"`
}

// ListFiles godoc
//
//	@Summary		List the files of a policy bundle artifact
//	@Description	Returns every file of a stored policy bundle with its SHA-256, size and, for Rego modules, its package, plus the bundle's tree digest (the digest agent config reports use for the same tree). Agent config reports name bundle artifacts in policy-bundles[].artifact-digest. Any logged-in user or agent may read artifacts; that includes the policy bundles agents upload.
//	@Tags			Artifacts
//	@Produce		json
//	@Param			digest	path		string	true	"Artifact digest, sha256:<64 hex>"
//	@Success		200		{object}	handler.ArtifactFileList
//	@Success		304		"Not Modified"
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		415		{object}	api.Error	"The artifact is not a policy bundle"
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/artifacts/{digest}/files [get]
func (h *ArtifactHandler) ListFiles(ctx echo.Context) error {
	stored, errResp := h.loadBundle(ctx)
	if errResp != nil {
		return errResp()
	}
	files, err := artifact.ReadBundleFiles(stored.Content)
	if err != nil {
		h.sugar.Errorw("Failed to read stored bundle", "digest", stored.Digest, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	list := ArtifactFileList{Digest: stored.Digest, Files: make([]ArtifactFileInfo, 0, len(files))}
	tree := make(map[string][]byte, len(files))
	for _, f := range files {
		tree[f.Path] = f.Content
		list.Files = append(list.Files, ArtifactFileInfo{
			Path:    f.Path,
			SHA256:  sha256Hex(f.Content),
			Size:    int64(len(f.Content)),
			Package: regoPackage(f),
		})
	}
	list.TreeDigest = agentconfig.BundleTreeDigest(tree)
	return immutableJSON(ctx, list)
}

// GetFile godoc
//
//	@Summary		Get one file of a policy bundle artifact
//	@Description	Returns the source of one file of a stored policy bundle, with its SHA-256 and, for Rego modules, its package. path is the file's path in the bundle, as GET /artifacts/{digest}/files lists it. Files over 1 MiB, or that are not UTF-8 text, are not returned as source (422); download the artifact instead. Any logged-in user or agent may read artifacts; that includes the policy bundles agents upload.
//	@Tags			Artifacts
//	@Produce		json
//	@Param			digest	path		string	true	"Artifact digest, sha256:<64 hex>"
//	@Param			path	path		string	true	"File path in the bundle, e.g. policies/ssh.rego"
//	@Success		200		{object}	handler.ArtifactFileSource
//	@Success		304		"Not Modified"
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error	"No such artifact, or no such file in it"
//	@Failure		415		{object}	api.Error	"The artifact is not a policy bundle"
//	@Failure		422		{object}	api.Error	"The file is over 1 MiB or not UTF-8 text"
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/artifacts/{digest}/files/{path} [get]
func (h *ArtifactHandler) GetFile(ctx echo.Context) error {
	filePath := pathParam(ctx, "*")
	if filePath == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("file path is required")))
	}
	stored, errResp := h.loadBundle(ctx)
	if errResp != nil {
		return errResp()
	}

	var found *artifact.BundleFile
	errFound := errors.New("found")
	err := artifact.WalkBundleTar(stored.Content, func(f artifact.BundleFile) error {
		if f.Path != filePath {
			return nil
		}
		found = &f
		return errFound
	})
	if err != nil && !errors.Is(err, errFound) {
		h.sugar.Errorw("Failed to read stored bundle", "digest", stored.Digest, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if found == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("artifact %s has no file %q", stored.Digest, filePath)))
	}
	if len(found.Content) > MaxArtifactFileSourceBytes {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(fmt.Errorf("file %q is %d bytes, over the %d byte limit for source; download the artifact instead", filePath, len(found.Content), MaxArtifactFileSourceBytes)))
	}
	if !utf8.Valid(found.Content) {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(fmt.Errorf("file %q is not UTF-8 text; download the artifact instead", filePath)))
	}
	return immutableJSON(ctx, ArtifactFileSource{
		Path:    found.Path,
		Package: regoPackage(*found),
		SHA256:  sha256Hex(found.Content),
		Source:  string(found.Content),
	})
}

// loadBundle loads the policy bundle artifact the digest path parameter names. On failure
// it returns a function that writes the error response: 400 for a malformed digest, 404
// when none is stored, 415 when the artifact is not a policy bundle.
func (h *ArtifactHandler) loadBundle(ctx echo.Context) (*relational.Artifact, func() error) {
	digest := pathParam(ctx, "digest")
	if !artifact.ValidDigest(digest) {
		return nil, func() error {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid digest %q", digest)))
		}
	}
	stored, err := h.service.Get(ctx.Request().Context(), digest)
	if errors.Is(err, artifactsvc.ErrNotFound) {
		return nil, func() error { return ctx.JSON(http.StatusNotFound, api.NewError(err)) }
	}
	if err != nil {
		h.sugar.Errorw("Failed to load artifact", "digest", digest, "error", err)
		return nil, func() error { return ctx.JSON(http.StatusInternalServerError, api.NewError(err)) }
	}
	if stored.MediaType != artifact.MediaTypePolicyBundle {
		return nil, func() error {
			return ctx.JSON(http.StatusUnsupportedMediaType, api.NewError(fmt.Errorf("artifact %s is %s, not a policy bundle (%s)", digest, stored.MediaType, artifact.MediaTypePolicyBundle)))
		}
	}
	return stored, nil
}

// pathParam returns a path parameter unescaped. Echo matches routes on the escaped path
// when the request has one (an encoded character in a file name), and its parameters are
// then escaped too.
func pathParam(ctx echo.Context, name string) string {
	value := ctx.Param(name)
	if ctx.Request().URL.RawPath == "" {
		return value
	}
	if unescaped, err := url.PathUnescape(value); err == nil {
		return unescaped
	}
	return value
}

// setImmutable marks a response as never changing: its ETag is fixed and it may be cached
// for a year.
func setImmutable(ctx echo.Context, etag string) {
	header := ctx.Response().Header()
	header.Set("ETag", strconv.Quote(etag))
	header.Set("Cache-Control", "private, max-age=31536000, immutable")
}

// immutableJSON writes a JSON body derived only from an immutable artifact. The ETag is
// the digest of the body itself, so it changes if a later API version renders the same
// artifact differently; a matching If-None-Match gets 304.
func immutableJSON(ctx echo.Context, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	etag := artifact.Digest(raw)
	setImmutable(ctx, etag)
	if ifNoneMatch(ctx.Request().Header.Get("If-None-Match"), strconv.Quote(etag)) {
		return ctx.NoContent(http.StatusNotModified)
	}
	return ctx.JSONBlob(http.StatusOK, raw)
}

// ifNoneMatch reports whether an If-None-Match header matches etag (weak comparison).
func ifNoneMatch(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// regoPackage returns a .rego file's package, or "" for other files.
func regoPackage(f artifact.BundleFile) string {
	if !strings.HasSuffix(f.Path, ".rego") {
		return ""
	}
	return artifact.ModulePackage(f.Path, f.Content)
}

func uploaderAgentID(ctx echo.Context) *uuid.UUID {
	auth, ok := ctx.Get("agent_auth").(*middleware.AgentAuthContext)
	if !ok || auth == nil || auth.Agent == nil {
		return nil
	}
	return auth.Agent.ID
}
