package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	artifactsvc "github.com/compliance-framework/api/internal/service/relational/artifacts"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// PlaybackHandler evaluates caller-supplied Rego against caller-supplied input. It reads
// and writes nothing in the database; the sandbox, time limit, body limit and a global
// concurrency limit bound what one request can cost.
type PlaybackHandler struct {
	sugar    *zap.SugaredLogger
	timeout  time.Duration
	maxBytes int64
	slots    chan struct{}

	// Set by WithEvidencePlayback, to replay stored evidence.
	evidence  *evidencesvc.EvidenceService
	artifacts *artifactsvc.Service
}

func NewPlaybackHandler(sugar *zap.SugaredLogger, cfg *config.PlaybackConfig) *PlaybackHandler {
	cfg = playbackConfigOrDefault(cfg)
	return &PlaybackHandler{
		sugar:    sugar,
		timeout:  cfg.Timeout,
		maxBytes: cfg.MaxBytes,
		slots:    make(chan struct{}, cfg.MaxConcurrent),
	}
}

func playbackConfigOrDefault(cfg *config.PlaybackConfig) *config.PlaybackConfig {
	if cfg == nil {
		return config.DefaultPlaybackConfig()
	}
	return cfg
}

func (h *PlaybackHandler) Register(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.POST("/evaluate", h.Evaluate, middlewares...)
}

// Evaluate godoc
//
//	@Summary		Evaluate a Rego policy
//	@Description	Evaluates Rego policy source against JSON input in a sandbox and returns the raw outcome plus the pass/fail interpretation the agent would record. Open to users, agents and anonymous callers where public agent endpoints are allowed. Nothing is persisted.
//	@Tags			Playback
//	@Accept			json
//	@Produce		json
//	@Param			request	body		policyeval.EvaluateRequest	true	"Policy, optional helper modules, input, optional policy data and evaluation time"
//	@Success		200		{object}	policyeval.EvaluateResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		403		{object}	api.Error
//	@Failure		413		{object}	api.Error
//	@Failure		422		{object}	policyeval.ErrorResponse
//	@Failure		429		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/playback/evaluate [post]
func (h *PlaybackHandler) Evaluate(ctx echo.Context) error {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		return ctx.JSON(http.StatusTooManyRequests, api.NewError(errors.New("too many playback evaluations in progress, retry shortly")))
	}

	body, err := io.ReadAll(http.MaxBytesReader(ctx.Response(), ctx.Request().Body, h.maxBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return ctx.JSON(http.StatusRequestEntityTooLarge, api.NewError(fmt.Errorf("request body exceeds %d bytes", h.maxBytes)))
		}
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	req, err := decodePlaybackRequest(body)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	evalCtx, cancel := context.WithTimeout(ctx.Request().Context(), h.timeout)
	defer cancel()

	started := time.Now()
	resp, err := policyeval.Evaluate(evalCtx, req)
	subject := middleware.SubjectFromContext(ctx)
	logFields := []any{
		"subject_type", subject.Type,
		"subject_id", subject.ID,
		"input_bytes", len(body),
		"duration_ms", time.Since(started).Milliseconds(),
	}

	if err != nil {
		var evalErrs *policyeval.EvalErrors
		if errors.As(err, &evalErrs) {
			h.sugar.Infow("Playback evaluation rejected", append(logFields, "code", evalErrs.Errors[0].Code)...)
			return ctx.JSON(http.StatusUnprocessableEntity, policyeval.ErrorResponse{Errors: evalErrs.Errors})
		}
		h.sugar.Errorw("Playback evaluation failed", append(logFields, "error", err)...)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	packages := make([]string, 0, len(resp.Results))
	for _, result := range resp.Results {
		packages = append(packages, result.Package)
	}
	h.sugar.Infow("Playback evaluation completed", append(logFields, "packages", packages)...)
	return ctx.JSON(http.StatusOK, resp)
}

// decodePlaybackRequest keeps JSON numbers exact, as OPA expects, and enforces the fields
// the request cannot do without.
func decodePlaybackRequest(body []byte) (policyeval.EvaluateRequest, error) {
	var req policyeval.EvaluateRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&req); err != nil {
		return req, fmt.Errorf("invalid request body: %w", err)
	}
	if req.Policy == "" {
		return req, errors.New("policy is required")
	}
	if req.Input == nil {
		return req, errors.New("input is required")
	}
	return req, nil
}
