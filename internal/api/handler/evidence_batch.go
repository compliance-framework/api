package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/authcontext"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	echomiddleware "github.com/labstack/echo/v5/middleware"
	"gorm.io/gorm"
)

const (
	// evidenceBatchBodyLimit bounds a batch request body.
	evidenceBatchBodyLimit = 64 * echomiddleware.MB
	// evidenceBatchRouteName names GET /evidence/batches/:id, the Location of a new batch.
	evidenceBatchRouteName = "evidence-batch"
)

// EvidenceBatchQueue runs evidence batch chunks in the background: the worker service.
type EvidenceBatchQueue interface {
	evidencesvc.BatchJobEnqueuer
	SetEvidenceBatchProcessor(processor worker.EvidenceBatchProcessor)
}

// EvidenceBatchCreateRequest is a list of evidence to store asynchronously.
type EvidenceBatchCreateRequest struct {
	// Evidence holds the evidence to store, each as accepted by POST /evidence.
	Evidence []EvidenceCreateRequest `json:"evidence"`
}

// evidenceBatchCreateBody is EvidenceBatchCreateRequest with each evidence kept as sent,
// to be stored and decoded again when it is processed.
type evidenceBatchCreateBody struct {
	Evidence []json.RawMessage `json:"evidence"`
}

// EvidenceBatchResponse is a batch's progress and, once read back, each item's outcome.
type EvidenceBatchResponse struct {
	ID uuid.UUID `json:"id"`
	// SubmittedBy is who submitted the batch: "user:<email>" or "agent:<agent id>".
	SubmittedBy string `json:"submitted-by"`
	// Status is pending (no item processed yet), processing or completed (every item
	// succeeded or failed).
	Status     string                      `json:"status"`
	Total      int                         `json:"total"`
	Pending    int                         `json:"pending"`
	Succeeded  int                         `json:"succeeded"`
	Failed     int                         `json:"failed"`
	AcceptedAt time.Time                   `json:"accepted-at"`
	Items      []EvidenceBatchItemResponse `json:"items"`
}

// EvidenceBatchItemResponse is the outcome of the evidence at Index in the request.
type EvidenceBatchItemResponse struct {
	Index int `json:"index"`
	// Status is pending, succeeded or failed.
	Status     string     `json:"status"`
	EvidenceID *uuid.UUID `json:"evidence-id,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// evidenceBatchConfig is cfg's batch limits, or the defaults when cfg sets none.
func evidenceBatchConfig(cfg *config.Config) *config.EvidenceBatchConfig {
	if cfg != nil && cfg.EvidenceBatch != nil {
		return cfg.EvidenceBatch
	}
	return &config.EvidenceBatchConfig{
		MaxItems:  config.DefaultEvidenceBatchMaxItems,
		ChunkSize: config.DefaultEvidenceBatchChunkSize,
		Workers:   config.DefaultEvidenceBatchWorkers,
	}
}

// WithBatchService enables POST /evidence/batches and GET /evidence/batches/{id}. pdp
// decides evidence:inspect, which lets a caller read batches others submitted; with a nil
// pdp batches are readable only by their submitter.
func (h *EvidenceHandler) WithBatchService(service *evidencesvc.BatchService, maxItems int, pdp authz.PDP) *EvidenceHandler {
	h.batchService = service
	h.batchMaxItems = maxItems
	h.batchPDP = pdp
	return h
}

// canInspectBatches reports whether the caller holds evidence:inspect, evaluated against
// the PDP like a route guard. It fails closed: no PDP, an unavailable PDP or an evaluation
// error all count as no.
func (h *EvidenceHandler) canInspectBatches(ctx *echo.Context) bool {
	if h.batchPDP == nil {
		return false
	}
	subject := middleware.SubjectFromContext(ctx)
	resource := authz.Resource{Type: authz.ResourceEvidence, ID: ctx.Param("id")}
	reqCtx := map[string]any{"method": ctx.Request().Method, "path": ctx.Path()}
	decision, err := h.batchPDP.Evaluate(ctx.Request().Context(), subject, authz.ActionInspect, resource, reqCtx)
	if err != nil {
		h.sugar.Warnw("evidence:inspect check failed; showing only the caller's own batches", "path", ctx.Path(), "error", err)
		return false
	}
	return decision.Allow
}

// RegisterBatchRoutes registers the batch routes with their auth middleware and guard.
func (h *EvidenceHandler) RegisterBatchRoutes(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	createMiddlewares := append([]echo.MiddlewareFunc{echomiddleware.BodyLimit(evidenceBatchBodyLimit)}, middlewares...)
	api.POST("", h.CreateBatch, createMiddlewares...)
	if _, err := api.AddRoute(echo.Route{
		Method:      http.MethodGet,
		Path:        "/:id",
		Name:        evidenceBatchRouteName,
		Handler:     h.GetBatch,
		Middlewares: middlewares,
	}); err != nil {
		panic(err) // as echo's GET does: a route that can't be registered is a programming error
	}
}

// CreateBatch godoc
//
//	@Summary		Submit a batch of Evidence
//	@Description	Accepts up to CCF_EVIDENCE_BATCH_MAX_ITEMS evidence and stores them asynchronously, returning the batch to poll with GET /evidence/batches/{id}. Each evidence is the body POST /evidence accepts; its shape and times are checked on submit, everything else when it is processed, where a failure fails that evidence only. Needs an authenticated user or agent, and the worker service.
//	@Tags			Evidence
//	@Accept			json
//	@Produce		json
//	@Param			batch	body		EvidenceBatchCreateRequest	true	"Evidence batch"
//	@Success		202		{object}	GenericDataResponse[EvidenceBatchResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		413		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Failure		503		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/evidence/batches [post]
func (h *EvidenceHandler) CreateBatch(ctx *echo.Context) error {
	if h.batchService == nil {
		return ctx.JSON(http.StatusServiceUnavailable, api.NewError(errors.New("evidence batches are not available")))
	}
	if err := h.batchService.Available(); err != nil {
		return ctx.JSON(http.StatusServiceUnavailable, api.NewError(errors.New("evidence batches are not available: the worker service is disabled")))
	}

	var body evidenceBatchCreateBody
	if err := ctx.Bind(&body); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if len(body.Evidence) == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("evidence must hold at least one item")))
	}
	if len(body.Evidence) > h.batchMaxItems {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("evidence holds %d items; a batch may hold at most %d", len(body.Evidence), h.batchMaxItems)))
	}

	if invalid := h.checkBatchItems(ctx, body.Evidence, time.Now().UTC()); len(invalid.Errors) > 0 {
		return ctx.JSON(http.StatusBadRequest, invalid)
	}

	summary, err := h.batchService.Submit(ctx.Request().Context(), body.Evidence, authcontext.SignerContextFromEcho(ctx))
	if errors.Is(err, evidencesvc.ErrBatchSubmitterRequired) {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(err))
	}
	if err != nil {
		h.sugar.Errorw("Failed to submit evidence batch", "items", len(body.Evidence), "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	if location, err := ctx.Echo().Router().Routes().Reverse(evidenceBatchRouteName, summary.ID.String()); err == nil {
		ctx.Response().Header().Set(echo.HeaderLocation, location)
	}
	return ctx.JSON(http.StatusAccepted, GenericDataResponse[EvidenceBatchResponse]{Data: newEvidenceBatchResponse(summary)})
}

// checkBatchItems checks what can be checked without the database: each item decodes,
// validates, sets no reserved prop and doesn't start or end in the future. Problems are
// keyed by the item's position, "evidence[i]".
func (h *EvidenceHandler) checkBatchItems(ctx *echo.Context, items []json.RawMessage, now time.Time) api.Error {
	invalid := api.Error{Errors: map[string]any{}}
	for i, raw := range items {
		key := fmt.Sprintf("evidence[%d]", i)
		input, err := decodeEvidenceCreateRequest(raw)
		if err != nil {
			invalid.Errors[key] = err.Error()
			continue
		}
		if err := ctx.Validate(input); err != nil {
			invalid.Errors[key] = api.Validator(err).Errors
			continue
		}
		if err := checkReservedProps(input); err != nil {
			invalid.Errors[key] = err.Error()
			continue
		}
		if err := checkEvidenceTimes(input, now); err != nil {
			invalid.Errors[key] = err.Error()
		}
	}
	return invalid
}

func decodeEvidenceCreateRequest(raw json.RawMessage) (*EvidenceCreateRequest, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("evidence must be an object")
	}
	var input EvidenceCreateRequest
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, err
	}
	return &input, nil
}

func checkReservedProps(input *EvidenceCreateRequest) error {
	for _, prop := range input.Props {
		if artifact.IsReservedProp(prop.Name) {
			return fmt.Errorf("prop %q is set by the API from policy-artifacts and may not be supplied", prop.Name)
		}
	}
	return nil
}

// storeBatchItem is the evidencesvc.BatchItemFunc of evidence batches: it stores one item
// exactly as POST /evidence would have when the batch was accepted.
func (h *EvidenceHandler) storeBatchItem(ctx context.Context, payload json.RawMessage, signer *evidencesvc.SignerContext, onCreated func(tx *gorm.DB, evidence *relational.Evidence) error) error {
	input, err := decodeEvidenceCreateRequest(payload)
	if err != nil {
		return evidencesvc.RejectBatchItem(err)
	}
	now := time.Now().UTC()
	if signer != nil && !signer.AcceptedAt.IsZero() {
		now = signer.AcceptedAt
	}
	_, err = h.storeEvidence(ctx, input, signer, now, onCreated)
	var rejected *evidenceRejectedError
	if errors.As(err, &rejected) {
		return evidencesvc.RejectBatchItem(rejected)
	}
	return err
}

// GetBatch godoc
//
//	@Summary		Get an Evidence batch
//	@Description	Returns the progress of a batch submitted with POST /evidence/batches and the outcome of each of its evidence, by position in the request. The user or agent that submitted the batch can read it, and so can callers holding evidence:inspect (the admin role under Cedar); anyone else gets 404.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Batch ID"
//	@Success		200	{object}	GenericDataResponse[EvidenceBatchResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Failure		503	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/evidence/batches/{id} [get]
func (h *EvidenceHandler) GetBatch(ctx *echo.Context) error {
	if h.batchService == nil {
		return ctx.JSON(http.StatusServiceUnavailable, api.NewError(errors.New("evidence batches are not available")))
	}
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.InvalidUUID())
	}

	submittedBy := evidencesvc.BatchSubmitter(authcontext.SignerContextFromEcho(ctx))
	summary, err := h.batchService.Get(ctx.Request().Context(), id, submittedBy)
	if errors.Is(err, evidencesvc.ErrBatchNotFound) && h.canInspectBatches(ctx) {
		summary, err = h.batchService.GetAny(ctx.Request().Context(), id)
	}
	if errors.Is(err, evidencesvc.ErrBatchNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}
	if err != nil {
		h.sugar.Errorw("Failed to get evidence batch", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[EvidenceBatchResponse]{Data: newEvidenceBatchResponse(summary)})
}

func newEvidenceBatchResponse(summary *evidencesvc.BatchSummary) EvidenceBatchResponse {
	items := make([]EvidenceBatchItemResponse, 0, len(summary.Items))
	for _, item := range summary.Items {
		items = append(items, EvidenceBatchItemResponse{
			Index:      item.Index,
			Status:     string(item.Status),
			EvidenceID: item.EvidenceID,
			Error:      item.Error,
		})
	}
	return EvidenceBatchResponse{
		ID:          summary.ID,
		SubmittedBy: summary.SubmittedBy,
		Status:      string(summary.Status),
		Total:       summary.Total,
		Pending:     summary.Pending,
		Succeeded:   summary.Succeeded,
		Failed:      summary.Failed,
		AcceptedAt:  summary.AcceptedAt,
		Items:       items,
	}
}
