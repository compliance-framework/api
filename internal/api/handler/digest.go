package handler

import (
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/scheduler"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// DigestHandler handles digest-related API endpoints
type DigestHandler struct {
	digestService *digest.Service
	scheduler     scheduler.Scheduler
	logger        *zap.SugaredLogger
}

// NewDigestHandler creates a new digest handler
func NewDigestHandler(digestService *digest.Service, sched scheduler.Scheduler, logger *zap.SugaredLogger) *DigestHandler {
	return &DigestHandler{
		digestService: digestService,
		scheduler:     sched,
		logger:        logger,
	}
}

// Register registers the digest endpoints
func (h *DigestHandler) Register(api *echo.Group) {
	api.POST("/trigger", h.TriggerDigest)
	api.GET("/preview", h.PreviewDigest)
}

// TriggerDigest godoc
//
//	@Summary		Trigger evidence digest
//	@Description	Manually triggers the evidence digest job to send emails to all users
//	@Tags			Digest
//	@Produce		json
//	@Param			job	query		string	false	"Job name to trigger (default: global-evidence-digest)"
//	@Success		200	{object}	map[string]string
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/digest/trigger [post]
func (h *DigestHandler) TriggerDigest(ctx echo.Context) error {
	jobName := ctx.QueryParam("job")
	if jobName == "" {
		jobName = "global-evidence-digest"
	}

	if h.scheduler == nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("scheduler is not available")))
	}

	if err := h.scheduler.RunNow(ctx.Request().Context(), jobName); err != nil {
		h.logger.Errorw("Failed to trigger digest job", "job", jobName, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"message": "Digest job triggered successfully",
		"job":     jobName,
	})
}

// PreviewDigest godoc
//
//	@Summary		Preview evidence digest
//	@Description	Returns the current evidence summary that would be included in a digest email
//	@Tags			Digest
//	@Produce		json
//	@Success		200	{object}	GenericDataResponse[digest.EvidenceSummary]
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/digest/preview [get]
func (h *DigestHandler) PreviewDigest(ctx echo.Context) error {
	summary, err := h.digestService.GetGlobalEvidenceSummary(ctx.Request().Context())
	if err != nil {
		h.logger.Errorw("Failed to get evidence summary", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[*digest.EvidenceSummary]{Data: summary})
}
