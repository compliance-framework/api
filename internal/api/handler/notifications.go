package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	notificationtroubleshooting "github.com/compliance-framework/api/internal/service/notificationtroubleshooting"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type NotificationsHandler struct {
	sugar           *zap.SugaredLogger
	db              *gorm.DB
	cfg             *config.Config
	providers       notification.ProviderLookup
	troubleshooting *notificationtroubleshooting.Service
	enqueuer        notificationTestEnqueuer
}

type notificationTestEnqueuer interface {
	notification.WorkerEnqueuer
	emailprovider.Enqueuer
	slackprovider.Enqueuer
}

type configuredSystemDestinationResponse struct {
	ProviderType      string `json:"providerType"`
	DestinationTarget string `json:"destinationTarget"`
}

type availableNotificationProviderResponse struct {
	ProviderType string            `json:"providerType"`
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description"`
	Enabled      bool              `json:"enabled"`
	Error        string            `json:"error,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type notificationProviderStatusResponse struct {
	ProviderType string `json:"providerType"`
	Enabled      bool   `json:"enabled"`
}

type systemNotificationResponse struct {
	Name                   string                                `json:"name"`
	ConfiguredDestinations []configuredSystemDestinationResponse `json:"configuredDestinations"`
}

type createSystemNotificationDestinationRequest struct {
	ProviderType      string `json:"providerType" validate:"required"`
	DestinationTarget string `json:"destinationTarget" validate:"required"`
}

type testNotificationRequest struct {
	ProviderType      string `json:"providerType" validate:"required,oneof=email slack" enums:"email,slack"`
	DestinationTarget string `json:"destinationTarget" validate:"required"`
	Mode              string `json:"mode" validate:"omitempty,oneof=enqueue" enums:"enqueue"`
}

type testNotificationResponse struct {
	Accepted          bool    `json:"accepted"`
	Mode              string  `json:"mode"`
	ProviderType      string  `json:"providerType"`
	DestinationTarget string  `json:"destinationTarget"`
	JobIDs            []int64 `json:"jobIds"`
	Message           string  `json:"message"`
}

func (r *createSystemNotificationDestinationRequest) UnmarshalJSON(data []byte) error {
	type requestAlias struct {
		ProviderTypeCamel      string `json:"providerType"`
		DestinationTargetCamel string `json:"destinationTarget"`
		ProviderTypeKebab      string `json:"provider-type"`
		DestinationTargetKebab string `json:"destination-target"`
	}

	var decoded requestAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	r.ProviderType = strings.TrimSpace(firstNonEmpty(decoded.ProviderTypeCamel, decoded.ProviderTypeKebab))
	r.DestinationTarget = strings.TrimSpace(firstNonEmpty(decoded.DestinationTargetCamel, decoded.DestinationTargetKebab))
	return nil
}

func NewNotificationsHandler(sugar *zap.SugaredLogger, db *gorm.DB, cfg *config.Config, enqueuer notification.WorkerEnqueuer) *NotificationsHandler {
	testEnqueuer, _ := enqueuer.(notificationTestEnqueuer)
	return &NotificationsHandler{
		sugar:           sugar,
		db:              db,
		cfg:             cfg,
		providers:       notificationproviders.NewLookup(notificationproviders.WithConfig(cfg)),
		troubleshooting: notificationtroubleshooting.New(db, cfg),
		enqueuer:        testEnqueuer,
	}
}

func (h *NotificationsHandler) Register(api *echo.Group) {
	api.GET("/health", h.GetTroubleshootingHealth)
	api.GET("/jobs", h.ListTroubleshootingJobs)
	api.GET("/jobs/:id", h.GetTroubleshootingJob)
	api.POST("/test", h.SendTestNotification)
	api.GET("/:notificationName/diagnostics", h.GetNotificationDiagnostics)
	api.GET("", h.ListSystemNotifications)
	api.GET("/providers", h.ListNotificationProviders)
	api.POST("/:notificationName/destinations", h.CreateSystemNotificationDestination)
	api.DELETE("/:notificationName/destinations", h.DeleteSystemNotificationDestination)
}

func (h *NotificationsHandler) RegisterPublic(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("/providers", h.ListNotificationProviderStatus, guard.Read())
}

// GetTroubleshootingHealth godoc
//
//	@Summary		Get notification troubleshooting health
//	@Description	Returns provider, worker, queue, subscriber, destination, and schedule health for admin notification troubleshooting
//	@Tags			Notifications
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[notificationtroubleshooting.HealthResponse]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/health [get]
func (h *NotificationsHandler) GetTroubleshootingHealth(ctx echo.Context) error {
	response, err := h.troubleshooting.Health(ctx.Request().Context())
	if err != nil {
		h.sugar.Errorw("Failed to get notification troubleshooting health", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[notificationtroubleshooting.HealthResponse]{Data: response})
}

// ListTroubleshootingJobs godoc
//
//	@Summary		List notification River jobs
//	@Description	Lists recent notification-related River jobs with sanitized notification metadata
//	@Tags			Notifications
//	@Produce		json
//	@Param			queue				query		[]string	false	"Queue filter; repeat or comma-separate values"
//	@Param			provider			query		string		false	"Provider filter: email or slack"	Enums(email, slack)
//	@Param			notificationKind	query		string		false	"Notification kind filter"
//	@Param			state				query		[]string	false	"River state filter; repeat or comma-separate values"	Enums(available, cancelled, completed, discarded, pending, retryable, running, scheduled)
//	@Param			since				query		string		false	"RFC3339 lower bound for job creation time"				Format(date-time)
//	@Param			limit				query		int			false	"Page size, default 50, max 200"						minimum(1)	maximum(200)
//	@Param			cursor				query		string		false	"Opaque pagination cursor"
//	@Success		200					{object}	notificationtroubleshooting.JobsListResponse
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/jobs [get]
func (h *NotificationsHandler) ListTroubleshootingJobs(ctx echo.Context) error {
	query, err := parseTroubleshootingJobsQuery(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	response, err := h.troubleshooting.Jobs(ctx.Request().Context(), query)
	if err != nil {
		h.sugar.Warnw("Failed to list notification troubleshooting jobs", "error", err)
		if notificationtroubleshooting.IsInvalidJobsQuery(err) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, response)
}

// GetTroubleshootingJob godoc
//
//	@Summary		Get notification River job detail
//	@Description	Returns one sanitized notification-related River job with attempt errors
//	@Tags			Notifications
//	@Produce		json
//	@Param			id	path		int	true	"River job ID"
//	@Success		200	{object}	handler.GenericDataResponse[notificationtroubleshooting.JobDetail]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/jobs/{id} [get]
func (h *NotificationsHandler) GetTroubleshootingJob(ctx echo.Context) error {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("invalid job id")))
	}
	response, ok, err := h.troubleshooting.Job(ctx.Request().Context(), id)
	if err != nil {
		h.sugar.Errorw("Failed to get notification troubleshooting job", "error", err, "jobID", id)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if !ok {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[notificationtroubleshooting.JobDetail]{Data: response})
}

// GetNotificationDiagnostics godoc
//
//	@Summary		Get notification diagnostics
//	@Description	Runs read-only diagnostics for evidence digest, workflow, risk, or POAM notifications
//	@Tags			Notifications
//	@Produce		json
//	@Param			notificationName	path		string	true	"Notification name or family"
//	@Success		200					{object}	handler.GenericDataResponse[notificationtroubleshooting.DiagnosticsResponse]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error	"Not Found"
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/{notificationName}/diagnostics [get]
func (h *NotificationsHandler) GetNotificationDiagnostics(ctx echo.Context) error {
	response, err := h.troubleshooting.Diagnostics(ctx.Request().Context(), ctx.Param("notificationName"))
	if err != nil {
		if notificationtroubleshooting.IsUnsupportedNotificationName(err) {
			return ctx.JSON(http.StatusNotFound, api.NotFound())
		}
		h.sugar.Errorw("Failed to get notification diagnostics", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[notificationtroubleshooting.DiagnosticsResponse]{Data: response})
}

// SendTestNotification godoc
//
//	@Summary		Enqueue fixed test notification
//	@Description	Enqueues a fixed server-side test notification to a validated admin-supplied destination
//	@Tags			Notifications
//	@Accept			json
//	@Produce		json
//	@Param			request	body		handler.testNotificationRequest	true	"Test destination"
//	@Success		202		{object}	handler.GenericDataResponse[handler.testNotificationResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Failure		503		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/test [post]
func (h *NotificationsHandler) SendTestNotification(ctx echo.Context) error {
	if h.enqueuer == nil || !h.enqueuer.IsStarted() {
		return ctx.JSON(http.StatusServiceUnavailable, api.NewError(errors.New("notification worker enqueuer is not available")))
	}

	var req testNotificationRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind test notification request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "enqueue"
	}
	if mode != "enqueue" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("unsupported test notification mode")))
	}

	provider, ok := notification.NormalizeDeliveryChannel(req.ProviderType)
	if !ok || (provider != notification.DeliveryChannelEmail && provider != notification.DeliveryChannelSlack) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("unsupported notification provider %q", req.ProviderType)))
	}
	target, err := h.buildTarget(provider, req.DestinationTarget)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	metadata := notification.TransportMetadata{
		NotificationKind: notification.Kind("admin_test_notification"),
		Provider:         provider,
		Channel:          provider,
		Target:           req.DestinationTarget,
		CorrelationID:    "admin-test-notification:" + time.Now().UTC().Format(time.RFC3339Nano),
		SourceJobKind:    "admin_test_notification",
	}
	var jobIDs []int64
	switch provider {
	case notification.DeliveryChannelEmail:
		jobIDs, err = h.enqueuer.EnqueueNotificationEmail(ctx.Request().Context(), emailprovider.Delivery{
			To: target.Address[emailprovider.AddressKeyEmail],
			Content: emailprovider.Content{
				From:     h.defaultTestEmailFrom(),
				Subject:  "Compliance Framework test notification",
				TextBody: "This is a fixed test notification from Compliance Framework.",
			},
			Metadata: metadata,
		})
	case notification.DeliveryChannelSlack:
		jobIDs, err = h.enqueuer.EnqueueNotificationSlack(ctx.Request().Context(), slackprovider.Delivery{
			Channel:    target.Address[slackprovider.AddressKeyChannel],
			TargetType: target.Address[slackprovider.AddressKeyTargetType],
			Content: slackprovider.Content{
				Text: "Compliance Framework test notification.",
			},
			Metadata: metadata,
		})
	}
	if err != nil {
		h.sugar.Errorw("Failed to enqueue test notification", "error", err, "provider", provider)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusAccepted, GenericDataResponse[testNotificationResponse]{Data: testNotificationResponse{
		Accepted:          true,
		Mode:              mode,
		ProviderType:      provider,
		DestinationTarget: req.DestinationTarget,
		JobIDs:            jobIDs,
		Message:           "Test notification enqueued. Use jobIds to inspect deliveries.",
	}})
}

// ListNotificationProviders godoc
//
//	@Summary		List available notification providers
//	@Description	Returns notification providers registered in the backend
//	@Tags			Notifications
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[handler.availableNotificationProviderResponse]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/providers [get]
func (h *NotificationsHandler) ListNotificationProviders(ctx echo.Context) error {
	catalog, ok := h.providers.(notification.ProviderCatalog)
	if !ok {
		err := errors.New("notification provider catalog is not configured")
		h.sugar.Errorw("Failed to list notification providers", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	providers := catalog.Providers()
	response := make([]availableNotificationProviderResponse, 0, len(providers))
	for _, provider := range providers {
		response = append(response, availableNotificationProviderResponse{
			ProviderType: provider.ProviderType,
			DisplayName:  provider.DisplayName,
			Description:  provider.Description,
			Enabled:      provider.Enabled,
			Error:        provider.Error,
			Metadata:     provider.Metadata,
		})
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[availableNotificationProviderResponse]{Data: response})
}

// ListNotificationProviderStatus godoc
//
//	@Summary		List notification provider status
//	@Description	Returns notification provider availability for authenticated users
//	@Tags			Notifications
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[handler.notificationProviderStatusResponse]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/notifications/providers [get]
func (h *NotificationsHandler) ListNotificationProviderStatus(ctx echo.Context) error {
	catalog, ok := h.providers.(notification.ProviderCatalog)
	if !ok {
		err := errors.New("notification provider catalog is not configured")
		h.sugar.Errorw("Failed to list notification provider status", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	providers := catalog.Providers()
	response := make([]notificationProviderStatusResponse, 0, len(providers))
	for _, provider := range providers {
		response = append(response, notificationProviderStatusResponse{
			ProviderType: provider.ProviderType,
			Enabled:      provider.Enabled,
		})
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[notificationProviderStatusResponse]{Data: response})
}

// ListSystemNotifications godoc
//
//	@Summary		List system notification destinations
//	@Description	Returns system notification destination configurations for admin management
//	@Tags			Notifications
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[handler.systemNotificationResponse]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications [get]
func (h *NotificationsHandler) ListSystemNotifications(ctx echo.Context) error {
	var rows []relational.SystemNotificationDestination
	if err := h.db.WithContext(ctx.Request().Context()).
		Order("notification_type ASC, provider ASC, created_at ASC").
		Find(&rows).Error; err != nil {
		h.sugar.Errorw("Failed to list system notification destinations", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	configsByName := make(map[string][]configuredSystemDestinationResponse)
	seenDestinations := make(map[string]struct{})

	for i := range rows {
		name, ok := notification.NormalizeSystemNotificationName(rows[i].NotificationType)
		if !ok {
			err := fmt.Errorf("unsupported notification type %q", rows[i].NotificationType)
			h.sugar.Errorw("Invalid configured system notification type", "error", err, "notificationType", rows[i].NotificationType)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		destination, err := h.destinationResponseForRecord(rows[i])
		if err != nil {
			h.sugar.Errorw(
				"Invalid configured system notification destination",
				"error", err,
				"notificationType", name,
				"provider", rows[i].Provider,
			)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		destinationKey := name + ":" + destination.ProviderType + ":" + strings.ToLower(strings.TrimSpace(destination.DestinationTarget))
		if _, exists := seenDestinations[destinationKey]; exists {
			continue
		}
		seenDestinations[destinationKey] = struct{}{}

		configsByName[name] = append(configsByName[name], destination)
	}

	orderedNames := make([]string, 0, len(configsByName))
	for name := range configsByName {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)

	response := make([]systemNotificationResponse, 0, len(orderedNames))
	for _, name := range orderedNames {
		destinations := append([]configuredSystemDestinationResponse(nil), configsByName[name]...)
		sort.Slice(destinations, func(i, j int) bool {
			if destinations[i].ProviderType == destinations[j].ProviderType {
				return destinations[i].DestinationTarget < destinations[j].DestinationTarget
			}
			return destinations[i].ProviderType < destinations[j].ProviderType
		})

		response = append(response, systemNotificationResponse{
			Name:                   strings.ToUpper(name),
			ConfiguredDestinations: destinations,
		})
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[systemNotificationResponse]{Data: response})
}

// CreateSystemNotificationDestination godoc
//
//	@Summary		Create system notification destination
//	@Description	Creates a new system notification destination configuration for an admin-managed notification
//	@Tags			Notifications
//	@Accept			json
//	@Produce		json
//	@Param			notificationName	path		string												true	"Notification name"
//	@Param			destination			body		handler.createSystemNotificationDestinationRequest	true	"Destination details"
//	@Success		201					{object}	handler.GenericDataResponse[handler.configuredSystemDestinationResponse]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		409					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/{notificationName}/destinations [post]
func (h *NotificationsHandler) CreateSystemNotificationDestination(ctx echo.Context) error {
	notificationName := ctx.Param("notificationName")
	canonicalType, ok := notification.NormalizeSystemNotificationName(notificationName)
	if !ok {
		err := fmt.Errorf("unsupported notification type %q", notificationName)
		h.sugar.Warnw("Invalid system notification type", "error", err, "notificationName", notificationName)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req createSystemNotificationDestinationRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind create system notification destination request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	provider, ok := notification.NormalizeDeliveryChannel(req.ProviderType)
	if !ok {
		err := fmt.Errorf("unsupported notification provider %q", req.ProviderType)
		h.sugar.Warnw("Invalid system notification provider", "error", err, "providerType", req.ProviderType)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	target, err := h.buildTarget(provider, req.DestinationTarget)
	if err != nil {
		h.sugar.Warnw(
			"Invalid system notification destination target",
			"error", err,
			"provider", provider,
			"notificationType", canonicalType,
		)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	exists, err := h.destinationExists(ctx.Request().Context(), canonicalType, target)
	if err != nil {
		h.sugar.Errorw(
			"Failed to check existing system notification destinations",
			"error", err,
			"provider", provider,
			"notificationType", canonicalType,
		)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if exists {
		return ctx.JSON(
			http.StatusConflict,
			api.NewError(errors.New("destination already configured for this notification")),
		)
	}

	row := relational.SystemNotificationDestination{
		NotificationType: canonicalType,
		Provider:         provider,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: target.Address,
		}),
	}
	if err := h.db.WithContext(ctx.Request().Context()).Create(&row).Error; err != nil {
		h.sugar.Errorw(
			"Failed to create system notification destination",
			"error", err,
			"provider", provider,
			"notificationType", canonicalType,
		)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response, err := h.destinationResponseForTarget(target)
	if err != nil {
		h.sugar.Errorw(
			"Failed to build created system notification destination response",
			"error", err,
			"provider", provider,
			"notificationType", canonicalType,
		)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[configuredSystemDestinationResponse]{Data: response})
}

// DeleteSystemNotificationDestination godoc
//
//	@Summary		Delete system notification destination
//	@Description	Deletes a stored system notification destination configuration for an admin-managed notification
//	@Tags			Notifications
//	@Accept			json
//	@Produce		json
//	@Param			notificationName	path		string												true	"Notification name"
//	@Param			destination			body		handler.createSystemNotificationDestinationRequest	true	"Destination details"
//	@Success		204					{object}	nil
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/{notificationName}/destinations [delete]
func (h *NotificationsHandler) DeleteSystemNotificationDestination(ctx echo.Context) error {
	notificationName := ctx.Param("notificationName")
	canonicalType, ok := notification.NormalizeSystemNotificationName(notificationName)
	if !ok {
		err := fmt.Errorf("unsupported notification type %q", notificationName)
		h.sugar.Warnw("Invalid system notification type", "error", err, "notificationName", notificationName)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req createSystemNotificationDestinationRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind delete system notification destination request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	provider, ok := notification.NormalizeDeliveryChannel(req.ProviderType)
	if !ok {
		err := fmt.Errorf("unsupported notification provider %q", req.ProviderType)
		h.sugar.Warnw("Invalid system notification provider", "error", err, "providerType", req.ProviderType)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	target, err := h.buildTarget(provider, req.DestinationTarget)
	if err != nil {
		h.sugar.Warnw(
			"Invalid system notification destination target",
			"error", err,
			"provider", provider,
			"notificationType", canonicalType,
		)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	rows, err := h.findDestinationRows(ctx.Request().Context(), canonicalType, target)
	if err != nil {
		h.sugar.Errorw(
			"Failed to find system notification destinations for delete",
			"error", err,
			"provider", provider,
			"notificationType", canonicalType,
		)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if len(rows) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NotFoundCustomMsg("configured notification destination not found"))
	}

	if err := h.db.WithContext(ctx.Request().Context()).Transaction(func(tx *gorm.DB) error {
		for i := range rows {
			if err := tx.Delete(&rows[i]).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.sugar.Errorw(
			"Failed to delete system notification destination",
			"error", err,
			"provider", provider,
			"notificationType", canonicalType,
		)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (h *NotificationsHandler) destinationResponseForRecord(record relational.SystemNotificationDestination) (configuredSystemDestinationResponse, error) {
	target, err := h.targetForRecord(record)
	if err != nil {
		return configuredSystemDestinationResponse{}, err
	}

	return h.destinationResponseForTarget(target)
}

func (h *NotificationsHandler) destinationResponseForTarget(target notification.Target) (configuredSystemDestinationResponse, error) {
	provider, ok := notification.NormalizeDeliveryChannel(target.Provider)
	if !ok {
		return configuredSystemDestinationResponse{}, fmt.Errorf("unsupported notification provider %q", target.Provider)
	}

	configurator, ok := notification.LookupTargetConfigurator(h.providers, provider)
	if !ok {
		return configuredSystemDestinationResponse{}, fmt.Errorf("unsupported notification provider %q", provider)
	}

	destinationTarget, err := configurator.DisplayTarget(target)
	if err != nil {
		return configuredSystemDestinationResponse{}, err
	}

	return configuredSystemDestinationResponse{
		ProviderType:      provider,
		DestinationTarget: destinationTarget,
	}, nil
}

func (h *NotificationsHandler) targetForRecord(record relational.SystemNotificationDestination) (notification.Target, error) {
	provider, ok := notification.NormalizeDeliveryChannel(record.Provider)
	if !ok {
		return notification.Target{}, fmt.Errorf("unsupported notification provider %q", record.Provider)
	}

	configurator, ok := notification.LookupTargetConfigurator(h.providers, provider)
	if !ok {
		return notification.Target{}, fmt.Errorf("unsupported notification provider %q", provider)
	}

	target, err := configurator.NormalizeTarget(notification.Target{
		Provider: provider,
		Address:  record.Target.Data().Address,
	})
	if err != nil {
		return notification.Target{}, err
	}

	return target, nil
}

func (h *NotificationsHandler) buildTarget(provider string, rawTarget string) (notification.Target, error) {
	configurator, ok := notification.LookupTargetConfigurator(h.providers, provider)
	if !ok {
		return notification.Target{}, fmt.Errorf("unsupported notification provider %q", provider)
	}

	return configurator.BuildTarget(rawTarget)
}

func (h *NotificationsHandler) destinationExists(ctx context.Context, notificationType string, target notification.Target) (bool, error) {
	rows, err := h.findDestinationRows(ctx, notificationType, target)
	if err != nil {
		return false, err
	}

	return len(rows) > 0, nil
}

func (h *NotificationsHandler) findDestinationRows(ctx context.Context, notificationType string, target notification.Target) ([]relational.SystemNotificationDestination, error) {
	provider, ok := notification.NormalizeDeliveryChannel(target.Provider)
	if !ok {
		return nil, fmt.Errorf("unsupported notification provider %q", target.Provider)
	}

	var rows []relational.SystemNotificationDestination
	if err := h.db.WithContext(ctx).
		Where("notification_type = ? AND provider = ?", notificationType, provider).
		Find(&rows).Error; err != nil {
		return nil, err
	}

	matches := make([]relational.SystemNotificationDestination, 0, len(rows))
	for i := range rows {
		existingTarget, err := h.targetForRecord(rows[i])
		if err != nil {
			return nil, err
		}

		match, err := h.targetsMatch(existingTarget, target)
		if err != nil {
			return nil, err
		}
		if match {
			matches = append(matches, rows[i])
		}
	}

	return matches, nil
}

func (h *NotificationsHandler) targetsMatch(left notification.Target, right notification.Target) (bool, error) {
	if reflect.DeepEqual(left.Address, right.Address) {
		return true, nil
	}

	leftResponse, err := h.destinationResponseForTarget(left)
	if err != nil {
		return false, err
	}
	rightResponse, err := h.destinationResponseForTarget(right)
	if err != nil {
		return false, err
	}

	if leftResponse.ProviderType != rightResponse.ProviderType {
		return false, nil
	}

	return strings.EqualFold(leftResponse.DestinationTarget, rightResponse.DestinationTarget), nil
}

func parseTroubleshootingJobsQuery(ctx echo.Context) (notificationtroubleshooting.JobsQuery, error) {
	query := notificationtroubleshooting.JobsQuery{
		Queues:           ctx.QueryParams()["queue"],
		Provider:         strings.TrimSpace(ctx.QueryParam("provider")),
		NotificationKind: strings.TrimSpace(ctx.QueryParam("notificationKind")),
		States:           ctx.QueryParams()["state"],
		Cursor:           strings.TrimSpace(ctx.QueryParam("cursor")),
	}
	if since := strings.TrimSpace(ctx.QueryParam("since")); since != "" {
		parsed, err := time.Parse(time.RFC3339, since)
		if err != nil {
			return query, fmt.Errorf("since must be an RFC3339 timestamp")
		}
		query.Since = &parsed
	}
	if limit := strings.TrimSpace(ctx.QueryParam("limit")); limit != "" {
		parsed, err := strconv.Atoi(limit)
		if err != nil {
			return query, fmt.Errorf("limit must be an integer")
		}
		query.Limit = parsed
	}
	return query, nil
}

func (h *NotificationsHandler) defaultTestEmailFrom() string {
	if h.cfg != nil && h.cfg.Email != nil {
		if provider := h.cfg.Email.GetDefaultProvider(); provider != nil {
			if from := emailFromAddress(provider); from != "" {
				return from
			}
		}
	}
	return "noreply@localhost"
}

func emailFromAddress(provider config.EmailProviderSettings) string {
	switch typed := provider.(type) {
	case *config.SMTPConfig:
		return strings.TrimSpace(typed.From)
	case *config.SESConfig:
		return strings.TrimSpace(typed.From)
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}
