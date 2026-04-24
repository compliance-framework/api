package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type NotificationsHandler struct {
	sugar     *zap.SugaredLogger
	db        *gorm.DB
	providers notification.ProviderLookup
}

type configuredSystemDestinationResponse struct {
	ProviderType      string `json:"providerType"`
	DestinationTarget string `json:"destinationTarget"`
}

type systemNotificationResponse struct {
	Name                   string                                `json:"name"`
	ConfiguredDestinations []configuredSystemDestinationResponse `json:"configuredDestinations"`
}

type createSystemNotificationDestinationRequest struct {
	ProviderType      string `json:"providerType" validate:"required"`
	DestinationTarget string `json:"destinationTarget" validate:"required"`
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

func NewNotificationsHandler(sugar *zap.SugaredLogger, db *gorm.DB) *NotificationsHandler {
	return &NotificationsHandler{
		sugar:     sugar,
		db:        db,
		providers: notificationproviders.NewLookup(),
	}
}

func (h *NotificationsHandler) Register(api *echo.Group) {
	api.GET("", h.ListSystemNotifications)
	api.POST("/:notificationName/destinations", h.CreateSystemNotificationDestination)
	api.DELETE("/:notificationName/destinations", h.DeleteSystemNotificationDestination)
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
		name, ok := notification.NormalizeNotificationType(rows[i].NotificationType)
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

		destinationKey := name + ":" + destination.ProviderType + ":" + destination.DestinationTarget
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
//	@Param			notificationName	path		string													true	"Notification name"
//	@Param			destination			body		handler.createSystemNotificationDestinationRequest		true	"Destination details"
//	@Success		201					{object}	handler.GenericDataResponse[handler.configuredSystemDestinationResponse]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		409					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/{notificationName}/destinations [post]
func (h *NotificationsHandler) CreateSystemNotificationDestination(ctx echo.Context) error {
	notificationName := ctx.Param("notificationName")
	canonicalType, ok := notification.NormalizeNotificationType(notificationName)
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
			api.NewError(errors.New("That destination is already configured for this notification.")),
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
//	@Param			notificationName	path		string													true	"Notification name"
//	@Param			destination			body		handler.createSystemNotificationDestinationRequest		true	"Destination details"
//	@Success		204					{object}	nil
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/notifications/{notificationName}/destinations [delete]
func (h *NotificationsHandler) DeleteSystemNotificationDestination(ctx echo.Context) error {
	notificationName := ctx.Param("notificationName")
	canonicalType, ok := notification.NormalizeNotificationType(notificationName)
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}
