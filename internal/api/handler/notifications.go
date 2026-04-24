package handler

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
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

func NewNotificationsHandler(sugar *zap.SugaredLogger, db *gorm.DB) *NotificationsHandler {
	return &NotificationsHandler{
		sugar:     sugar,
		db:        db,
		providers: notificationproviders.NewLookup(),
	}
}

func (h *NotificationsHandler) Register(api *echo.Group) {
	api.GET("", h.ListSystemNotifications)
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

func (h *NotificationsHandler) destinationResponseForRecord(record relational.SystemNotificationDestination) (configuredSystemDestinationResponse, error) {
	provider, ok := notification.NormalizeDeliveryChannel(record.Provider)
	if !ok {
		return configuredSystemDestinationResponse{}, fmt.Errorf("unsupported notification provider %q", record.Provider)
	}

	configurator, ok := notification.LookupTargetConfigurator(h.providers, provider)
	if !ok {
		return configuredSystemDestinationResponse{}, fmt.Errorf("unsupported notification provider %q", provider)
	}

	target, err := configurator.NormalizeTarget(notification.Target{
		Provider: provider,
		Address:  record.Target.Data().Address,
	})
	if err != nil {
		return configuredSystemDestinationResponse{}, err
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
