package notification

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserSubscription struct {
	NotificationType string
	Channels         []string
}

type User struct {
	ID            string
	Email         string
	FirstName     string
	LastName      string
	SlackUserID   string
	Subscriptions []UserSubscription
}

func (u User) FullName() string {
	if strings.TrimSpace(u.LastName) == "" {
		return strings.TrimSpace(u.FirstName)
	}
	return strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName)
}

func (u User) NotificationChannels(notificationType string) []string {
	normalizedType, ok := NormalizeNotificationType(notificationType)
	if !ok {
		return nil
	}

	seen := make(map[string]struct{})
	channels := make([]string, 0)
	for _, subscription := range u.Subscriptions {
		currentType, typeOK := NormalizeNotificationType(subscription.NotificationType)
		if !typeOK || currentType != normalizedType {
			continue
		}

		for _, candidate := range subscription.Channels {
			channel, channelOK := NormalizeDeliveryChannel(candidate)
			if !channelOK {
				continue
			}
			if _, exists := seen[channel]; exists {
				continue
			}
			seen[channel] = struct{}{}
			channels = append(channels, channel)
		}
	}

	return channels
}

type UserRepository interface {
	FindUserByID(ctx context.Context, userID string) (User, error)
	ListActiveUsersByNotificationType(ctx context.Context, notificationType string) ([]User, error)
}

type GORMUserRepository struct {
	db *gorm.DB
}

func NewGORMUserRepository(db *gorm.DB) *GORMUserRepository {
	return &GORMUserRepository{db: db}
}

func (r *GORMUserRepository) FindUserByID(ctx context.Context, userID string) (User, error) {
	parsedID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return User{}, fmt.Errorf("invalid user id %q: %w", userID, err)
	}

	var record relational.User
	if err := r.db.WithContext(ctx).First(&record, parsedID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return User{}, fmt.Errorf("user %s not found: %w", userID, gorm.ErrRecordNotFound)
		}
		return User{}, fmt.Errorf("failed to fetch user %s: %w", userID, err)
	}

	var subscriptions []relational.UserNotificationSubscription
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", record.ID.String()).
		Find(&subscriptions).Error; err != nil {
		return User{}, fmt.Errorf("failed to fetch notification subscriptions for user %s: %w", userID, err)
	}

	var slackLink relational.SlackUserLink
	var slackUserID string
	err = r.db.WithContext(ctx).
		Where("user_id = ?", record.ID.String()).
		First(&slackLink).Error
	if err == nil {
		slackUserID = slackLink.SlackUserID
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return User{}, fmt.Errorf("failed to fetch slack user link for user %s: %w", userID, err)
	}

	out := make([]UserSubscription, 0, len(subscriptions))
	for i := range subscriptions {
		channels := make([]string, len(subscriptions[i].Channels))
		copy(channels, subscriptions[i].Channels)

		out = append(out, UserSubscription{
			NotificationType: subscriptions[i].NotificationType,
			Channels:         channels,
		})
	}

	return User{
		ID:            record.ID.String(),
		Email:         record.Email,
		FirstName:     record.FirstName,
		LastName:      record.LastName,
		SlackUserID:   slackUserID,
		Subscriptions: out,
	}, nil
}

func (r *GORMUserRepository) ListActiveUsersByNotificationType(ctx context.Context, notificationType string) ([]User, error) {
	canonicalType, ok := NormalizeNotificationType(notificationType)
	if !ok {
		return []User{}, nil
	}

	var subscriptions []relational.UserNotificationSubscription
	if err := r.db.WithContext(ctx).
		Where("notification_type = ?", canonicalType).
		Find(&subscriptions).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch notification subscriptions for type %s: %w", canonicalType, err)
	}

	userIDSet := make(map[string]struct{}, len(subscriptions))
	for i := range subscriptions {
		userID := strings.TrimSpace(subscriptions[i].UserID)
		if userID == "" {
			continue
		}

		channels, _ := NormalizeDeliveryChannels(subscriptions[i].Channels)
		if len(channels) == 0 {
			continue
		}

		userIDSet[userID] = struct{}{}
	}

	if len(userIDSet) == 0 {
		return []User{}, nil
	}

	userIDs := make([]string, 0, len(userIDSet))
	for userID := range userIDSet {
		userIDs = append(userIDs, userID)
	}

	var records []relational.User
	if err := r.db.WithContext(ctx).
		Where("id IN ?", userIDs).
		Where("is_active = ? AND is_locked = ?", true, false).
		Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch subscribed users for type %s: %w", canonicalType, err)
	}

	var slackLinks []relational.SlackUserLink
	if err := r.db.WithContext(ctx).
		Where("user_id IN ?", userIDs).
		Find(&slackLinks).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch slack user links for type %s: %w", canonicalType, err)
	}

	slackUserIDByUserID := make(map[string]string, len(slackLinks))
	for i := range slackLinks {
		slackUserIDByUserID[slackLinks[i].UserID] = slackLinks[i].SlackUserID
	}

	subscriptionsByUserID := make(map[string][]UserSubscription, len(subscriptions))
	for i := range subscriptions {
		userID := strings.TrimSpace(subscriptions[i].UserID)
		if userID == "" {
			continue
		}

		channels := make([]string, len(subscriptions[i].Channels))
		copy(channels, subscriptions[i].Channels)
		subscriptionsByUserID[userID] = append(subscriptionsByUserID[userID], UserSubscription{
			NotificationType: subscriptions[i].NotificationType,
			Channels:         channels,
		})
	}

	users := make([]User, 0, len(records))
	for i := range records {
		record := records[i]
		userID := record.ID.String()
		users = append(users, User{
			ID:            userID,
			Email:         record.Email,
			FirstName:     record.FirstName,
			LastName:      record.LastName,
			SlackUserID:   strings.TrimSpace(slackUserIDByUserID[userID]),
			Subscriptions: subscriptionsByUserID[userID],
		})
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Email < users[j].Email
	})

	return users, nil
}

type ConfiguredDestinationResolver interface {
	ResolveConfiguredDestination(ctx context.Context, key string) (ConfiguredDestination, error)
}

type ConfigDestinationResolver struct {
	cfg *config.Config
}

func NewConfigDestinationResolver(cfg *config.Config) *ConfigDestinationResolver {
	return &ConfigDestinationResolver{cfg: cfg}
}

func (r *ConfigDestinationResolver) ResolveConfiguredDestination(_ context.Context, key string) (ConfiguredDestination, error) {
	normalizedKey := strings.TrimSpace(key)
	switch normalizedKey {
	case ConfiguredDestinationSlackDigestChannel:
		if r == nil || r.cfg == nil || r.cfg.Slack == nil {
			return ConfiguredDestination{}, fmt.Errorf("%w: %q", ErrConfiguredDestinationNotFound, key)
		}

		channel := strings.TrimSpace(r.cfg.Slack.DigestChannel)
		if channel == "" {
			return ConfiguredDestination{}, fmt.Errorf("%w: %q is empty", ErrConfiguredDestinationNotFound, key)
		}

		return ConfiguredDestination{
			Channel: DeliveryChannelSlack,
			Address: channel,
			Attributes: map[string]string{
				"target_type": SlackTargetChannel,
			},
		}, nil
	default:
		return ConfiguredDestination{}, fmt.Errorf("%w: %q", ErrConfiguredDestinationNotFound, key)
	}
}

type Resolver struct {
	users                  UserRepository
	configuredDestinations ConfiguredDestinationResolver
}

func NewResolver(users UserRepository, configuredDestinations ConfiguredDestinationResolver) *Resolver {
	return &Resolver{
		users:                  users,
		configuredDestinations: configuredDestinations,
	}
}

func (r *Resolver) Resolve(ctx context.Context, request Request, definition Definition) ([]Target, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}

	normalizedDefinition, err := definition.normalized()
	if err != nil {
		return nil, err
	}

	requestedChannel, ok := normalizeRequestedChannel(request.Options.RequestedChannel)
	if !ok {
		return nil, fmt.Errorf("%w: requested channel %q", ErrUnsupportedChannel, request.Options.RequestedChannel)
	}
	if requestedChannel != "" && !normalizedDefinition.SupportsChannel(requestedChannel) {
		return nil, fmt.Errorf("%w: requested channel %q is not supported for kind %q", ErrUnsupportedChannel, requestedChannel, request.Kind)
	}

	targets := make([]Target, 0)
	seen := make(map[string]struct{})

	for i := range request.Audiences {
		resolved, err := r.resolveAudience(ctx, request.Audiences[i], request.Options, normalizedDefinition)
		if err != nil {
			return nil, fmt.Errorf("resolve audience %d: %w", i, err)
		}

		for _, target := range resolved {
			if err := target.Validate(); err != nil {
				return nil, err
			}
			key := target.dedupKey()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			targets = append(targets, target)
		}
	}

	return targets, nil
}

func (r *Resolver) ListSubscribedUsers(ctx context.Context, definition Definition) ([]User, error) {
	if r == nil || r.users == nil {
		return nil, ErrResolverNotConfigured
	}

	normalizedDefinition, err := definition.normalized()
	if err != nil {
		return nil, err
	}
	if normalizedDefinition.SubscriptionType == "" {
		return nil, ErrMissingSubscriptionType
	}

	return r.users.ListActiveUsersByNotificationType(ctx, normalizedDefinition.SubscriptionType)
}

func (r *Resolver) resolveAudience(ctx context.Context, audience Audience, options DispatchOptions, definition Definition) ([]Target, error) {
	switch {
	case audience.User != nil:
		if r == nil || r.users == nil {
			return nil, ErrResolverNotConfigured
		}
		return r.resolveUserAudience(ctx, *audience.User, options, definition)
	case audience.DirectEmail != nil:
		return r.resolveDirectEmailAudience(*audience.DirectEmail, options, definition)
	case audience.DirectSlack != nil:
		return r.resolveDirectSlackAudience(*audience.DirectSlack, options, definition)
	case audience.ConfiguredDestination != nil:
		if r == nil || r.configuredDestinations == nil {
			return nil, ErrResolverNotConfigured
		}
		return r.resolveConfiguredDestinationAudience(ctx, *audience.ConfiguredDestination, options, definition)
	default:
		return nil, fmt.Errorf("%w: no audience mode set", ErrInvalidAudience)
	}
}

func (r *Resolver) resolveUserAudience(ctx context.Context, audience UserAudience, options DispatchOptions, definition Definition) ([]Target, error) {
	user, err := r.users.FindUserByID(ctx, audience.UserID)
	if err != nil {
		return nil, err
	}

	return r.resolveUser(user, options, definition)
}

func (r *Resolver) ResolveUser(user User, options DispatchOptions, definition Definition) ([]Target, error) {
	normalizedDefinition, err := definition.normalized()
	if err != nil {
		return nil, err
	}
	return r.resolveUser(user, options, normalizedDefinition)
}

func (r *Resolver) resolveUser(user User, options DispatchOptions, definition Definition) ([]Target, error) {

	if definition.SubscriptionType == "" {
		return nil, ErrMissingSubscriptionType
	}

	channels := user.NotificationChannels(definition.SubscriptionType)
	channels = applyRequestedChannelFilter(channels, options.RequestedChannel)
	if len(channels) == 0 {
		return nil, nil
	}

	targets := make([]Target, 0, len(channels))
	for _, channel := range channels {
		switch channel {
		case DeliveryChannelEmail:
			email := strings.TrimSpace(user.Email)
			if email == "" {
				continue
			}
			targets = append(targets, Target{
				Channel: DeliveryChannelEmail,
				UserID:  user.ID,
				Address: email,
			})
		case DeliveryChannelSlack:
			slackUserID := strings.TrimSpace(user.SlackUserID)
			if slackUserID == "" {
				continue
			}
			targets = append(targets, Target{
				Channel: DeliveryChannelSlack,
				UserID:  user.ID,
				Address: slackUserID,
				Attributes: map[string]string{
					"target_type": SlackTargetDirectMessage,
				},
			})
		}
	}

	return targets, nil
}

func (r *Resolver) resolveDirectEmailAudience(audience DirectEmailAudience, options DispatchOptions, definition Definition) ([]Target, error) {
	if !definition.SupportsChannel(DeliveryChannelEmail) {
		return nil, nil
	}
	if !matchesRequestedChannel(DeliveryChannelEmail, options.RequestedChannel) {
		return nil, nil
	}

	return []Target{{
		Channel: DeliveryChannelEmail,
		Address: strings.TrimSpace(audience.Email),
	}}, nil
}

func (r *Resolver) resolveDirectSlackAudience(audience DirectSlackAudience, options DispatchOptions, definition Definition) ([]Target, error) {
	if !definition.SupportsChannel(DeliveryChannelSlack) {
		return nil, nil
	}
	if !matchesRequestedChannel(DeliveryChannelSlack, options.RequestedChannel) {
		return nil, nil
	}

	targetType := SlackTargetChannel
	if normalizedTargetType, ok := NormalizeSlackTarget(audience.TargetType); ok {
		targetType = normalizedTargetType
	}

	return []Target{{
		Channel: DeliveryChannelSlack,
		Address: strings.TrimSpace(audience.Channel),
		Attributes: map[string]string{
			"target_type": targetType,
		},
	}}, nil
}

func (r *Resolver) resolveConfiguredDestinationAudience(ctx context.Context, audience ConfiguredDestinationAudience, options DispatchOptions, definition Definition) ([]Target, error) {
	destination, err := r.configuredDestinations.ResolveConfiguredDestination(ctx, audience.Key)
	if err != nil {
		return nil, err
	}
	if err := destination.Validate(); err != nil {
		return nil, err
	}
	if !definition.SupportsChannel(destination.Channel) {
		return nil, nil
	}
	if !matchesRequestedChannel(destination.Channel, options.RequestedChannel) {
		return nil, nil
	}

	return []Target{{
		Channel:    destination.Channel,
		Address:    strings.TrimSpace(destination.Address),
		Attributes: destination.Attributes,
	}}, nil
}

func normalizeRequestedChannel(channel string) (string, bool) {
	if strings.TrimSpace(channel) == "" {
		return "", true
	}
	return NormalizeDeliveryChannel(channel)
}

func applyRequestedChannelFilter(channels []string, requestedChannel string) []string {
	normalizedRequested, ok := normalizeRequestedChannel(requestedChannel)
	if !ok {
		return nil
	}
	if normalizedRequested == "" {
		return append([]string(nil), channels...)
	}
	if !slices.Contains(channels, normalizedRequested) {
		return nil
	}
	return []string{normalizedRequested}
}

func matchesRequestedChannel(channel, requested string) bool {
	normalizedRequested, ok := normalizeRequestedChannel(requested)
	if !ok {
		return false
	}
	return normalizedRequested == "" || channel == normalizedRequested
}
