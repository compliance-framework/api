package notification

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

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
	Identities    map[string]map[string]string
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

	out := make([]UserSubscription, 0, len(subscriptions))
	for i := range subscriptions {
		channels := make([]string, len(subscriptions[i].Channels))
		copy(channels, subscriptions[i].Channels)

		out = append(out, UserSubscription{
			NotificationType: subscriptions[i].NotificationType,
			Channels:         channels,
		})
	}

	identitiesByUserID, err := r.loadProviderIdentitiesByUserID(ctx, []string{record.ID.String()})
	if err != nil {
		return User{}, fmt.Errorf("failed to fetch notification identities for user %s: %w", userID, err)
	}

	return User{
		ID:            record.ID.String(),
		Email:         record.Email,
		FirstName:     record.FirstName,
		LastName:      record.LastName,
		Identities:    identitiesByUserID[record.ID.String()],
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

	identitiesByUserID, err := r.loadProviderIdentitiesByUserID(ctx, userIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch notification identities for type %s: %w", canonicalType, err)
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
			Identities:    identitiesByUserID[userID],
			Subscriptions: subscriptionsByUserID[userID],
		})
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Email < users[j].Email
	})

	return users, nil
}

func (r *GORMUserRepository) loadProviderIdentitiesByUserID(ctx context.Context, userIDs []string) (map[string]map[string]map[string]string, error) {
	identitiesByUserID := make(map[string]map[string]map[string]string)
	if r == nil || r.db == nil || len(userIDs) == 0 {
		return identitiesByUserID, nil
	}

	var slackLinks []relational.SlackUserLink
	if err := r.db.WithContext(ctx).
		Where("user_id IN ?", userIDs).
		Find(&slackLinks).Error; err != nil {
		return nil, err
	}

	for i := range slackLinks {
		userID := strings.TrimSpace(slackLinks[i].UserID)
		identity := slackDirectMessageIdentity(slackLinks[i].SlackUserID)
		if userID == "" || len(identity) == 0 {
			continue
		}

		if _, exists := identitiesByUserID[userID]; !exists {
			identitiesByUserID[userID] = map[string]map[string]string{}
		}
		identitiesByUserID[userID][DeliveryChannelSlack] = identity
	}

	return identitiesByUserID, nil
}

func slackDirectMessageIdentity(slackUserID string) map[string]string {
	trimmedSlackUserID := strings.TrimSpace(slackUserID)
	if trimmedSlackUserID == "" {
		return nil
	}

	return map[string]string{
		"channel":     trimmedSlackUserID,
		"target_type": "direct_message",
	}
}

type ConfiguredDestinationResolver interface {
	ResolveConfiguredDestination(ctx context.Context, key string) (ConfiguredDestination, error)
}

type Resolver struct {
	users                  UserRepository
	configuredDestinations ConfiguredDestinationResolver
	providers              ProviderLookup
}

func NewResolver(users UserRepository, configuredDestinations ConfiguredDestinationResolver, providers ProviderLookup) *Resolver {
	return &Resolver{
		users:                  users,
		configuredDestinations: configuredDestinations,
		providers:              providers,
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
	case audience.Direct != nil:
		return r.resolveDirectAudience(*audience.Direct, options, definition)
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
		provider, ok := r.provider(channel)
		if !ok {
			if fallback, resolved := legacyUserTarget(channel, user); resolved {
				targets = append(targets, fallback)
			}
			continue
		}

		target, resolved, err := provider.ResolveUserTarget(user)
		if err != nil {
			return nil, err
		}
		if !resolved {
			if fallback, ok := legacyUserTarget(channel, user); ok {
				targets = append(targets, fallback)
			}
			continue
		}
		target.UserID = user.ID
		target.Provider = channel
		targets = append(targets, target)
	}

	return targets, nil
}

func (r *Resolver) resolveDirectAudience(audience DirectAudience, options DispatchOptions, definition Definition) ([]Target, error) {
	provider, ok := NormalizeDeliveryChannel(audience.Provider)
	if !ok {
		return nil, fmt.Errorf("%w: invalid direct audience provider %q", ErrInvalidAudience, audience.Provider)
	}
	if !definition.SupportsChannel(provider) {
		return nil, nil
	}
	if !matchesRequestedChannel(provider, options.RequestedChannel) {
		return nil, nil
	}

	address := make(map[string]string, len(audience.Address))
	for key, value := range audience.Address {
		address[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	return []Target{{
		Provider: provider,
		Address:  address,
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
	if !definition.SupportsChannel(destination.Provider) {
		return nil, nil
	}
	if !matchesRequestedChannel(destination.Provider, options.RequestedChannel) {
		return nil, nil
	}

	address := make(map[string]string, len(destination.Address))
	for key, value := range destination.Address {
		address[key] = strings.TrimSpace(value)
	}

	return []Target{{
		Provider: destination.Provider,
		Address:  address,
	}}, nil
}

func (r *Resolver) provider(providerID string) (Provider, bool) {
	if r == nil || r.providers == nil {
		return nil, false
	}

	return r.providers.Provider(providerID)
}

func legacyUserTarget(provider string, user User) (Target, bool) {
	identityByProvider := user.Identities
	if len(identityByProvider) == 0 {
		return Target{}, false
	}
	identity, ok := identityByProvider[provider]
	if !ok || len(identity) == 0 {
		return Target{}, false
	}

	address := make(map[string]string, len(identity))
	for key, value := range identity {
		address[key] = strings.TrimSpace(value)
	}

	return Target{Provider: provider, UserID: user.ID, Address: address}, true
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
