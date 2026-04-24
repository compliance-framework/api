package digest

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// EvidenceSummary contains aggregated evidence statistics
type EvidenceSummary struct {
	TotalCount        int64
	SatisfiedCount    int64
	NotSatisfiedCount int64
	ExpiredCount      int64
	OtherCount        int64

	// Top items for the digest email
	TopExpired      []EvidenceItem
	TopNotSatisfied []EvidenceItem
}

// EvidenceItem represents a single evidence entry for display
type EvidenceItem struct {
	ID          string
	UUID        string
	Title       string
	Description string
	Status      string
	ExpiresAt   string // Formatted expiration date string (empty if no expiration)
	Labels      []string
}

// Service handles digest generation and delivery
type Service struct {
	db       *gorm.DB
	notifier *notification.Service
	config   *config.Config
	logger   *zap.SugaredLogger
}

type DigestRecipient struct {
	User     relational.User
	Channels []string
}

// NewService creates a new digest service.
func NewService(db *gorm.DB, notifier *notification.Service, cfg *config.Config, logger *zap.SugaredLogger) *Service {
	if notifier == nil {
		notifier = notification.NewService(nil, nil, nil)
	}

	service := &Service{
		db:       db,
		notifier: notifier,
		config:   cfg,
		logger:   logger,
	}

	return service
}

// GetGlobalEvidenceSummary retrieves evidence summary across all evidence (Phase 0)
func (s *Service) GetGlobalEvidenceSummary(ctx context.Context) (*EvidenceSummary, error) {
	summary := &EvidenceSummary{}

	// Get latest evidence streams once using CTE to avoid recomputing the subquery multiple times
	now := time.Now()
	zeroTime := time.Unix(0, 0)

	// Create a single CTE query for latest evidence streams with all aggregations
	summaryQuery := s.db.Raw(`
		WITH latest_evidence AS (
			SELECT DISTINCT ON (uuid) *
			FROM evidences
			ORDER BY uuid, evidences.end DESC
		)
		SELECT 
			COUNT(*) as total_count,
			COUNT(CASE WHEN status->>'state' = 'satisfied' THEN 1 END) as satisfied_count,
			COUNT(CASE WHEN status->>'state' = 'not-satisfied' THEN 1 END) as not_satisfied_count,
			COUNT(CASE WHEN status->>'state' NOT IN ('satisfied', 'not-satisfied') THEN 1 END) as other_count,
			COUNT(CASE WHEN expires IS NOT NULL AND expires > ? AND expires <= ? THEN 1 END) as expired_count
		FROM latest_evidence
	`, zeroTime, now)

	var result struct {
		TotalCount        int64
		SatisfiedCount    int64
		NotSatisfiedCount int64
		OtherCount        int64
		ExpiredCount      int64
	}

	if err := summaryQuery.Scan(&result).Error; err != nil {
		return nil, fmt.Errorf("failed to get evidence summary: %w", err)
	}

	summary.TotalCount = result.TotalCount
	summary.SatisfiedCount = result.SatisfiedCount
	summary.NotSatisfiedCount = result.NotSatisfiedCount
	summary.ExpiredCount = result.ExpiredCount
	summary.OtherCount = result.OtherCount

	// Get top 5 expired evidence items (only those with explicit expiration dates, excluding zero time)
	var expiredEvidence []relational.Evidence
	expiredItemsQuery := s.db.Session(&gorm.Session{})
	expiredItemsQuery = relational.GetLatestEvidenceStreamsQuery(expiredItemsQuery)
	if err := expiredItemsQuery.
		Where("expires IS NOT NULL AND expires > ? AND expires <= ?", zeroTime, now).
		Preload("Labels").
		Order("expires ASC").
		Limit(5).
		Find(&expiredEvidence).Error; err != nil {
		s.logger.Warnw("Failed to fetch top expired evidence", "error", err)
	} else {
		summary.TopExpired = s.convertToEvidenceItems(expiredEvidence)
	}

	// Get top 5 not-satisfied evidence items
	var notSatisfiedEvidence []relational.Evidence
	if err := s.db.Table("(?) as latest", relational.GetLatestEvidenceStreamsQuery(s.db)).
		Where("status->>'state' = ?", "not-satisfied").
		Preload("Labels").
		Order("latest.end DESC").
		Limit(5).
		Find(&notSatisfiedEvidence).Error; err != nil {
		s.logger.Warnw("Failed to fetch top not-satisfied evidence", "error", err)
	} else {
		summary.TopNotSatisfied = s.convertToEvidenceItems(notSatisfiedEvidence)
	}

	return summary, nil
}

func (s *Service) convertToEvidenceItems(evidences []relational.Evidence) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(evidences))
	for _, e := range evidences {
		labels := make([]string, 0, len(e.Labels))
		for _, l := range e.Labels {
			labels = append(labels, fmt.Sprintf("%s:%s", l.Name, l.Value))
		}

		status := ""
		if statusData := e.Status.Data(); statusData.State != "" {
			status = statusData.State
		}

		// Format expiration date for display
		expiresAt := ""
		if e.Expires != nil && !e.Expires.IsZero() {
			expiresAt = e.Expires.Format("2006-01-02 15:04 MST")
		}

		items = append(items, EvidenceItem{
			ID:          e.ID.String(),
			UUID:        e.UUID.String(),
			Title:       e.Title,
			Description: e.Description,
			Status:      status,
			ExpiresAt:   expiresAt,
			Labels:      labels,
		})
	}
	return items
}

// GetDigestRecipients returns active users and their evidence-digest channels.
func (s *Service) GetDigestRecipients(ctx context.Context) ([]DigestRecipient, error) {
	var subscriptions []relational.UserNotificationSubscription
	if err := s.db.WithContext(ctx).
		Where("notification_type = ?", notification.NotificationTypeEvidenceDigest).
		Find(&subscriptions).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch evidence digest subscriptions: %w", err)
	}

	channelSetsByUserID := make(map[string]map[string]struct{}, len(subscriptions))
	for i := range subscriptions {
		userID := subscriptions[i].UserID
		if userID == "" {
			continue
		}

		for _, rawChannel := range subscriptions[i].Channels {
			channel, ok := notification.NormalizeDeliveryChannel(rawChannel)
			if !ok {
				continue
			}
			if _, exists := channelSetsByUserID[userID]; !exists {
				channelSetsByUserID[userID] = make(map[string]struct{})
			}
			channelSetsByUserID[userID][channel] = struct{}{}
		}
	}

	if len(channelSetsByUserID) == 0 {
		return []DigestRecipient{}, nil
	}

	subscribedUserIDs := make([]string, 0, len(channelSetsByUserID))
	for userID := range channelSetsByUserID {
		subscribedUserIDs = append(subscribedUserIDs, userID)
	}

	var users []relational.User
	if err := s.db.WithContext(ctx).
		Where("id IN ?", subscribedUserIDs).
		Where("is_active = ? AND is_locked = ?", true, false).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch subscribed users: %w", err)
	}

	recipients := make([]DigestRecipient, 0, len(users))
	for i := range users {
		userID := users[i].ID.String()
		channelSet := channelSetsByUserID[userID]
		if len(channelSet) == 0 {
			continue
		}

		channels := make([]string, 0, len(channelSet))
		for channel := range channelSet {
			channels = append(channels, channel)
		}
		sort.Strings(channels)

		recipients = append(recipients, DigestRecipient{
			User:     users[i],
			Channels: channels,
		})
	}

	return recipients, nil
}

// SendGlobalDigest sends or enqueues the global digest to all active users.
func (s *Service) SendGlobalDigest(ctx context.Context) error {
	summary, err := s.GetGlobalEvidenceSummary(ctx)
	if err != nil {
		return fmt.Errorf("failed to get evidence summary: %w", err)
	}

	sendConfiguredDestinations := s.hasGlobalDigestDestinations(ctx)
	sendUserDigests := summary.TotalCount > 0 && (summary.NotSatisfiedCount > 0 || summary.ExpiredCount > 0)

	if !sendUserDigests {
		if summary.TotalCount == 0 {
			if !sendConfiguredDestinations {
				s.logger.Debug("No evidence found, skipping digest")
				return nil
			}
		} else if !sendConfiguredDestinations {
			s.logger.Debug("No issues found (no expired or not-satisfied evidence), skipping digest")
			return nil
		}
	}

	generatedAt := time.Now().UTC()
	webBaseURL := ""
	if s.config != nil {
		webBaseURL = s.config.WebBaseURL
	}

	if !sendUserDigests {
		return s.dispatchEvidenceDigestNotifications(ctx, summary, webBaseURL, generatedAt, sendConfiguredDestinations, false)
	}

	s.logger.Debugw("Sending global digest",
		"totalEvidence", summary.TotalCount,
		"notSatisfied", summary.NotSatisfiedCount,
		"expired", summary.ExpiredCount,
	)

	return s.dispatchEvidenceDigestNotifications(ctx, summary, webBaseURL, generatedAt, sendConfiguredDestinations, true)
}
