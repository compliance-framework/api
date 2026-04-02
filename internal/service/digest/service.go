package digest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	"github.com/compliance-framework/api/internal/service/slack/formatters"
	"github.com/compliance-framework/api/internal/service/worker"
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
	db            *gorm.DB
	emailService  *email.Service
	workerService *worker.Service
	config        *config.Config
	logger        *zap.SugaredLogger
}

type DigestRecipient struct {
	User        relational.User
	Channels    []string
	SlackUserID string
}

// NewService creates a new digest service
func NewService(db *gorm.DB, emailService *email.Service, workerService *worker.Service, cfg *config.Config, logger *zap.SugaredLogger) *Service {
	return &Service{
		db:            db,
		emailService:  emailService,
		workerService: workerService,
		config:        cfg,
		logger:        logger,
	}
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

	var slackLinks []relational.SlackUserLink
	if err := s.db.WithContext(ctx).
		Where("user_id IN ?", subscribedUserIDs).
		Find(&slackLinks).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch Slack links for digest recipients: %w", err)
	}
	slackUserIDByUserID := make(map[string]string, len(slackLinks))
	for i := range slackLinks {
		slackUserIDByUserID[slackLinks[i].UserID] = slackLinks[i].SlackUserID
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
			User:        users[i],
			Channels:    channels,
			SlackUserID: strings.TrimSpace(slackUserIDByUserID[userID]),
		})
	}

	return recipients, nil
}

// GetAllActiveUsers returns all active users (for admin purposes)
func (s *Service) GetAllActiveUsers(ctx context.Context) ([]relational.User, error) {
	var users []relational.User
	if err := s.db.Where("is_active = ? AND is_locked = ?", true, false).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch active users: %w", err)
	}
	return users, nil
}

func (s *Service) SendDigestSlack(ctx context.Context, summary *EvidenceSummary) error {
	if s.config == nil || s.config.Slack == nil || !s.config.Slack.Enabled {
		return nil
	}
	if s.config.Slack.DigestChannel == "" {
		s.logger.Warn("Slack is enabled but digest_channel is empty; skipping digest Slack message")
		return nil
	}

	return s.sendDigestSlackToChannel(ctx, s.config.Slack.DigestChannel, summary)
}

func (s *Service) sendDigestSlackToChannel(ctx context.Context, channel string, summary *EvidenceSummary) error {
	if strings.TrimSpace(channel) == "" {
		return fmt.Errorf("slack channel is required")
	}

	slackService, err := slacksvc.NewService(s.config.Slack, s.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Slack service for digest: %w", err)
	}

	data := formatters.DigestSummary{
		TotalCount:        summary.TotalCount,
		SatisfiedCount:    summary.SatisfiedCount,
		NotSatisfiedCount: summary.NotSatisfiedCount,
		ExpiredCount:      summary.ExpiredCount,
		TopExpired:        toSlackDigestEvidence(summary.TopExpired),
		TopNotSatisfied:   toSlackDigestEvidence(summary.TopNotSatisfied),
		BaseURL:           s.config.WebBaseURL,
	}
	message, err := formatters.FormatDigestMessage(&data)
	if err != nil {
		return fmt.Errorf("failed to format Slack message for digest: %w", err)
	}
	_, err = slackService.SendMessage(ctx, channel, message)

	if err != nil {
		return fmt.Errorf("failed to send Slack message for digest: %w", err)
	}
	return nil
}

func toSlackDigestEvidence(items []EvidenceItem) []formatters.DigestSummaryEvidence {
	if len(items) == 0 {
		return nil
	}

	out := make([]formatters.DigestSummaryEvidence, 0, len(items))
	for i := range items {
		out = append(out, formatters.DigestSummaryEvidence{
			ID:          items[i].ID,
			Title:       items[i].Title,
			Description: items[i].Description,
			ExpiresAt:   items[i].ExpiresAt,
		})
	}
	return out
}

// SendDigestEmail sends a digest email to a user
func (s *Service) SendDigestEmail(ctx context.Context, user *relational.User, summary *EvidenceSummary) error {
	if s.emailService == nil || !s.emailService.IsEnabled() {
		return fmt.Errorf("email service is not enabled")
	}

	// Prepare template data
	data := map[string]interface{}{
		"UserName":          user.FirstName,
		"TotalCount":        summary.TotalCount,
		"SatisfiedCount":    summary.SatisfiedCount,
		"NotSatisfiedCount": summary.NotSatisfiedCount,
		"ExpiredCount":      summary.ExpiredCount,
		"TopExpired":        summary.TopExpired,
		"TopNotSatisfied":   summary.TopNotSatisfied,
		"WebBaseURL":        s.config.WebBaseURL,
		"GeneratedAt":       time.Now().UTC().Format(time.RFC1123),
	}

	htmlContent, textContent, err := s.emailService.UseTemplate("evidence-digest", data)
	if err != nil {
		return fmt.Errorf("failed to render digest template: %w", err)
	}

	message := &types.Message{
		To:       []string{user.Email},
		Subject:  "Evidence Compliance Digest",
		HTMLBody: htmlContent,
		TextBody: textContent,
	}

	// Enqueue email job instead of sending directly
	if s.workerService != nil && s.workerService.IsStarted() {
		args := &worker.SendEmailArgs{
			From:     s.getDefaultFromAddress(),
			To:       message.To,
			Subject:  message.Subject,
			HTMLBody: message.HTMLBody,
			TextBody: message.TextBody,
		}

		err = s.workerService.EnqueueSendEmail(ctx, args)
		if err != nil {
			return fmt.Errorf("failed to enqueue digest email: %w", err)
		}

		s.logger.Debugw("Digest email enqueued", "user", user.Email)
	} else {
		// Fallback to direct sending if worker is not available
		result, err := s.emailService.Send(ctx, message)
		if err != nil {
			return fmt.Errorf("failed to send digest email: %w", err)
		}

		if !result.Success {
			return fmt.Errorf("digest email send failed: %s", result.Error)
		}

		s.logger.Debugw("Digest email sent", "user", user.Email, "messageId", result.MessageID)
	}

	return nil
}

// SendGlobalDigest sends the global digest to all active users (Phase 0)
func (s *Service) SendGlobalDigest(ctx context.Context) error {
	summary, err := s.GetGlobalEvidenceSummary(ctx)
	if err != nil {
		return fmt.Errorf("failed to get evidence summary: %w", err)
	}

	if err := s.SendDigestSlack(ctx, summary); err != nil {
		s.logger.Warnw("Failed to send digest to Slack", "error", err)
	}

	// Skip if there's nothing to report
	if summary.TotalCount == 0 {
		s.logger.Debug("No evidence found, skipping digest")
		return nil
	}

	// Skip if there are no issues to report
	if summary.NotSatisfiedCount == 0 && summary.ExpiredCount == 0 {
		s.logger.Debug("No issues found (no expired or not-satisfied evidence), skipping digest")
		return nil
	}

	recipients, err := s.GetDigestRecipients(ctx)
	if err != nil {
		return fmt.Errorf("failed to get digest recipients: %w", err)
	}

	if len(recipients) == 0 {
		s.logger.Debug("No digest recipients found, skipping digest")
		return nil
	}

	s.logger.Debugw("Sending global digest",
		"totalEvidence", summary.TotalCount,
		"notSatisfied", summary.NotSatisfiedCount,
		"expired", summary.ExpiredCount,
		"userCount", len(recipients),
	)

	var sendErrors []error
	for i := range recipients {
		recipient := recipients[i]

		for _, channel := range recipient.Channels {
			switch channel {
			case notification.DeliveryChannelEmail:
				if err := s.SendDigestEmail(ctx, &recipient.User, summary); err != nil {
					s.logger.Errorw("failed to send digest email to user", "user", recipient.User.Email, "error", err)
					sendErrors = append(sendErrors, err)
				}
			case notification.DeliveryChannelSlack:
				if recipient.SlackUserID == "" {
					s.logger.Debugw("skipping digest Slack DM: user has no Slack link",
						"user", recipient.User.Email,
					)
					continue
				}

				if err := s.sendDigestSlackToChannel(ctx, recipient.SlackUserID, summary); err != nil {
					s.logger.Errorw("failed to send digest Slack DM to user",
						"user", recipient.User.Email,
						"slackUserID", recipient.SlackUserID,
						"error", err,
					)
					sendErrors = append(sendErrors, err)
				}
			default:
				s.logger.Debugw("skipping unsupported digest channel",
					"user", recipient.User.Email,
					"channel", channel,
				)
			}
		}
	}

	if len(sendErrors) > 0 {
		return fmt.Errorf("failed to send digest to %d users", len(sendErrors))
	}

	return nil
}

// SetWorkerService sets the worker service reference (used to avoid circular dependency)
func (s *Service) SetWorkerService(workerService *worker.Service) {
	s.workerService = workerService
}

// getDefaultFromAddress returns the default From address from the email service configuration
func (s *Service) getDefaultFromAddress() string {
	if s.emailService == nil {
		return ""
	}
	return s.emailService.GetDefaultFromAddress()
}
