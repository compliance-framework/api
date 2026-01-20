package digest

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/email/types"
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
	db           *gorm.DB
	emailService *email.Service
	config       *config.Config
	logger       *zap.SugaredLogger
}

// NewService creates a new digest service
func NewService(db *gorm.DB, emailService *email.Service, cfg *config.Config, logger *zap.SugaredLogger) *Service {
	return &Service{
		db:           db,
		emailService: emailService,
		config:       cfg,
		logger:       logger,
	}
}

// GetGlobalEvidenceSummary retrieves evidence summary across all evidence (Phase 0)
func (s *Service) GetGlobalEvidenceSummary(ctx context.Context) (*EvidenceSummary, error) {
	summary := &EvidenceSummary{}

	// Get latest evidence streams
	latestQuery := relational.GetLatestEvidenceStreamsQuery(s.db)

	// Count by status
	type StatusCount struct {
		Count  int64  `json:"count"`
		Status string `json:"status"`
	}

	var statusCounts []StatusCount
	if err := s.db.Table("(?) as latest", latestQuery).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&statusCounts).Error; err != nil {
		return nil, fmt.Errorf("failed to count evidence by status: %w", err)
	}

	for _, sc := range statusCounts {
		summary.TotalCount += sc.Count
		switch sc.Status {
		case "satisfied":
			summary.SatisfiedCount = sc.Count
		case "not-satisfied":
			summary.NotSatisfiedCount = sc.Count
		default:
			summary.OtherCount += sc.Count
		}
	}

	// Count expired evidence (expires <= now)
	// Note: Evidence without expiration dates (expires IS NULL) are treated as never expiring
	// and are excluded from the expired count. This maintains backward compatibility with
	// deployments that have evidence without expiration dates.
	now := time.Now()
	expiredCountQuery := s.db.Session(&gorm.Session{})
	expiredCountQuery = relational.GetLatestEvidenceStreamsQuery(expiredCountQuery)
	if err := expiredCountQuery.
		Where("expires IS NOT NULL AND expires <= ?", now).
		Count(&summary.ExpiredCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count expired evidence: %w", err)
	}

	// Get top 5 expired evidence items (only those with explicit expiration dates)
	var expiredEvidence []relational.Evidence
	expiredItemsQuery := s.db.Session(&gorm.Session{})
	expiredItemsQuery = relational.GetLatestEvidenceStreamsQuery(expiredItemsQuery)
	if err := expiredItemsQuery.
		Where("expires IS NOT NULL AND expires <= ?", now).
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
		Order("\"end\" DESC").
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

// GetSubscribedUsers returns all active users who are subscribed to digest emails
func (s *Service) GetSubscribedUsers(ctx context.Context) ([]relational.User, error) {
	var users []relational.User
	if err := s.db.Where("is_active = ? AND is_locked = ? AND digest_subscribed = ?", true, false, true).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch subscribed users: %w", err)
	}
	return users, nil
}

// GetAllActiveUsers returns all active users (for admin purposes)
func (s *Service) GetAllActiveUsers(ctx context.Context) ([]relational.User, error) {
	var users []relational.User
	if err := s.db.Where("is_active = ? AND is_locked = ?", true, false).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch active users: %w", err)
	}
	return users, nil
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

	result, err := s.emailService.Send(ctx, message)
	if err != nil {
		return fmt.Errorf("failed to send digest email: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("digest email send failed: %s", result.Error)
	}

	s.logger.Infow("Digest email sent", "user", user.Email, "messageId", result.MessageID)
	return nil
}

// SendGlobalDigest sends the global digest to all active users (Phase 0)
func (s *Service) SendGlobalDigest(ctx context.Context) error {
	summary, err := s.GetGlobalEvidenceSummary(ctx)
	if err != nil {
		return fmt.Errorf("failed to get evidence summary: %w", err)
	}

	// Skip if there's nothing to report
	if summary.TotalCount == 0 {
		s.logger.Info("No evidence found, skipping digest")
		return nil
	}

	// Skip if there are no issues to report
	if summary.NotSatisfiedCount == 0 && summary.ExpiredCount == 0 {
		s.logger.Info("No issues found (no expired or not-satisfied evidence), skipping digest")
		return nil
	}

	users, err := s.GetSubscribedUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to get subscribed users: %w", err)
	}

	if len(users) == 0 {
		s.logger.Info("No subscribed users found, skipping digest")
		return nil
	}

	s.logger.Infow("Sending global digest",
		"totalEvidence", summary.TotalCount,
		"notSatisfied", summary.NotSatisfiedCount,
		"expired", summary.ExpiredCount,
		"userCount", len(users),
	)

	var sendErrors []error
	for _, user := range users {
		if err := s.SendDigestEmail(ctx, &user, summary); err != nil {
			s.logger.Errorw("Failed to send digest to user", "user", user.Email, "error", err)
			sendErrors = append(sendErrors, err)
		}
	}

	if len(sendErrors) > 0 {
		return fmt.Errorf("failed to send digest to %d users", len(sendErrors))
	}

	return nil
}
