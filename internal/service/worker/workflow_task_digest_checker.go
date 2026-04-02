package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// WorkflowTaskDigestCheckerArgs represents the arguments for the periodic digest checker job
type WorkflowTaskDigestCheckerArgs struct{}

// Kind returns the job kind for River
func (WorkflowTaskDigestCheckerArgs) Kind() string { return "workflow_task_digest_checker" }

// Timeout returns the timeout for the digest checker job
func (WorkflowTaskDigestCheckerArgs) Timeout() time.Duration { return 5 * time.Minute }

// WorkflowTaskDigestCheckerWorker queries all subscribed users and enqueues per-user digest jobs
type WorkflowTaskDigestCheckerWorker struct {
	db     *gorm.DB
	client workflow.RiverClient
	logger *zap.SugaredLogger
}

// NewWorkflowTaskDigestCheckerWorker creates a new WorkflowTaskDigestCheckerWorker
func NewWorkflowTaskDigestCheckerWorker(db *gorm.DB, client workflow.RiverClient, logger *zap.SugaredLogger) *WorkflowTaskDigestCheckerWorker {
	return &WorkflowTaskDigestCheckerWorker{
		db:     db,
		client: client,
		logger: logger,
	}
}

// Work queries all users subscribed to task daily digest and enqueues a WorkflowTaskDigestArgs job for each.
func (w *WorkflowTaskDigestCheckerWorker) Work(ctx context.Context, job *river.Job[WorkflowTaskDigestCheckerArgs]) error {
	if w.db == nil {
		return fmt.Errorf("WorkflowTaskDigestCheckerWorker: db is nil")
	}

	var subscriptions []relational.UserNotificationSubscription
	if err := w.db.WithContext(ctx).
		Where("notification_type = ?", notification.NotificationTypeTaskDailyDigest).
		Find(&subscriptions).Error; err != nil {
		return fmt.Errorf("workflow-task-digest-checker: failed to query task daily digest subscriptions: %w", err)
	}

	subscribedUserIDs := make(map[string]struct{}, len(subscriptions))
	for i := range subscriptions {
		userID := strings.TrimSpace(subscriptions[i].UserID)
		if userID == "" {
			continue
		}

		normalizedChannels, invalidChannels := notification.NormalizeDeliveryChannels(subscriptions[i].Channels)
		if len(invalidChannels) > 0 {
			w.logger.Warnw(
				"WorkflowTaskDigestCheckerWorker: ignoring invalid delivery channels in task daily digest subscription",
				"user_id", userID,
				"invalid_channels", invalidChannels,
				"channels", subscriptions[i].Channels,
			)
		}
		if len(normalizedChannels) == 0 {
			continue
		}

		subscribedUserIDs[userID] = struct{}{}
	}

	if len(subscribedUserIDs) == 0 {
		w.logger.Infow("WorkflowTaskDigestCheckerWorker: no subscribed users found")
		return nil
	}

	userIDs := make([]string, 0, len(subscribedUserIDs))
	for userID := range subscribedUserIDs {
		userIDs = append(userIDs, userID)
	}

	var users []relational.User
	if err := w.db.WithContext(ctx).
		Select("id").
		Where("id IN ?", userIDs).
		Find(&users).Error; err != nil {
		return fmt.Errorf("workflow-task-digest-checker: failed to load subscribed users: %w", err)
	}

	if len(users) == 0 {
		w.logger.Infow("WorkflowTaskDigestCheckerWorker: no subscribed users found")
		return nil
	}

	params := make([]river.InsertManyParams, 0, len(users))
	for i := range users {
		if users[i].ID == nil {
			continue
		}
		params = append(params, river.InsertManyParams{
			Args: WorkflowTaskDigestArgs{UserID: users[i].ID.String()},
			InsertOpts: &river.InsertOpts{
				Queue:       "digest",
				MaxAttempts: 3,
			},
		})
	}

	if len(params) == 0 {
		return nil
	}

	results, err := w.client.InsertMany(ctx, params)
	if err != nil {
		return fmt.Errorf("workflow-task-digest-checker: failed to enqueue digest jobs: %w", err)
	}

	inserted := 0
	for _, r := range results {
		if r != nil && r.Job != nil {
			inserted++
		}
	}

	w.logger.Infow("WorkflowTaskDigestCheckerWorker: enqueued digest jobs",
		"total_users", len(users),
		"enqueued", inserted,
	)
	return nil
}
