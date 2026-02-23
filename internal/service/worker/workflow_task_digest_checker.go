package worker

import (
	"context"
	"fmt"
	"time"

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

// Work queries all users with TaskDailyDigestSubscribed=true and enqueues a WorkflowTaskDigestArgs job for each
func (w *WorkflowTaskDigestCheckerWorker) Work(ctx context.Context, job *river.Job[WorkflowTaskDigestCheckerArgs]) error {
	if w.db == nil {
		return fmt.Errorf("WorkflowTaskDigestCheckerWorker: db is nil")
	}

	var users []relational.User
	if err := w.db.WithContext(ctx).
		Where("task_daily_digest_subscribed = ? AND deleted_at IS NULL", true).
		Find(&users).Error; err != nil {
		return fmt.Errorf("workflow-task-digest-checker: failed to query subscribed users: %w", err)
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
