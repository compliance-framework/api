package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ─── Scanner / transition worker ─────────────────────────────────────────────

// PoamOverdueTransitionScannerWorker scans daily for POAM items whose deadline
// has passed and whose status is still open or in-progress. For each such item
// it:
//  1. Transitions the status to "overdue" in the database (with updated_at).
//  2. Enqueues a PoamOverdueNotificationArgs job per item per recipient.
//
// "overdue" is a terminal state that can only be reversed by a manual
// PUT /poam-items/:id status update.
type PoamOverdueTransitionScannerWorker struct {
	db         *gorm.DB
	client     workflow.RiverClient
	webBaseURL string
	userRepo   UserRepository
	logger     *zap.SugaredLogger
}

// NewPoamOverdueTransitionScannerWorker constructs a PoamOverdueTransitionScannerWorker.
func NewPoamOverdueTransitionScannerWorker(
	db *gorm.DB,
	client workflow.RiverClient,
	userRepo UserRepository,
	webBaseURL string,
	logger *zap.SugaredLogger,
) *PoamOverdueTransitionScannerWorker {
	return &PoamOverdueTransitionScannerWorker{
		db:         db,
		client:     client,
		webBaseURL: webBaseURL,
		userRepo:   userRepo,
		logger:     logger,
	}
}

// Work queries for overdue POAM items, transitions their status, and enqueues
// notification jobs.
func (w *PoamOverdueTransitionScannerWorker) Work(
	ctx context.Context,
	job *river.Job[PoamOverdueTransitionScannerArgs],
) error {
	if w.db == nil {
		return fmt.Errorf("PoamOverdueTransitionScannerWorker: db is nil")
	}

	now := time.Now().UTC()
	overdueBucket := now.Format("2006-01-02")

	var items []poam.PoamItem
	if err := w.db.WithContext(ctx).
		Where(
			"status IN ? AND planned_completion_date IS NOT NULL AND planned_completion_date < ?",
			[]string{
				string(poam.PoamItemStatusOpen),
				string(poam.PoamItemStatusInProgress),
			},
			now,
		).
		Find(&items).Error; err != nil {
		return fmt.Errorf("poam overdue transition scanner: query failed: %w", err)
	}

	if len(items) == 0 {
		w.logger.Infow("PoamOverdueTransitionScannerWorker: no overdue items found")
		return nil
	}

	sspNames, err := resolvePoamSSPDisplayNames(ctx, w.db, items)
	if err != nil {
		w.logger.Warnw("PoamOverdueTransitionScannerWorker: failed to resolve SSP names", "error", err)
		sspNames = map[string]string{}
	}

	transitioned := 0
	params := make([]river.InsertManyParams, 0, len(items))

	for i := range items {
		item := &items[i]
		if item.PlannedCompletionDate == nil {
			continue
		}

		// Transition status to overdue in the DB.
		if err := w.db.WithContext(ctx).
			Model(item).
			Updates(map[string]interface{}{
				"status":                string(poam.PoamItemStatusOverdue),
				"last_status_change_at": now,
				"updated_at":            now,
			}).Error; err != nil {
			w.logger.Errorw("PoamOverdueTransitionScannerWorker: failed to transition item to overdue",
				"poam_item_id", item.ID,
				"error", err,
			)
			// Continue processing remaining items rather than aborting the whole scan.
			continue
		}
		transitioned++

		recipients := resolvePoamRecipients(item)
		sspName := sspNames[item.SspID.String()]
		if sspName == "" {
			sspName = item.SspID.String()
		}
		poamURL := resolvePoamURL(w.webBaseURL, item.ID)

		for _, recipientID := range recipients {
			args := PoamOverdueNotificationArgs{
				PoamItemID:      item.ID,
				RecipientUserID: recipientID,
				PoamTitle:       item.Title,
				SspID:           item.SspID,
				SspDisplayName:  sspName,
				Deadline:        item.PlannedCompletionDate.UTC().Format(time.RFC3339),
				PoamURL:         poamURL,
				OverdueWindow:   overdueBucket,
			}
			params = append(params, river.InsertManyParams{
				Args:       args,
				InsertOpts: JobInsertOptionsForPoamNotification(24 * time.Hour),
			})
		}
	}

	if len(params) > 0 {
		if _, err := w.client.InsertMany(ctx, params); err != nil {
			return fmt.Errorf("poam overdue transition scanner: failed to enqueue notification jobs: %w", err)
		}
	}

	w.logger.Infow("PoamOverdueTransitionScannerWorker: completed",
		"items_found", len(items),
		"transitioned", transitioned,
		"notifications_enqueued", len(params),
	)
	return nil
}

// ─── Notification worker ─────────────────────────────────────────────────────

// PoamOverdueNotificationWorker sends a single POAM overdue notification
// to one recipient.
type PoamOverdueNotificationWorker struct {
	userRepo                   UserRepository
	webBaseURL                 string
	notificationServiceFactory *PoamNotificationServiceFactory
	logger                     *zap.SugaredLogger
}

// NewPoamOverdueNotificationWorker constructs a PoamOverdueNotificationWorker.
func NewPoamOverdueNotificationWorker(
	userRepo UserRepository,
	webBaseURL string,
	notificationServiceFactory *PoamNotificationServiceFactory,
	logger *zap.SugaredLogger,
) *PoamOverdueNotificationWorker {
	return &PoamOverdueNotificationWorker{
		userRepo:                   userRepo,
		webBaseURL:                 webBaseURL,
		notificationServiceFactory: notificationServiceFactory,
		logger:                     logger,
	}
}

// Work sends the POAM overdue notification for a single item × recipient.
func (w *PoamOverdueNotificationWorker) Work(
	ctx context.Context,
	job *river.Job[PoamOverdueNotificationArgs],
) error {
	args := job.Args

	user, err := w.userRepo.FindUserByID(ctx, args.RecipientUserID.String())
	if err != nil {
		w.logger.Warnw("PoamOverdueNotificationWorker: could not resolve recipient, skipping",
			"recipient_user_id", args.RecipientUserID,
			"error", err,
		)
		return nil
	}

	notificationService, err := w.notificationServiceFactory.New(
		newNotificationUserRepositoryAdapter(w.userRepo, user),
	)
	if err != nil {
		return fmt.Errorf("create poam notification service: %w", err)
	}

	if err := notificationService.Dispatch(
		ctx,
		buildPoamOverdueNotificationRequest(args, user.FullName()),
	); err != nil {
		return fmt.Errorf("dispatch poam-overdue-notification notification: %w", err)
	}

	w.logger.Infow("PoamOverdueNotificationWorker: overdue notification sent",
		"poam_item_id", args.PoamItemID,
		"recipient_user_id", args.RecipientUserID,
	)
	return nil
}
