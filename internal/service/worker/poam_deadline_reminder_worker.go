package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ─── Scanner worker ──────────────────────────────────────────────────────────

// PoamDeadlineReminderScannerWorker scans daily for POAM items whose deadline
// is approaching within the configured window and enqueues per-item per-recipient
// reminder jobs. Mirrors the Risk Review Deadline Reminder scanner pattern.
type PoamDeadlineReminderScannerWorker struct {
	db             *gorm.DB
	client         workflow.RiverClient
	webBaseURL     string
	userRepo       UserRepository
	reminderWindow time.Duration
	logger         *zap.SugaredLogger
}

// NewPoamDeadlineReminderScannerWorker constructs a PoamDeadlineReminderScannerWorker.
// reminderWindow is the look-ahead horizon; items with deadline within this duration
// of now will receive a reminder. Pass a positive value (e.g. 30 * 24 * time.Hour).
func NewPoamDeadlineReminderScannerWorker(
	db *gorm.DB,
	client workflow.RiverClient,
	userRepo UserRepository,
	webBaseURL string,
	reminderWindow time.Duration,
	logger *zap.SugaredLogger,
) *PoamDeadlineReminderScannerWorker {
	if reminderWindow <= 0 {
		reminderWindow = 30 * 24 * time.Hour
	}
	return &PoamDeadlineReminderScannerWorker{
		db:             db,
		client:         client,
		webBaseURL:     webBaseURL,
		userRepo:       userRepo,
		reminderWindow: reminderWindow,
		logger:         logger,
	}
}

// Work queries for POAM items with deadlines within the configured reminder window and
// enqueues PoamDeadlineReminderArgs jobs for each item × recipient pair.
func (w *PoamDeadlineReminderScannerWorker) Work(
	ctx context.Context,
	job *river.Job[PoamDeadlineReminderScannerArgs],
) error {
	if w.db == nil {
		return fmt.Errorf("PoamDeadlineReminderScannerWorker: db is nil")
	}

	now := time.Now().UTC()
	windowEnd := now.Add(w.reminderWindow)
	reminderBucket := now.Format("2006-01-02")

	var items []poam.PoamItem
	if err := w.db.WithContext(ctx).
		Preload("Milestones").
		Where(
			"status IN ? AND planned_completion_date IS NOT NULL AND planned_completion_date > ? AND planned_completion_date <= ?",
			[]string{
				string(poam.PoamItemStatusOpen),
				string(poam.PoamItemStatusInProgress),
			},
			now,
			windowEnd,
		).
		Find(&items).Error; err != nil {
		return fmt.Errorf("poam deadline reminder scanner: query failed: %w", err)
	}

	if len(items) == 0 {
		w.logger.Infow("PoamDeadlineReminderScannerWorker: no items approaching deadline",
			"window_end", windowEnd,
		)
		return nil
	}

	sspNames, err := resolvePoamSSPDisplayNames(ctx, w.db, items)
	if err != nil {
		w.logger.Warnw("PoamDeadlineReminderScannerWorker: failed to resolve SSP names", "error", err)
		sspNames = map[string]string{}
	}

	params := make([]river.InsertManyParams, 0, len(items))
	for i := range items {
		item := &items[i]
		if item.PlannedCompletionDate == nil {
			continue
		}

		recipients := resolvePoamRecipients(item)
		sspName := sspNames[item.SspID.String()]
		if sspName == "" {
			sspName = item.SspID.String()
		}
		poamURL := resolvePoamURL(w.webBaseURL, item.ID)

		for _, recipientID := range recipients {
			args := PoamDeadlineReminderArgs{
				PoamItemID:           item.ID,
				RecipientUserID:      recipientID,
				PoamTitle:            item.Title,
				SspID:                item.SspID,
				SspDisplayName:       sspName,
				CurrentStatus:        item.Status,
				Deadline:             item.PlannedCompletionDate.UTC().Format(time.RFC3339),
				MilestoneCount:       len(item.Milestones),
				PoamURL:              poamURL,
				ReminderWindowBucket: reminderBucket,
			}
			params = append(params, river.InsertManyParams{
				Args:       args,
				InsertOpts: JobInsertOptionsForPoamNotification(24 * time.Hour),
			})
		}
	}

	if len(params) == 0 {
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("poam deadline reminder scanner: failed to enqueue jobs: %w", err)
	}

	w.logger.Infow("PoamDeadlineReminderScannerWorker: enqueued reminder jobs",
		"count", len(params),
		"items", len(items),
	)
	return nil
}

// ─── Notification worker ─────────────────────────────────────────────────────

// PoamDeadlineReminderWorker sends a single POAM deadline approaching reminder
// email to one recipient.
type PoamDeadlineReminderWorker struct {
	emailService EmailService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

// NewPoamDeadlineReminderWorker constructs a PoamDeadlineReminderWorker.
func NewPoamDeadlineReminderWorker(
	emailService EmailService,
	userRepo UserRepository,
	webBaseURL string,
	logger *zap.SugaredLogger,
) *PoamDeadlineReminderWorker {
	return &PoamDeadlineReminderWorker{
		emailService: emailService,
		userRepo:     userRepo,
		webBaseURL:   webBaseURL,
		logger:       logger,
	}
}

// Work sends the POAM deadline reminder email for a single item × recipient.
func (w *PoamDeadlineReminderWorker) Work(
	ctx context.Context,
	job *river.Job[PoamDeadlineReminderArgs],
) error {
	args := job.Args

	user, err := w.userRepo.FindUserByID(ctx, args.RecipientUserID.String())
	if err != nil {
		w.logger.Warnw("PoamDeadlineReminderWorker: could not resolve recipient, skipping",
			"recipient_user_id", args.RecipientUserID,
			"error", err,
		)
		return nil
	}
	if user.Email == "" {
		return nil
	}

	templateData := map[string]interface{}{
		"RecipientName":  user.FullName(),
		"PoamTitle":      args.PoamTitle,
		"SSPName":        args.SspDisplayName,
		"CurrentStatus":  args.CurrentStatus,
		"Deadline":       args.Deadline,
		"MilestoneCount": args.MilestoneCount,
		"PoamURL":        args.PoamURL,
	}

	htmlBody, textBody, err := w.emailService.UseTemplate("poam-deadline-reminder", templateData)
	if err != nil {
		return fmt.Errorf("poam deadline reminder: render template failed: %w", err)
	}

	message := &types.Message{
		From:     w.emailService.GetDefaultFromAddress(),
		To:       []string{user.Email},
		Subject:  fmt.Sprintf("POAM Deadline Approaching: %s", args.PoamTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		return fmt.Errorf("poam deadline reminder: send email failed: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("poam deadline reminder: email send reported failure: %s", result.Error)
	}

	w.logger.Infow("PoamDeadlineReminderWorker: email sent",
		"poam_item_id", args.PoamItemID,
		"recipient_user_id", args.RecipientUserID,
		"message_id", result.MessageID,
	)
	return nil
}
