package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ─── Scanner worker ──────────────────────────────────────────────────────────

// MilestoneOverdueScannerWorker scans weekly for POAM item milestones that are
// in "open" or "in-progress" status, whose planned_completion_date has passed,
// and whose parent POAM item is not yet completed. For each such milestone it
// enqueues a MilestoneOverdueReminderArgs job per milestone per recipient.
type MilestoneOverdueScannerWorker struct {
	db         *gorm.DB
	client     workflow.RiverClient
	webBaseURL string
	userRepo   UserRepository
	logger     *zap.SugaredLogger
}

// NewMilestoneOverdueScannerWorker constructs a MilestoneOverdueScannerWorker.
func NewMilestoneOverdueScannerWorker(
	db *gorm.DB,
	client workflow.RiverClient,
	userRepo UserRepository,
	webBaseURL string,
	logger *zap.SugaredLogger,
) *MilestoneOverdueScannerWorker {
	return &MilestoneOverdueScannerWorker{
		db:         db,
		client:     client,
		webBaseURL: webBaseURL,
		userRepo:   userRepo,
		logger:     logger,
	}
}

// milestoneWithParent is a local join result used by the scanner query.
type milestoneWithParent struct {
	poam.PoamItemMilestone
	ParentStatus string  `gorm:"column:parent_status"`
	ParentSspID  string  `gorm:"column:parent_ssp_id"`
	ParentTitle  string  `gorm:"column:parent_title"`
	ParentOwner  *string `gorm:"column:parent_owner"`
}

// Work queries for overdue milestones on non-completed POAM items and enqueues
// per-milestone per-recipient reminder jobs.
func (w *MilestoneOverdueScannerWorker) Work(
	ctx context.Context,
	job *river.Job[MilestoneOverdueScannerArgs],
) error {
	if w.db == nil {
		return fmt.Errorf("MilestoneOverdueScannerWorker: db is nil")
	}

	now := time.Now().UTC()
	year, week := now.ISOWeek()
	weeklyBucket := fmt.Sprintf("%d-W%02d", year, week)

	var rows []milestoneWithParent
	if err := w.db.WithContext(ctx).
		Table("ccf_poam_item_milestones AS m").
		Select(
			"m.*, "+
				"p.status AS parent_status, "+
				"p.ssp_id AS parent_ssp_id, "+
				"p.title AS parent_title, "+
				"p.primary_owner_user_id AS parent_owner",
		).
		Joins("JOIN ccf_poam_items AS p ON p.id = m.poam_item_id").
		Where(
			"m.status IN ? AND m.planned_completion_date IS NOT NULL AND m.planned_completion_date < ? AND p.status != ?",
			[]string{
				string(poam.MilestoneStatusOpen),
				string(poam.MilestoneStatusInProgress),
			},
			now,
			string(poam.PoamItemStatusCompleted),
		).
		Scan(&rows).Error; err != nil {
		return fmt.Errorf("milestone overdue scanner: query failed: %w", err)
	}

	if len(rows) == 0 {
		w.logger.Infow("MilestoneOverdueScannerWorker: no overdue milestones found")
		return nil
	}

	params := make([]river.InsertManyParams, 0, len(rows))

	for i := range rows {
		row := &rows[i]
		if row.PlannedCompletionDate == nil {
			continue
		}

		// TODO(BCH-follow-on): Ideally notifications should be routed to the
		// milestone's responsible party rather than the POAM item owner.
		// Currently ccf_poam_item_milestones.responsible_party is a free-text
		// string with no FK to the users table, so we cannot resolve a user
		// email address from it. A follow-on schema migration to add a
		// responsible_party_user_id uuid column is required before this can be
		// changed. See: https://github.com/compliance-framework/api/pull/366#discussion
		recipients := resolvePoamRecipientsFromOwner(row.ParentOwner)
		if len(recipients) == 0 {
			continue
		}

		poamURL := resolvePoamURL(w.webBaseURL, row.PoamItemID)

		// Parse the parent SSP ID for the args struct.
		var sspID uuid.UUID
		if row.ParentSspID != "" {
			if parsed, err := uuid.Parse(row.ParentSspID); err == nil {
				sspID = parsed
			}
		}

		for _, recipientID := range recipients {
			args := MilestoneOverdueReminderArgs{
				MilestoneID:     row.ID,
				PoamItemID:      row.PoamItemID,
				RecipientUserID: recipientID,
				MilestoneTitle:  row.Title,
				PoamTitle:       row.ParentTitle,
				SspID:           sspID,
				SspDisplayName:  row.ParentSspID,
				DueDate:         row.PlannedCompletionDate.UTC().Format(time.RFC3339),
				PoamURL:         poamURL,
				WeeklyBucket:    weeklyBucket,
			}
			params = append(params, river.InsertManyParams{
				Args:       args,
				InsertOpts: JobInsertOptionsForPoamNotification(7 * 24 * time.Hour),
			})
		}
	}

	if len(params) == 0 {
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("milestone overdue scanner: failed to enqueue jobs: %w", err)
	}

	w.logger.Infow("MilestoneOverdueScannerWorker: enqueued reminder jobs",
		"milestones_found", len(rows),
		"jobs_enqueued", len(params),
		"weekly_bucket", weeklyBucket,
	)
	return nil
}

// ─── Notification worker ─────────────────────────────────────────────────────

// MilestoneOverdueReminderWorker sends a single incomplete milestone overdue
// reminder email to one recipient.
type MilestoneOverdueReminderWorker struct {
	emailService EmailService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

// NewMilestoneOverdueReminderWorker constructs a MilestoneOverdueReminderWorker.
func NewMilestoneOverdueReminderWorker(
	emailService EmailService,
	userRepo UserRepository,
	webBaseURL string,
	logger *zap.SugaredLogger,
) *MilestoneOverdueReminderWorker {
	return &MilestoneOverdueReminderWorker{
		emailService: emailService,
		userRepo:     userRepo,
		webBaseURL:   webBaseURL,
		logger:       logger,
	}
}

// Work sends the milestone overdue reminder email for a single milestone × recipient.
func (w *MilestoneOverdueReminderWorker) Work(
	ctx context.Context,
	job *river.Job[MilestoneOverdueReminderArgs],
) error {
	args := job.Args

	user, err := w.userRepo.FindUserByID(ctx, args.RecipientUserID.String())
	if err != nil {
		w.logger.Warnw("MilestoneOverdueReminderWorker: could not resolve recipient, skipping",
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
		"MilestoneTitle": args.MilestoneTitle,
		"PoamTitle":      args.PoamTitle,
		"SSPName":        args.SspDisplayName,
		"DueDate":        args.DueDate,
		"PoamURL":        args.PoamURL,
	}

	htmlBody, textBody, err := w.emailService.UseTemplate("poam-milestone-overdue-reminder", templateData)
	if err != nil {
		return fmt.Errorf("milestone overdue reminder: render template failed: %w", err)
	}

	message := &types.Message{
		From:     w.emailService.GetDefaultFromAddress(),
		To:       []string{user.Email},
		Subject:  fmt.Sprintf("POAM Milestone Overdue: %s", args.MilestoneTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		return fmt.Errorf("milestone overdue reminder: send email failed: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("milestone overdue reminder: email send reported failure: %s", result.Error)
	}

	w.logger.Infow("MilestoneOverdueReminderWorker: email sent",
		"milestone_id", args.MilestoneID,
		"poam_item_id", args.PoamItemID,
		"recipient_user_id", args.RecipientUserID,
		"message_id", result.MessageID,
	)
	return nil
}
