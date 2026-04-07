package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const riskScannerBatchSize = 1000

type RiskReviewDeadlineReminderScannerWorker struct {
	db     *gorm.DB
	client workflow.RiverClient
	logger *zap.SugaredLogger
}

func NewRiskReviewDeadlineReminderScannerWorker(db *gorm.DB, client workflow.RiverClient, logger *zap.SugaredLogger) *RiskReviewDeadlineReminderScannerWorker {
	return &RiskReviewDeadlineReminderScannerWorker{db: db, client: client, logger: logger}
}

func (w *RiskReviewDeadlineReminderScannerWorker) Work(ctx context.Context, _ *river.Job[RiskReviewDeadlineReminderScannerArgs]) error {
	now := time.Now().UTC()
	windowEnd := now.Add(30 * 24 * time.Hour)

	var (
		risks         []riskrel.Risk
		totalEnqueued int
	)
	if err := w.db.WithContext(ctx).
		Where("status = ? AND review_deadline IS NOT NULL AND review_deadline > ? AND review_deadline <= ?",
			string(riskrel.RiskStatusRiskAccepted), now, windowEnd).
		FindInBatches(&risks, riskScannerBatchSize, func(_ *gorm.DB, _ int) error {
			ownersByRiskID, err := resolveRiskOwnerUserIDsBatch(ctx, w.db, risks)
			if err != nil {
				return fmt.Errorf("risk deadline reminder scanner: resolve owners failed: %w", err)
			}

			params := make([]river.InsertManyParams, 0, len(risks))
			for i := range risks {
				risk := &risks[i]
				if risk.ID == nil {
					continue
				}
				ownerIDs := ownersByRiskID[*risk.ID]
				for _, ownerID := range ownerIDs {
					params = append(params, river.InsertManyParams{
						Args: RiskReviewDueReminderArgs{
							RiskID:         *risk.ID,
							OwnerUserID:    ownerID,
							ReviewDeadline: risk.ReviewDeadline.UTC().Format(time.RFC3339),
							ReminderWindow: "30d",
						},
						InsertOpts: JobInsertOptionsForRiskNotification(24 * time.Hour),
					})
				}
			}

			if len(params) == 0 {
				return nil
			}

			if _, err := w.client.InsertMany(ctx, params); err != nil {
				return fmt.Errorf("risk deadline reminder scanner: enqueue failed: %w", err)
			}
			totalEnqueued += len(params)
			return nil
		}).Error; err != nil {
		return fmt.Errorf("risk deadline reminder scanner: query failed: %w", err)
	}

	if totalEnqueued == 0 {
		w.logger.Infow("RiskReviewDeadlineReminderScannerWorker: no reminders to enqueue")
		return nil
	}

	w.logger.Infow("RiskReviewDeadlineReminderScannerWorker: enqueued reminders", "count", totalEnqueued)
	return nil
}

type RiskReviewOverdueEscalationScannerWorker struct {
	db                      *gorm.DB
	client                  workflow.RiverClient
	logger                  *zap.SugaredLogger
	autoReopenEnabled       bool
	autoReopenThresholdDays int
}

func NewRiskReviewOverdueEscalationScannerWorker(
	db *gorm.DB,
	client workflow.RiverClient,
	logger *zap.SugaredLogger,
	autoReopenEnabled bool,
	autoReopenThresholdDays int,
) *RiskReviewOverdueEscalationScannerWorker {
	return &RiskReviewOverdueEscalationScannerWorker{
		db:                      db,
		client:                  client,
		logger:                  logger,
		autoReopenEnabled:       autoReopenEnabled,
		autoReopenThresholdDays: autoReopenThresholdDays,
	}
}

func (w *RiskReviewOverdueEscalationScannerWorker) Work(ctx context.Context, _ *river.Job[RiskReviewOverdueEscalationScannerArgs]) error {
	now := time.Now().UTC()
	threshold := time.Duration(w.autoReopenThresholdDays) * 24 * time.Hour

	var (
		risks            []riskrel.Risk
		totalEnqueued    int
		totalReopenCount int
	)
	if err := w.db.WithContext(ctx).
		Where("status = ? AND review_deadline IS NOT NULL AND review_deadline < ?",
			string(riskrel.RiskStatusRiskAccepted), now).
		FindInBatches(&risks, riskScannerBatchSize, func(_ *gorm.DB, _ int) error {
			ownersByRiskID, err := resolveRiskOwnerUserIDsBatch(ctx, w.db, risks)
			if err != nil {
				return fmt.Errorf("risk overdue escalation scanner: resolve owners failed: %w", err)
			}

			params := make([]river.InsertManyParams, 0, len(risks))
			overdueWindow := now.Format("2006-01-02")
			for i := range risks {
				risk := &risks[i]
				if risk.ID == nil {
					continue
				}
				ownerIDs := ownersByRiskID[*risk.ID]
				for _, ownerID := range ownerIDs {
					params = append(params, river.InsertManyParams{
						Args: RiskReviewOverdueEscalationArgs{
							RiskID:         *risk.ID,
							OwnerUserID:    ownerID,
							ReviewDeadline: risk.ReviewDeadline.UTC().Format(time.RFC3339),
							OverdueWindow:  overdueWindow,
						},
						InsertOpts: JobInsertOptionsForRiskNotification(24 * time.Hour),
					})
				}

				if w.autoReopenEnabled && w.autoReopenThresholdDays > 0 {
					overdueFor := now.Sub(risk.ReviewDeadline.UTC())
					if overdueFor >= threshold {
						params = append(params, river.InsertManyParams{
							Args: RiskReviewOverdueReopenArgs{
								RiskID:         *risk.ID,
								ReviewDeadline: risk.ReviewDeadline.UTC().Format(time.RFC3339),
								ThresholdDays:  w.autoReopenThresholdDays,
							},
							InsertOpts: JobInsertOptionsForRiskWorkerUnique(24 * time.Hour),
						})
						totalReopenCount++
					}
				}
			}

			if len(params) == 0 {
				return nil
			}

			if _, err := w.client.InsertMany(ctx, params); err != nil {
				return fmt.Errorf("risk overdue escalation scanner: enqueue failed: %w", err)
			}
			totalEnqueued += len(params)
			return nil
		}).Error; err != nil {
		return fmt.Errorf("risk overdue escalation scanner: query failed: %w", err)
	}

	if totalEnqueued == 0 {
		w.logger.Infow("RiskReviewOverdueEscalationScannerWorker: no escalations to enqueue")
		return nil
	}

	w.logger.Infow("RiskReviewOverdueEscalationScannerWorker: enqueued jobs", "count", totalEnqueued, "reopen_count", totalReopenCount)
	return nil
}

type RiskStaleRiskScannerWorker struct {
	db     *gorm.DB
	client workflow.RiverClient
	logger *zap.SugaredLogger
}

func NewRiskStaleRiskScannerWorker(db *gorm.DB, client workflow.RiverClient, logger *zap.SugaredLogger) *RiskStaleRiskScannerWorker {
	return &RiskStaleRiskScannerWorker{db: db, client: client, logger: logger}
}

func (w *RiskStaleRiskScannerWorker) Work(ctx context.Context, _ *river.Job[RiskStaleRiskScannerArgs]) error {
	now := time.Now().UTC()
	cutoff := now.Add(-30 * 24 * time.Hour)
	staleBucketDate := startOfISOWeekUTC(now).Format("2006-01-02")

	var (
		risks         []riskrel.Risk
		totalEnqueued int
	)
	if err := w.db.WithContext(ctx).
		Where("status IN ? AND last_seen_at <= ?",
			[]string{
				string(riskrel.RiskStatusOpen),
				string(riskrel.RiskStatusInvestigating),
				string(riskrel.RiskStatusMitigatingPlanned),
				string(riskrel.RiskStatusMitigatingImplemented),
			},
			cutoff).
		FindInBatches(&risks, riskScannerBatchSize, func(_ *gorm.DB, _ int) error {
			ownersByRiskID, err := resolveRiskOwnerUserIDsBatch(ctx, w.db, risks)
			if err != nil {
				return fmt.Errorf("risk stale scanner: resolve owners failed: %w", err)
			}

			params := make([]river.InsertManyParams, 0, len(risks))
			for i := range risks {
				risk := &risks[i]
				if risk.ID == nil {
					continue
				}
				ownerIDs := ownersByRiskID[*risk.ID]
				for _, ownerID := range ownerIDs {
					params = append(params, river.InsertManyParams{
						Args: RiskStaleOpenReminderArgs{
							RiskID:          *risk.ID,
							OwnerUserID:     ownerID,
							LastSeenAt:      risk.LastSeenAt.UTC().Format(time.RFC3339),
							StaleBucketDate: staleBucketDate,
						},
						InsertOpts: JobInsertOptionsForRiskNotification(7 * 24 * time.Hour),
					})
				}
			}

			if len(params) == 0 {
				return nil
			}

			if _, err := w.client.InsertMany(ctx, params); err != nil {
				return fmt.Errorf("risk stale scanner: enqueue failed: %w", err)
			}
			totalEnqueued += len(params)
			return nil
		}).Error; err != nil {
		return fmt.Errorf("risk stale scanner: query failed: %w", err)
	}

	if totalEnqueued == 0 {
		w.logger.Infow("RiskStaleRiskScannerWorker: no stale reminders to enqueue")
		return nil
	}

	w.logger.Infow("RiskStaleRiskScannerWorker: enqueued stale reminders", "count", totalEnqueued)
	return nil
}

type RiskEvidenceReconciliationScannerWorker struct {
	db     *gorm.DB
	client workflow.RiverClient
	logger *zap.SugaredLogger
}

func NewRiskEvidenceReconciliationScannerWorker(db *gorm.DB, client workflow.RiverClient, logger *zap.SugaredLogger) *RiskEvidenceReconciliationScannerWorker {
	return &RiskEvidenceReconciliationScannerWorker{db: db, client: client, logger: logger}
}

func (w *RiskEvidenceReconciliationScannerWorker) Work(ctx context.Context, _ *river.Job[RiskEvidenceReconciliationScannerArgs]) error {
	var params []river.InsertManyParams

	// Pass 1: Duplicate active risks with same dedupe key.
	var duplicateKeys []string
	if err := w.db.WithContext(ctx).
		Model(&riskrel.Risk{}).
		Select("dedupe_key").
		Where("status <> ? AND dedupe_key <> ''", string(riskrel.RiskStatusClosed)).
		Group("dedupe_key").
		Having("COUNT(*) > 1").
		Pluck("dedupe_key", &duplicateKeys).Error; err != nil {
		return fmt.Errorf("risk reconciliation scanner: query duplicate dedupe keys failed: %w", err)
	}
	for _, key := range duplicateKeys {
		params = append(params, river.InsertManyParams{
			Args:       RiskReconcileDuplicatesArgs{DedupeKey: key},
			InsertOpts: JobInsertOptionsForRiskWorkerUnique(24 * time.Hour),
		})
	}

	// Pass 2: Orphaned controls — open auto-generated risks whose linked controls no
	// longer exist in the SSP's current profile set (profile was swapped or unbound).
	// Only auto-generated risks (risk_template_id IS NOT NULL) are candidates; manually
	// created risks are not subject to automatic profile-binding cleanup.
	var orphanCandidateIDs []string
	if err := w.db.WithContext(ctx).
		Table("risk_register_risks r").
		Select("CAST(r.id AS TEXT)").
		Joins("JOIN risk_control_links rcl ON rcl.risk_id = r.id").
		Where(
			"r.status NOT IN ? AND r.risk_template_id IS NOT NULL",
			[]string{
				string(riskrel.RiskStatusClosed),
				string(riskrel.RiskStatusRemediated),
			},
		).
		Group("r.id").
		Pluck("CAST(r.id AS TEXT)", &orphanCandidateIDs).Error; err != nil {
		return fmt.Errorf("risk reconciliation scanner: query orphan candidates failed: %w", err)
	}
	for _, idStr := range orphanCandidateIDs {
		riskID, err := uuid.Parse(idStr)
		if err != nil {
			w.logger.Warnw("RiskEvidenceReconciliationScannerWorker: skipping unparseable risk ID",
				"raw_id", idStr, "error", err)
			continue
		}
		params = append(params, river.InsertManyParams{
			Args:       RiskOrphanedControlsArgs{RiskID: riskID},
			InsertOpts: JobInsertOptionsForRiskWorkerUnique(24 * time.Hour),
		})
	}

	if len(params) == 0 {
		w.logger.Infow("RiskEvidenceReconciliationScannerWorker: no reconciliation jobs to enqueue")
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("risk reconciliation scanner: enqueue failed: %w", err)
	}

	w.logger.Infow("RiskEvidenceReconciliationScannerWorker: enqueued reconciliation jobs",
		"duplicate_count", len(duplicateKeys),
		"orphan_candidate_count", len(orphanCandidateIDs),
		"total", len(params),
	)
	return nil
}

type RiskReviewDueReminderWorker struct {
	db           *gorm.DB
	emailService EmailService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

func NewRiskReviewDueReminderWorker(db *gorm.DB, emailService EmailService, userRepo UserRepository, webBaseURL string, logger *zap.SugaredLogger) *RiskReviewDueReminderWorker {
	return &RiskReviewDueReminderWorker{db: db, emailService: emailService, userRepo: userRepo, webBaseURL: webBaseURL, logger: logger}
}

func (w *RiskReviewDueReminderWorker) Work(ctx context.Context, job *river.Job[RiskReviewDueReminderArgs]) error {
	return w.sendRiskNotification(ctx, job.Args.RiskID, job.Args.OwnerUserID, "risk-review-due-reminder", "Risk review due soon")
}

type RiskReviewOverdueEscalationWorker struct {
	db           *gorm.DB
	emailService EmailService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

func NewRiskReviewOverdueEscalationWorker(db *gorm.DB, emailService EmailService, userRepo UserRepository, webBaseURL string, logger *zap.SugaredLogger) *RiskReviewOverdueEscalationWorker {
	return &RiskReviewOverdueEscalationWorker{db: db, emailService: emailService, userRepo: userRepo, webBaseURL: webBaseURL, logger: logger}
}

func (w *RiskReviewOverdueEscalationWorker) Work(ctx context.Context, job *river.Job[RiskReviewOverdueEscalationArgs]) error {
	return w.sendRiskNotification(ctx, job.Args.RiskID, job.Args.OwnerUserID, "risk-review-overdue-escalation", "Risk review overdue")
}

type RiskStaleOpenReminderWorker struct {
	db           *gorm.DB
	emailService EmailService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

func NewRiskStaleOpenReminderWorker(db *gorm.DB, emailService EmailService, userRepo UserRepository, webBaseURL string, logger *zap.SugaredLogger) *RiskStaleOpenReminderWorker {
	return &RiskStaleOpenReminderWorker{db: db, emailService: emailService, userRepo: userRepo, webBaseURL: webBaseURL, logger: logger}
}

func (w *RiskStaleOpenReminderWorker) Work(ctx context.Context, job *river.Job[RiskStaleOpenReminderArgs]) error {
	return w.sendRiskNotification(ctx, job.Args.RiskID, job.Args.OwnerUserID, "risk-stale-open-reminder", "Stale risk reminder")
}

func (w *RiskReviewDueReminderWorker) sendRiskNotification(ctx context.Context, riskID, ownerUserID uuid.UUID, templateName, subjectPrefix string) error {
	return sendRiskNotification(ctx, w.db, w.emailService, w.userRepo, w.webBaseURL, w.logger, riskID, ownerUserID, templateName, subjectPrefix)
}

func (w *RiskReviewOverdueEscalationWorker) sendRiskNotification(ctx context.Context, riskID, ownerUserID uuid.UUID, templateName, subjectPrefix string) error {
	return sendRiskNotification(ctx, w.db, w.emailService, w.userRepo, w.webBaseURL, w.logger, riskID, ownerUserID, templateName, subjectPrefix)
}

func (w *RiskStaleOpenReminderWorker) sendRiskNotification(ctx context.Context, riskID, ownerUserID uuid.UUID, templateName, subjectPrefix string) error {
	return sendRiskNotification(ctx, w.db, w.emailService, w.userRepo, w.webBaseURL, w.logger, riskID, ownerUserID, templateName, subjectPrefix)
}

func sendRiskNotification(
	ctx context.Context,
	db *gorm.DB,
	emailService EmailService,
	userRepo UserRepository,
	webBaseURL string,
	logger *zap.SugaredLogger,
	riskID, ownerUserID uuid.UUID,
	templateName, subjectPrefix string,
) error {
	var risk riskrel.Risk
	if err := db.WithContext(ctx).First(&risk, "id = ?", riskID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warnw("Risk notification worker: risk not found, skipping", "risk_id", riskID)
			return nil
		}
		return fmt.Errorf("risk notification worker: load risk failed: %w", err)
	}

	user, err := userRepo.FindUserByID(ctx, ownerUserID.String())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warnw("Risk notification worker: owner user not found, skipping", "risk_id", riskID, "owner_user_id", ownerUserID, "error", err)
			return nil
		}
		return fmt.Errorf("risk notification worker: load owner user failed: %w", err)
	}
	if !user.RiskNotificationsSubscribed {
		logger.Debugw("Risk notification worker: owner unsubscribed, skipping", "risk_id", riskID, "owner_user_id", ownerUserID)
		return nil
	}

	riskTitle := strings.TrimSpace(risk.Title)
	if riskTitle == "" {
		riskTitle = riskID.String()
	}

	sspName := resolveSSPDisplayName(ctx, db, risk.SSPID)
	reviewDeadline := ""
	if risk.ReviewDeadline != nil {
		reviewDeadline = formatDate(*risk.ReviewDeadline)
	}

	templateData := map[string]interface{}{
		"OwnerName":      user.FullName(),
		"RiskTitle":      riskTitle,
		"SSPName":        sspName,
		"RiskStatus":     risk.Status,
		"ReviewDeadline": reviewDeadline,
		"LastSeenAt":     formatDate(risk.LastSeenAt),
		"RiskURL":        resolveRiskURL(webBaseURL, riskID),
	}

	htmlBody, textBody, err := emailService.UseTemplate(templateName, templateData)
	if err != nil {
		return fmt.Errorf("risk notification worker: render template %q failed: %w", templateName, err)
	}

	message := &types.Message{
		From:     emailService.GetDefaultFromAddress(),
		To:       []string{user.Email},
		Subject:  fmt.Sprintf("%s: %s", subjectPrefix, riskTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}
	result, err := emailService.Send(ctx, message)
	if err != nil {
		return fmt.Errorf("risk notification worker: send email failed: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("risk notification worker: email send failed: %s", result.Error)
	}

	logger.Infow("Risk notification worker: email sent",
		"risk_id", riskID,
		"owner_user_id", ownerUserID,
		"template", templateName,
		"message_id", result.MessageID,
	)
	return nil
}

type RiskReconcileDuplicatesWorker struct {
	db     *gorm.DB
	logger *zap.SugaredLogger
}

func NewRiskReconcileDuplicatesWorker(db *gorm.DB, logger *zap.SugaredLogger) *RiskReconcileDuplicatesWorker {
	return &RiskReconcileDuplicatesWorker{db: db, logger: logger}
}

func (w *RiskReconcileDuplicatesWorker) Work(ctx context.Context, job *river.Job[RiskReconcileDuplicatesArgs]) error {
	if strings.TrimSpace(job.Args.DedupeKey) == "" {
		return nil
	}

	var duplicates []riskrel.Risk
	if err := w.db.WithContext(ctx).
		Where("dedupe_key = ? AND status <> ?", job.Args.DedupeKey, string(riskrel.RiskStatusClosed)).
		Order("created_at ASC, id ASC").
		Find(&duplicates).Error; err != nil {
		return fmt.Errorf("risk reconcile duplicates: load duplicates failed: %w", err)
	}
	if len(duplicates) <= 1 {
		return nil
	}

	riskSvc := riskrel.NewRiskService(w.db.WithContext(ctx))
	keeper := duplicates[0]
	for i := 1; i < len(duplicates); i++ {
		risk := duplicates[i]
		oldStatus := risk.Status
		risk.Status = string(riskrel.RiskStatusClosed)
		if _, err := riskSvc.Update(riskrel.UpdateRiskParams{
			Risk:          &risk,
			OldStatus:     oldStatus,
			StatusChanged: oldStatus != risk.Status,
		}); err != nil {
			return fmt.Errorf("risk reconcile duplicates: close duplicate %s failed: %w", risk.ID.String(), err)
		}
	}

	w.logger.Infow("RiskReconcileDuplicatesWorker: reconciled duplicates",
		"dedupe_key", job.Args.DedupeKey,
		"kept_risk_id", keeper.ID.String(),
		"closed_count", len(duplicates)-1,
	)
	return nil
}

type RiskReviewOverdueReopenWorker struct {
	db     *gorm.DB
	logger *zap.SugaredLogger
}

func NewRiskReviewOverdueReopenWorker(db *gorm.DB, logger *zap.SugaredLogger) *RiskReviewOverdueReopenWorker {
	return &RiskReviewOverdueReopenWorker{db: db, logger: logger}
}

func (w *RiskReviewOverdueReopenWorker) Work(ctx context.Context, job *river.Job[RiskReviewOverdueReopenArgs]) error {
	if job.Args.ThresholdDays <= 0 {
		w.logger.Infow("RiskReviewOverdueReopenWorker: skipping reopen due to non-positive threshold_days",
			"risk_id", job.Args.RiskID,
			"threshold_days", job.Args.ThresholdDays,
		)
		return nil
	}

	now := time.Now().UTC()
	threshold := time.Duration(job.Args.ThresholdDays) * 24 * time.Hour
	cutoff := now.Add(-threshold)

	riskSvc := riskrel.NewRiskService(w.db.WithContext(ctx))
	if _, err := riskSvc.ReviewRisk(riskrel.ReviewRiskParams{
		RiskID:                             job.Args.RiskID,
		Decision:                           riskrel.RiskReviewDecisionReopen,
		ReviewedAt:                         &now,
		RequireCurrentReviewDeadlineBefore: &cutoff,
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || riskrel.IsValidationError(err) {
			return nil
		}
		return fmt.Errorf("risk overdue reopen: reopen review failed: %w", err)
	}

	w.logger.Infow("RiskReviewOverdueReopenWorker: reopened overdue accepted risk",
		"risk_id", job.Args.RiskID,
		"threshold_days", job.Args.ThresholdDays,
	)
	return nil
}

// RiskOrphanedControlsWorker checks whether a single open auto-generated risk has
// become orphaned after its SSP's profile binding changed. A risk is considered
// orphaned when none of its linked controls exist in the SSP's current profile
// control set. Orphaned risks are transitioned to remediated with an
// "orphaned_profile_change" audit event so they do not silently accumulate.
type RiskOrphanedControlsWorker struct {
	db     *gorm.DB
	logger *zap.SugaredLogger
}

func NewRiskOrphanedControlsWorker(db *gorm.DB, logger *zap.SugaredLogger) *RiskOrphanedControlsWorker {
	return &RiskOrphanedControlsWorker{db: db, logger: logger}
}

func (w *RiskOrphanedControlsWorker) Work(ctx context.Context, job *river.Job[RiskOrphanedControlsArgs]) error {
	riskID := job.Args.RiskID

	// Load the risk and verify it is still open and auto-generated.
	var risk riskrel.Risk
	if err := w.db.WithContext(ctx).First(&risk, "id = ?", riskID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // risk deleted between scan and execution
		}
		return fmt.Errorf("risk orphaned controls: load risk failed: %w", err)
	}

	// Skip if already terminal or manually created.
	if risk.Status == string(riskrel.RiskStatusClosed) ||
		risk.Status == string(riskrel.RiskStatusRemediated) ||
		risk.RiskTemplateID == nil {
		return nil
	}

	// Load the risk's linked control IDs (catalog_id + control_id pairs).
	type controlKey struct {
		CatalogID string
		ControlID string
	}
	var riskControlLinks []struct {
		CatalogID string `gorm:"column:catalog_id"`
		ControlID string `gorm:"column:control_id"`
	}
	if err := w.db.WithContext(ctx).
		Table("risk_control_links").
		Select("CAST(catalog_id AS TEXT) AS catalog_id, UPPER(control_id) AS control_id").
		Where("risk_id = ?", riskID).
		Scan(&riskControlLinks).Error; err != nil {
		return fmt.Errorf("risk orphaned controls: load control links failed: %w", err)
	}
	if len(riskControlLinks) == 0 {
		// No control links — nothing to check against the profile.
		return nil
	}

	riskControlSet := make(map[controlKey]struct{}, len(riskControlLinks))
	for _, cl := range riskControlLinks {
		riskControlSet[controlKey{CatalogID: cl.CatalogID, ControlID: cl.ControlID}] = struct{}{}
	}

	// Load the SSP's current profile control set via profile_controls.
	var profileControls []struct {
		CatalogID string `gorm:"column:control_catalog_id"`
		ControlID string `gorm:"column:control_id"`
	}
	if err := w.db.WithContext(ctx).
		Table("profile_controls pc").
		Select("CAST(pc.control_catalog_id AS TEXT) AS control_catalog_id, UPPER(pc.control_id) AS control_id").
		Joins("JOIN system_security_plans ssp ON CAST(ssp.profile_id AS TEXT) = CAST(pc.profile_id AS TEXT)").
		Where("CAST(ssp.id AS TEXT) = CAST(? AS TEXT)", risk.SSPID).
		Scan(&profileControls).Error; err != nil {
		return fmt.Errorf("risk orphaned controls: load profile controls failed: %w", err)
	}

	// If the SSP has no profile (profile unbound entirely), all controls are orphaned.
	// If the SSP has a profile, check for intersection.
	if len(profileControls) > 0 {
		for _, pc := range profileControls {
			if _, exists := riskControlSet[controlKey{CatalogID: pc.CatalogID, ControlID: pc.ControlID}]; exists {
				// At least one control still exists in the current profile — not orphaned.
				return nil
			}
		}
	}

	// No intersection found — transition to remediated.
	return w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		oldStatus := risk.Status
		if err := tx.Model(&risk).Update("status", string(riskrel.RiskStatusRemediated)).Error; err != nil {
			return fmt.Errorf("risk orphaned controls: transition to remediated failed: %w", err)
		}

		occurredAt := time.Now().UTC()
		payload := map[string]interface{}{
			"from":   oldStatus,
			"to":     string(riskrel.RiskStatusRemediated),
			"reason": "orphaned_profile_change",
		}
		details := riskrel.BuildRiskEventDetails(string(riskrel.RiskEventTypeStatusChange), payload, occurredAt)
		event := &riskrel.RiskEvent{
			RiskID:     riskID,
			EventType:  string(riskrel.RiskEventTypeStatusChange),
			OccurredAt: occurredAt,
			Details:    &details,
			Payload:    payload,
		}
		if err := tx.Create(event).Error; err != nil {
			return fmt.Errorf("risk orphaned controls: emit status change event failed: %w", err)
		}

		w.logger.Infow("RiskOrphanedControlsWorker: orphaned risk transitioned to remediated",
			"risk_id", riskID,
			"ssp_id", risk.SSPID,
			"from_status", oldStatus,
		)
		return nil
	})
}

func resolveRiskOwnerUserIDsBatch(ctx context.Context, db *gorm.DB, risks []riskrel.Risk) (map[uuid.UUID][]uuid.UUID, error) {
	ownerSetByRiskID := make(map[uuid.UUID]map[uuid.UUID]struct{}, len(risks))
	riskIDs := make([]uuid.UUID, 0, len(risks))
	for i := range risks {
		risk := &risks[i]
		if risk.ID == nil {
			continue
		}
		riskID := *risk.ID
		riskIDs = append(riskIDs, riskID)
		if _, ok := ownerSetByRiskID[riskID]; !ok {
			ownerSetByRiskID[riskID] = make(map[uuid.UUID]struct{}, 4)
		}
		if risk.PrimaryOwnerUserID != nil {
			ownerSetByRiskID[riskID][*risk.PrimaryOwnerUserID] = struct{}{}
		}
	}
	if len(riskIDs) == 0 {
		return map[uuid.UUID][]uuid.UUID{}, nil
	}

	var assignments []riskrel.RiskOwnerAssignment
	if err := db.WithContext(ctx).
		Where("risk_id IN ? AND owner_kind = ?", riskIDs, "user").
		Find(&assignments).Error; err != nil {
		return nil, err
	}

	for _, assignment := range assignments {
		parsed, err := uuid.Parse(assignment.OwnerRef)
		if err != nil {
			continue
		}
		set, ok := ownerSetByRiskID[assignment.RiskID]
		if !ok {
			set = make(map[uuid.UUID]struct{}, 1)
			ownerSetByRiskID[assignment.RiskID] = set
		}
		set[parsed] = struct{}{}
	}

	ownersByRiskID := make(map[uuid.UUID][]uuid.UUID, len(ownerSetByRiskID))
	for riskID, ownerSet := range ownerSetByRiskID {
		owners := make([]uuid.UUID, 0, len(ownerSet))
		for ownerID := range ownerSet {
			owners = append(owners, ownerID)
		}
		sort.Slice(owners, func(i, j int) bool { return owners[i].String() < owners[j].String() })
		ownersByRiskID[riskID] = owners
	}

	return ownersByRiskID, nil
}

func resolveSSPDisplayName(ctx context.Context, db *gorm.DB, sspID uuid.UUID) string {
	var sc relational.SystemCharacteristics
	if err := db.WithContext(ctx).
		Select("system_name_short", "system_name").
		First(&sc, "system_security_plan_id = ?", sspID).Error; err != nil {
		return sspID.String()
	}

	name := strings.TrimSpace(sc.SystemNameShort)
	if name != "" {
		return name
	}
	name = strings.TrimSpace(sc.SystemName)
	if name != "" {
		return name
	}
	return sspID.String()
}

func resolveRiskURL(webBaseURL string, riskID uuid.UUID) string {
	base := strings.TrimRight(webBaseURL, "/")
	return base + "/risks/" + riskID.String()
}

func startOfISOWeekUTC(t time.Time) time.Time {
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	wd := int(d.Weekday())
	if wd == 0 {
		wd = 7
	}
	return d.AddDate(0, 0, -(wd - 1))
}
