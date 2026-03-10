package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
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

	var risks []riskrel.Risk
	if err := w.db.WithContext(ctx).
		Where("status = ? AND review_deadline IS NOT NULL AND review_deadline > ? AND review_deadline <= ?",
			string(riskrel.RiskStatusRiskAccepted), now, windowEnd).
		Find(&risks).Error; err != nil {
		return fmt.Errorf("risk deadline reminder scanner: query failed: %w", err)
	}

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
		w.logger.Infow("RiskReviewDeadlineReminderScannerWorker: no reminders to enqueue")
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("risk deadline reminder scanner: enqueue failed: %w", err)
	}

	w.logger.Infow("RiskReviewDeadlineReminderScannerWorker: enqueued reminders", "count", len(params))
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

	var risks []riskrel.Risk
	if err := w.db.WithContext(ctx).
		Where("status = ? AND review_deadline IS NOT NULL AND review_deadline < ?",
			string(riskrel.RiskStatusRiskAccepted), now).
		Find(&risks).Error; err != nil {
		return fmt.Errorf("risk overdue escalation scanner: query failed: %w", err)
	}

	ownersByRiskID, err := resolveRiskOwnerUserIDsBatch(ctx, w.db, risks)
	if err != nil {
		return fmt.Errorf("risk overdue escalation scanner: resolve owners failed: %w", err)
	}

	params := make([]river.InsertManyParams, 0, len(risks))
	reopenByRiskID := make(map[uuid.UUID]RiskReviewOverdueReopenArgs, len(risks))
	for i := range risks {
		risk := &risks[i]
		if risk.ID == nil {
			continue
		}
		ownerIDs := ownersByRiskID[*risk.ID]
		overdueWindow := now.Format("2006-01-02")
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

		if w.autoReopenEnabled {
			overdueFor := now.Sub(risk.ReviewDeadline.UTC())
			threshold := time.Duration(w.autoReopenThresholdDays) * 24 * time.Hour
			if overdueFor >= threshold {
				reopenByRiskID[*risk.ID] = RiskReviewOverdueReopenArgs{
					RiskID:         *risk.ID,
					ReviewDeadline: risk.ReviewDeadline.UTC().Format(time.RFC3339),
					ThresholdDays:  w.autoReopenThresholdDays,
				}
			}
		}
	}

	for _, args := range reopenByRiskID {
		params = append(params, river.InsertManyParams{
			Args:       args,
			InsertOpts: JobInsertOptionsForRiskWorkerUnique(24 * time.Hour),
		})
	}

	if len(params) == 0 {
		w.logger.Infow("RiskReviewOverdueEscalationScannerWorker: no escalations to enqueue")
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("risk overdue escalation scanner: enqueue failed: %w", err)
	}

	w.logger.Infow("RiskReviewOverdueEscalationScannerWorker: enqueued jobs", "count", len(params), "reopen_count", len(reopenByRiskID))
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

	var risks []riskrel.Risk
	if err := w.db.WithContext(ctx).
		Where("status IN ? AND last_seen_at <= ?",
			[]string{
				string(riskrel.RiskStatusOpen),
				string(riskrel.RiskStatusInvestigating),
				string(riskrel.RiskStatusMitigatingPlanned),
			},
			cutoff).
		Find(&risks).Error; err != nil {
		return fmt.Errorf("risk stale scanner: query failed: %w", err)
	}

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
		w.logger.Infow("RiskStaleRiskScannerWorker: no stale reminders to enqueue")
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("risk stale scanner: enqueue failed: %w", err)
	}

	w.logger.Infow("RiskStaleRiskScannerWorker: enqueued stale reminders", "count", len(params))
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

	// 1) Evidence failures without linked risks.
	var orphanEvidence []relational.Evidence
	orphanQuery := w.db.WithContext(ctx).Model(&relational.Evidence{})
	switch w.db.Name() {
	case "postgres":
		orphanQuery = orphanQuery.Where("status->>'state' = ?", relational.EvidenceStatusNotSatisfied)
	case "sqlite":
		orphanQuery = orphanQuery.Where("json_extract(status, '$.state') = ?", relational.EvidenceStatusNotSatisfied)
	default:
		orphanQuery = orphanQuery.Where("status->>'state' = ?", relational.EvidenceStatusNotSatisfied)
	}
	if err := orphanQuery.
		Where("NOT EXISTS (SELECT 1 FROM risk_evidence_links rel WHERE rel.evidence_id = evidences.id)").
		Find(&orphanEvidence).Error; err != nil {
		return fmt.Errorf("risk reconciliation scanner: query orphan evidence failed: %w", err)
	}

	for i := range orphanEvidence {
		e := &orphanEvidence[i]
		state := e.Status.Data().State
		if state == "" {
			state = relational.EvidenceStatusNotSatisfied
		}
		params = append(params, river.InsertManyParams{
			Args: RiskProcessEvidenceFailureArgs{
				EvidenceID:  *e.ID,
				EvidenceEnd: e.End.UTC().Format(time.RFC3339),
				Status:      state,
			},
			InsertOpts: JobInsertOptionsForRiskProcessEvidenceFailure(),
		})
	}

	// 2) Evidence-linked risks with missing subject links.
	var riskIDs []uuid.UUID
	if err := w.db.WithContext(ctx).
		Model(&riskrel.Risk{}).
		Select("risk_register_risks.id").
		Where("risk_register_risks.source_type = ? AND risk_register_risks.status <> ?",
			string(riskrel.RiskSourceTypeEvidenceAuto), string(riskrel.RiskStatusClosed)).
		Where("EXISTS (SELECT 1 FROM risk_evidence_links rel WHERE rel.risk_id = risk_register_risks.id)").
		Where("NOT EXISTS (SELECT 1 FROM risk_subject_links rsl WHERE rsl.risk_id = risk_register_risks.id)").
		Pluck("risk_register_risks.id", &riskIDs).Error; err != nil {
		return fmt.Errorf("risk reconciliation scanner: query missing subject links failed: %w", err)
	}

	if len(riskIDs) > 0 {
		type latestRiskEvidence struct {
			RiskID     uuid.UUID `gorm:"column:risk_id"`
			EvidenceID uuid.UUID `gorm:"column:evidence_id"`
		}
		var latestEvidence []latestRiskEvidence
		if err := w.db.WithContext(ctx).
			Table("risk_evidence_links rel").
			Select("rel.risk_id, rel.evidence_id").
			Joins("JOIN evidences e ON e.id = rel.evidence_id").
			Where("rel.risk_id IN ?", riskIDs).
			Where("EXISTS (SELECT 1 FROM evidence_subjects es WHERE es.evidence_id = rel.evidence_id)").
			Where(`NOT EXISTS (
				SELECT 1
				FROM risk_evidence_links rel2
				JOIN evidences e2 ON e2.id = rel2.evidence_id
				WHERE rel2.risk_id = rel.risk_id
				  AND (e2.end > e.end OR (e2.end = e.end AND rel2.evidence_id > rel.evidence_id))
			)`).
			Scan(&latestEvidence).Error; err != nil {
			return fmt.Errorf("risk reconciliation scanner: query latest evidence for missing subject links failed: %w", err)
		}

		evidenceIDs := make([]uuid.UUID, 0, len(latestEvidence))
		seenEvidenceIDs := make(map[uuid.UUID]struct{}, len(latestEvidence))
		for _, item := range latestEvidence {
			if _, seen := seenEvidenceIDs[item.EvidenceID]; seen {
				continue
			}
			seenEvidenceIDs[item.EvidenceID] = struct{}{}
			evidenceIDs = append(evidenceIDs, item.EvidenceID)
		}

		evidenceByID := make(map[uuid.UUID]relational.Evidence, len(evidenceIDs))
		if len(evidenceIDs) > 0 {
			var evidences []relational.Evidence
			if err := w.db.WithContext(ctx).Where("id IN ?", evidenceIDs).Find(&evidences).Error; err != nil {
				return fmt.Errorf("risk reconciliation scanner: load latest evidence records failed: %w", err)
			}
			for i := range evidences {
				if evidences[i].ID == nil {
					continue
				}
				evidenceByID[*evidences[i].ID] = evidences[i]
			}
		}

		for _, item := range latestEvidence {
			evidence, found := evidenceByID[item.EvidenceID]
			if !found {
				continue
			}
			state := evidence.Status.Data().State
			if state == "" {
				state = relational.EvidenceStatusNotSatisfied
			}
			params = append(params, river.InsertManyParams{
				Args: RiskProcessEvidenceFailureArgs{
					EvidenceID:  item.EvidenceID,
					EvidenceEnd: evidence.End.UTC().Format(time.RFC3339),
					Status:      state,
				},
				InsertOpts: JobInsertOptionsForRiskProcessEvidenceFailure(),
			})
		}
	}

	// 3) Duplicate active risks with same dedupe key.
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

	if len(params) == 0 {
		w.logger.Infow("RiskEvidenceReconciliationScannerWorker: no reconciliation jobs to enqueue")
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("risk reconciliation scanner: enqueue failed: %w", err)
	}

	w.logger.Infow("RiskEvidenceReconciliationScannerWorker: enqueued reconciliation jobs", "count", len(params))
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
		logger.Warnw("Risk notification worker: owner user not found, skipping", "risk_id", riskID, "owner_user_id", ownerUserID, "error", err)
		return nil
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

	riskSvc := riskrel.NewRiskService(w.db)
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
	riskSvc := riskrel.NewRiskService(w.db)
	risk, err := riskSvc.GetByID(job.Args.RiskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.logger.Warnw("RiskReviewOverdueReopenWorker: risk not found, skipping", "risk_id", job.Args.RiskID)
			return nil
		}
		return fmt.Errorf("risk overdue reopen: load risk failed: %w", err)
	}
	if risk.Status != string(riskrel.RiskStatusRiskAccepted) || risk.ReviewDeadline == nil {
		return nil
	}

	now := time.Now().UTC()
	threshold := time.Duration(job.Args.ThresholdDays) * 24 * time.Hour
	if now.Sub(risk.ReviewDeadline.UTC()) < threshold {
		return nil
	}

	oldStatus := risk.Status
	risk.Status = string(riskrel.RiskStatusInvestigating)
	risk.ReviewDeadline = nil
	if _, err := riskSvc.Update(riskrel.UpdateRiskParams{
		Risk:          risk,
		OldStatus:     oldStatus,
		StatusChanged: true,
	}); err != nil {
		return fmt.Errorf("risk overdue reopen: update risk failed: %w", err)
	}

	w.logger.Infow("RiskReviewOverdueReopenWorker: reopened overdue accepted risk",
		"risk_id", job.Args.RiskID,
		"threshold_days", job.Args.ThresholdDays,
	)
	return nil
}

func resolveRiskOwnerUserIDsBatch(ctx context.Context, db *gorm.DB, risks []riskrel.Risk) (map[uuid.UUID][]uuid.UUID, error) {
	ownerSetByRiskID := make(map[uuid.UUID]map[uuid.UUID]struct{}, len(risks))
	riskIDs := make([]uuid.UUID, 0, len(risks))
	for i := range risks {
		risk := &risks[i]
		if risk == nil || risk.ID == nil {
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

var systemCharacteristicsTableExistsCache sync.Map

func hasSystemCharacteristicsTable(ctx context.Context, db *gorm.DB) bool {
	sqlDB, err := db.DB()
	if err != nil {
		return false
	}
	if cached, ok := systemCharacteristicsTableExistsCache.Load(sqlDB); ok {
		return cached.(bool)
	}

	exists := db.WithContext(ctx).Migrator().HasTable(&relational.SystemCharacteristics{})
	systemCharacteristicsTableExistsCache.Store(sqlDB, exists)
	return exists
}

func resolveSSPDisplayName(ctx context.Context, db *gorm.DB, sspID uuid.UUID) string {
	if !hasSystemCharacteristicsTable(ctx, db) {
		return sspID.String()
	}

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
