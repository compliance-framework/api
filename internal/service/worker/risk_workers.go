package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const riskScannerBatchSize = 1000

type riskNotificationData struct {
	OwnerName      string
	RiskTitle      string
	SSPName        string
	RiskStatus     string
	ReviewDeadline string
	LastSeenAt     string
	RiskURL        string
}

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

	// Duplicate active risks with same dedupe key.
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
	db                         *gorm.DB
	userRepo                   UserRepository
	notificationServiceFactory *RiskNotificationServiceFactory
	webBaseURL                 string
	logger                     *zap.SugaredLogger
}

func NewRiskReviewDueReminderWorker(
	db *gorm.DB,
	userRepo UserRepository,
	webBaseURL string,
	notificationServiceFactory *RiskNotificationServiceFactory,
	logger *zap.SugaredLogger,
) *RiskReviewDueReminderWorker {
	worker := &RiskReviewDueReminderWorker{
		db:                         db,
		userRepo:                   userRepo,
		notificationServiceFactory: notificationServiceFactory,
		webBaseURL:                 webBaseURL,
		logger:                     logger,
	}
	return worker
}

func (w *RiskReviewDueReminderWorker) Work(ctx context.Context, job *river.Job[RiskReviewDueReminderArgs]) error {
	if _, ok := normalizeRequestedDeliveryChannel(job.Args.Channel); !ok {
		w.logger.Warnw("RiskReviewDueReminderWorker: invalid delivery channel, skipping",
			"risk_id", job.Args.RiskID,
			"owner_user_id", job.Args.OwnerUserID,
			"channel", job.Args.Channel,
		)
		return nil
	}

	return dispatchRiskReminderNotification(
		ctx,
		w.db,
		w.userRepo,
		w.notificationServiceFactory,
		w.webBaseURL,
		w.logger,
		job.Args.RiskID,
		job.Args.OwnerUserID,
		func(userName string, data riskNotificationData) notification.Request {
			return buildRiskReviewDueReminderNotificationRequest(job.Args, userName, data)
		},
	)
}

type RiskReviewOverdueEscalationWorker struct {
	db                         *gorm.DB
	userRepo                   UserRepository
	notificationServiceFactory *RiskNotificationServiceFactory
	webBaseURL                 string
	logger                     *zap.SugaredLogger
}

func NewRiskReviewOverdueEscalationWorker(
	db *gorm.DB,
	userRepo UserRepository,
	webBaseURL string,
	notificationServiceFactory *RiskNotificationServiceFactory,
	logger *zap.SugaredLogger,
) *RiskReviewOverdueEscalationWorker {
	worker := &RiskReviewOverdueEscalationWorker{
		db:                         db,
		userRepo:                   userRepo,
		notificationServiceFactory: notificationServiceFactory,
		webBaseURL:                 webBaseURL,
		logger:                     logger,
	}
	return worker
}

func (w *RiskReviewOverdueEscalationWorker) Work(ctx context.Context, job *river.Job[RiskReviewOverdueEscalationArgs]) error {
	if _, ok := normalizeRequestedDeliveryChannel(job.Args.Channel); !ok {
		w.logger.Warnw("RiskReviewOverdueEscalationWorker: invalid delivery channel, skipping",
			"risk_id", job.Args.RiskID,
			"owner_user_id", job.Args.OwnerUserID,
			"channel", job.Args.Channel,
		)
		return nil
	}

	return dispatchRiskReminderNotification(
		ctx,
		w.db,
		w.userRepo,
		w.notificationServiceFactory,
		w.webBaseURL,
		w.logger,
		job.Args.RiskID,
		job.Args.OwnerUserID,
		func(userName string, data riskNotificationData) notification.Request {
			return buildRiskReviewOverdueEscalationNotificationRequest(job.Args, userName, data)
		},
	)
}

type RiskStaleOpenReminderWorker struct {
	db                         *gorm.DB
	userRepo                   UserRepository
	notificationServiceFactory *RiskNotificationServiceFactory
	webBaseURL                 string
	logger                     *zap.SugaredLogger
}

func NewRiskStaleOpenReminderWorker(
	db *gorm.DB,
	userRepo UserRepository,
	webBaseURL string,
	notificationServiceFactory *RiskNotificationServiceFactory,
	logger *zap.SugaredLogger,
) *RiskStaleOpenReminderWorker {
	worker := &RiskStaleOpenReminderWorker{
		db:                         db,
		userRepo:                   userRepo,
		notificationServiceFactory: notificationServiceFactory,
		webBaseURL:                 webBaseURL,
		logger:                     logger,
	}
	return worker
}

func (w *RiskStaleOpenReminderWorker) Work(ctx context.Context, job *river.Job[RiskStaleOpenReminderArgs]) error {
	if _, ok := normalizeRequestedDeliveryChannel(job.Args.Channel); !ok {
		w.logger.Warnw("RiskStaleOpenReminderWorker: invalid delivery channel, skipping",
			"risk_id", job.Args.RiskID,
			"owner_user_id", job.Args.OwnerUserID,
			"channel", job.Args.Channel,
		)
		return nil
	}

	return dispatchRiskReminderNotification(
		ctx,
		w.db,
		w.userRepo,
		w.notificationServiceFactory,
		w.webBaseURL,
		w.logger,
		job.Args.RiskID,
		job.Args.OwnerUserID,
		func(userName string, data riskNotificationData) notification.Request {
			return buildRiskStaleOpenReminderNotificationRequest(job.Args, userName, data)
		},
	)
}

func dispatchRiskReminderNotification(
	ctx context.Context,
	db *gorm.DB,
	userRepo UserRepository,
	notificationServiceFactory *RiskNotificationServiceFactory,
	webBaseURL string,
	logger *zap.SugaredLogger,
	riskID, ownerUserID uuid.UUID,
	buildRequest func(userName string, data riskNotificationData) notification.Request,
) error {
	if db == nil {
		return fmt.Errorf("risk notification worker: db is nil")
	}
	if userRepo == nil {
		return fmt.Errorf("risk notification worker: user repository is nil")
	}
	if notificationServiceFactory == nil {
		return fmt.Errorf("risk notification worker: notification service factory is nil")
	}

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
	notifier, err := notificationServiceFactory.New(newNotificationUserRepositoryAdapter(userRepo, user))
	if err != nil {
		return fmt.Errorf("risk notification worker: create notification service failed: %w", err)
	}
	data := buildRiskNotificationData(ctx, db, webBaseURL, user, risk, riskID)
	request := buildRequest(user.FullName(), data)
	if err := notifier.Dispatch(ctx, request); err != nil {
		return fmt.Errorf("dispatch %s notification: %w", request.Kind, err)
	}

	return nil
}

func buildRiskNotificationData(
	ctx context.Context,
	db *gorm.DB,
	webBaseURL string,
	user NotificationUser,
	risk riskrel.Risk,
	riskID uuid.UUID,
) riskNotificationData {
	riskTitle := strings.TrimSpace(risk.Title)
	if riskTitle == "" {
		riskTitle = riskID.String()
	}

	sspName := resolveSSPDisplayName(ctx, db, risk.SSPID)
	reviewDeadline := ""
	if risk.ReviewDeadline != nil {
		reviewDeadline = formatDate(*risk.ReviewDeadline)
	}

	data := riskNotificationData{
		OwnerName:      user.FullName(),
		RiskTitle:      riskTitle,
		SSPName:        sspName,
		RiskStatus:     risk.Status,
		ReviewDeadline: reviewDeadline,
		LastSeenAt:     formatDate(risk.LastSeenAt),
		RiskURL:        resolveRiskURL(webBaseURL, riskID),
	}

	return data
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
