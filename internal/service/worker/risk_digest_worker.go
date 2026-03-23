package worker

import (
	"context"
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

const (
	riskDigestWindowDaily  = "daily"
	riskDigestWindowWeekly = "weekly"

	riskDigestDailyPeriod           = 24 * time.Hour
	riskDigestWeeklyPeriod          = 7 * 24 * time.Hour
	riskDigestOverdueActionAge      = 30 * 24 * time.Hour
	riskDigestStatusChangeGrace     = time.Minute
	riskDigestStaleAge              = 30 * 24 * time.Hour
	riskDigestDueReviewHorizon      = 30 * 24 * time.Hour
	riskDigestPeriodicDailyFallback = "0 0 11 * * *"
)

var riskDigestUnaddressedStatuses = []string{
	string(riskrel.RiskStatusOpen),
	string(riskrel.RiskStatusInvestigating),
	string(riskrel.RiskStatusMitigatingPlanned),
}

var riskDigestRecipientStatuses = []string{
	string(riskrel.RiskStatusOpen),
	string(riskrel.RiskStatusInvestigating),
	string(riskrel.RiskStatusMitigatingPlanned),
	string(riskrel.RiskStatusRiskAccepted),
}

type riskDigestWindow struct {
	Kind      string
	Start     time.Time
	End       time.Time
	ByPeriod  time.Duration
	PeriodTag string
}

type RiskDigestEmailItem struct {
	Title          string
	SSPName        string
	Status         string
	Severity       string
	OwnerName      string
	ReviewDeadline string
	RiskURL        string
}

type riskDigestClassification struct {
	NewSinceLastDigest []RiskDigestEmailItem
	OverdueForAction   []RiskDigestEmailItem
	Stale              []RiskDigestEmailItem
	OverdueReview      []RiskDigestEmailItem
	DueForReview       []RiskDigestEmailItem
}

func (c riskDigestClassification) Empty() bool {
	return len(c.NewSinceLastDigest) == 0 &&
		len(c.OverdueForAction) == 0 &&
		len(c.Stale) == 0 &&
		len(c.OverdueReview) == 0 &&
		len(c.DueForReview) == 0
}

type RiskOpenDigestSchedulerWorker struct {
	db         *gorm.DB
	client     workflow.RiverClient
	windowKind string
	logger     *zap.SugaredLogger
	now        func() time.Time
}

func NewRiskOpenDigestSchedulerWorker(db *gorm.DB, client workflow.RiverClient, windowKind string, logger *zap.SugaredLogger) *RiskOpenDigestSchedulerWorker {
	return &RiskOpenDigestSchedulerWorker{
		db:         db,
		client:     client,
		windowKind: normalizeRiskDigestWindow(windowKind),
		logger:     logger,
		now:        time.Now,
	}
}

func (w *RiskOpenDigestSchedulerWorker) Work(ctx context.Context, _ *river.Job[RiskOpenDigestSchedulerArgs]) error {
	window, err := computeRiskDigestWindow(w.now().UTC(), w.windowKind)
	if err != nil {
		return fmt.Errorf("risk open digest scheduler: invalid window: %w", err)
	}

	recipientIDs, err := resolveRiskDigestRecipientUserIDs(ctx, w.db, w.logger)
	if err != nil {
		return fmt.Errorf("risk open digest scheduler: resolve recipients failed: %w", err)
	}
	if len(recipientIDs) == 0 {
		w.logger.Infow("RiskOpenDigestSchedulerWorker: no recipients found")
		return nil
	}

	params := make([]river.InsertManyParams, 0, len(recipientIDs))
	for _, recipientID := range recipientIDs {
		params = append(params, river.InsertManyParams{
			Args: RiskOpenDigestArgs{
				RecipientUserID: recipientID,
				WindowStart:     window.Start.Format(time.RFC3339),
				WindowEnd:       window.End.Format(time.RFC3339),
				WindowKind:      window.Kind,
			},
			InsertOpts: JobInsertOptionsForRiskDigest(window.ByPeriod),
		})
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("risk open digest scheduler: enqueue failed: %w", err)
	}

	w.logger.Infow("RiskOpenDigestSchedulerWorker: enqueued digest jobs",
		"recipient_count", len(recipientIDs),
		"window_kind", window.Kind,
		"window_start", window.Start,
		"window_end", window.End,
	)
	return nil
}

type RiskOpenDigestWorker struct {
	db           *gorm.DB
	emailService EmailService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
	now          func() time.Time
}

func NewRiskOpenDigestWorker(db *gorm.DB, emailService EmailService, userRepo UserRepository, webBaseURL string, logger *zap.SugaredLogger) *RiskOpenDigestWorker {
	return &RiskOpenDigestWorker{
		db:           db,
		emailService: emailService,
		userRepo:     userRepo,
		webBaseURL:   webBaseURL,
		logger:       logger,
		now:          time.Now,
	}
}

func (w *RiskOpenDigestWorker) Work(ctx context.Context, job *river.Job[RiskOpenDigestArgs]) error {
	args := job.Args

	user, err := w.userRepo.FindUserByID(ctx, args.RecipientUserID.String())
	if err != nil {
		w.logger.Warnw("RiskOpenDigestWorker: user not found, skipping",
			"user_id", args.RecipientUserID,
			"error", err,
		)
		return nil
	}
	if !user.RiskNotificationsSubscribed {
		w.logger.Debugw("RiskOpenDigestWorker: user unsubscribed, skipping", "user_id", args.RecipientUserID)
		return nil
	}
	if w.db == nil {
		return fmt.Errorf("RiskOpenDigestWorker: db is nil")
	}

	window, err := parseRiskDigestWindowFromArgs(args)
	if err != nil {
		return fmt.Errorf("risk open digest: invalid job args: %w", err)
	}

	risks, err := loadRecipientDigestRisks(ctx, w.db, args.RecipientUserID)
	if err != nil {
		return fmt.Errorf("risk open digest: load risks failed: %w", err)
	}
	if len(risks) == 0 {
		w.logger.Debugw("RiskOpenDigestWorker: no risks for recipient, skipping", "user_id", args.RecipientUserID)
		return nil
	}

	classification, err := classifyRiskDigest(ctx, w.db, risks, w.webBaseURL, w.now().UTC(), window)
	if err != nil {
		return fmt.Errorf("risk open digest: classify failed: %w", err)
	}
	if classification.Empty() {
		w.logger.Debugw("RiskOpenDigestWorker: no digestable risks after classification, skipping", "user_id", args.RecipientUserID)
		return nil
	}

	templateData := map[string]interface{}{
		"RecipientName":       user.FullName(),
		"PeriodLabel":         formatRiskDigestPeriodLabel(window),
		"NewSinceLastDigest":  classification.NewSinceLastDigest,
		"OverdueForAction":    classification.OverdueForAction,
		"StaleRisks":          classification.Stale,
		"OverdueReview":       classification.OverdueReview,
		"DueForReview":        classification.DueForReview,
		"RisksURL":            strings.TrimRight(w.webBaseURL, "/") + "/risks",
		"HasNewSinceLast":     len(classification.NewSinceLastDigest) > 0,
		"HasOverdueForAction": len(classification.OverdueForAction) > 0,
		"HasStaleRisks":       len(classification.Stale) > 0,
		"HasOverdueReview":    len(classification.OverdueReview) > 0,
		"HasDueForReview":     len(classification.DueForReview) > 0,
	}

	htmlBody, textBody, err := w.emailService.UseTemplate("risk-open-digest", templateData)
	if err != nil {
		return fmt.Errorf("risk open digest: render template failed: %w", err)
	}

	message := &types.Message{
		From:     w.emailService.GetDefaultFromAddress(),
		To:       []string{user.Email},
		Subject:  fmt.Sprintf("Your risk digest — %s", formatDate(w.now().UTC())),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		return fmt.Errorf("risk open digest: send email failed: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("risk open digest: email send failed: %s", result.Error)
	}

	w.logger.Infow("RiskOpenDigestWorker: digest email sent",
		"user_id", args.RecipientUserID,
		"new_count", len(classification.NewSinceLastDigest),
		"overdue_count", len(classification.OverdueForAction),
		"stale_count", len(classification.Stale),
		"overdue_review_count", len(classification.OverdueReview),
		"due_review_count", len(classification.DueForReview),
		"message_id", result.MessageID,
	)
	return nil
}

func computeRiskDigestWindow(now time.Time, windowKind string) (riskDigestWindow, error) {
	switch normalizeRiskDigestWindow(windowKind) {
	case "none":
		end := startOfDayUTC(now.Add(24 * time.Hour)) // include day of the digest
		return riskDigestWindow{
			Kind:      "none",
			Start:     end.Add(-riskDigestDailyPeriod),
			End:       end,
			ByPeriod:  time.Minute,
			PeriodTag: formatDate(end.Add(-time.Minute)),
		}, nil
	case riskDigestWindowDaily:
		end := startOfDayUTC(now)
		return riskDigestWindow{
			Kind:      riskDigestWindowDaily,
			Start:     end.Add(-riskDigestDailyPeriod),
			End:       end,
			ByPeriod:  riskDigestDailyPeriod,
			PeriodTag: formatDate(end.Add(-riskDigestDailyPeriod)),
		}, nil
	case riskDigestWindowWeekly:
		end := startOfISOWeekUTC(now)
		return riskDigestWindow{
			Kind:      riskDigestWindowWeekly,
			Start:     end.Add(-riskDigestWeeklyPeriod),
			End:       end,
			ByPeriod:  riskDigestWeeklyPeriod,
			PeriodTag: formatDate(end.Add(-riskDigestWeeklyPeriod)),
		}, nil
	default:
		return riskDigestWindow{}, fmt.Errorf("unsupported risk digest window %q", windowKind)
	}
}

func parseRiskDigestWindowFromArgs(args RiskOpenDigestArgs) (riskDigestWindow, error) {
	start, err := time.Parse(time.RFC3339, args.WindowStart)
	if err != nil {
		return riskDigestWindow{}, fmt.Errorf("parse window_start: %w", err)
	}
	end, err := time.Parse(time.RFC3339, args.WindowEnd)
	if err != nil {
		return riskDigestWindow{}, fmt.Errorf("parse window_end: %w", err)
	}
	window, err := computeRiskDigestWindow(end, args.WindowKind)
	if err != nil {
		return riskDigestWindow{}, err
	}
	window.Start = start.UTC()
	window.End = end.UTC()
	if !window.Start.Before(window.End) {
		return riskDigestWindow{}, fmt.Errorf("window_start must be before window_end")
	}
	return window, nil
}

func resolveRiskDigestRecipientUserIDs(ctx context.Context, db *gorm.DB, logger *zap.SugaredLogger) ([]uuid.UUID, error) {
	type row struct {
		UserID string `gorm:"column:user_id"`
	}

	var rows []row
	query := `
		SELECT recipients.user_id
		FROM (
			SELECT DISTINCT CAST(r.primary_owner_user_id AS TEXT) AS user_id
			FROM risk_register_risks r
			WHERE r.status IN ? AND r.primary_owner_user_id IS NOT NULL
			UNION
			SELECT DISTINCT roa.owner_ref AS user_id
			FROM risk_owner_assignments roa
			JOIN risk_register_risks r ON r.id = roa.risk_id
			WHERE r.status IN ? AND roa.owner_kind = ?
		) AS recipients
		ORDER BY recipients.user_id
	`
	if err := db.WithContext(ctx).Raw(query, riskDigestRecipientStatuses, riskDigestRecipientStatuses, "user").Scan(&rows).Error; err != nil {
		return nil, err
	}

	recipients := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		recipientID, err := uuid.Parse(strings.TrimSpace(row.UserID))
		if err != nil {
			if logger != nil {
				logger.Warnw("RiskOpenDigestSchedulerWorker: skipping invalid recipient user ID",
					"user_id", row.UserID,
					"error", err,
				)
			}
			continue
		}
		recipients = append(recipients, recipientID)
	}
	return recipients, nil
}

func loadRecipientDigestRisks(ctx context.Context, db *gorm.DB, recipientID uuid.UUID) ([]riskrel.Risk, error) {
	var risks []riskrel.Risk
	err := db.WithContext(ctx).
		Where("status IN ?", riskDigestRecipientStatuses).
		Where(
			"primary_owner_user_id = ? OR EXISTS (SELECT 1 FROM risk_owner_assignments roa WHERE roa.risk_id = risk_register_risks.id AND roa.owner_kind = ? AND roa.owner_ref = ?)",
			recipientID,
			"user",
			recipientID.String(),
		).
		Find(&risks).Error
	return risks, err
}

func classifyRiskDigest(
	ctx context.Context,
	db *gorm.DB,
	risks []riskrel.Risk,
	webBaseURL string,
	now time.Time,
	window riskDigestWindow,
) (riskDigestClassification, error) {
	var classification riskDigestClassification
	if len(risks) == 0 {
		return classification, nil
	}

	ownersByRiskID, err := resolveRiskOwnerUserIDsBatch(ctx, db, risks)
	if err != nil {
		return classification, fmt.Errorf("resolve owners failed: %w", err)
	}
	ownerNamesByUserID, err := loadRiskDigestOwnerNames(ctx, db, ownersByRiskID)
	if err != nil {
		return classification, fmt.Errorf("load owner names failed: %w", err)
	}
	sspNamesByID, err := loadRiskDigestSSPNames(ctx, db, risks)
	if err != nil {
		return classification, fmt.Errorf("load SSP names failed: %w", err)
	}
	lastStatusChangeByRiskID, err := loadRiskDigestLastStatusChangeMap(ctx, db, risks)
	if err != nil {
		return classification, fmt.Errorf("load last status changes failed: %w", err)
	}

	for i := range risks {
		risk := &risks[i]
		if risk.ID == nil {
			continue
		}
		item, ok := buildRiskDigestEmailItem(risk, sspNamesByID, ownersByRiskID[*risk.ID], ownerNamesByUserID, webBaseURL)
		if !ok {
			continue
		}

		if isRiskNewSinceWindow(risk, window) {
			classification.NewSinceLastDigest = append(classification.NewSinceLastDigest, item)
		}
		if isRiskOverdueForAction(risk, now, lastStatusChangeByRiskID[*risk.ID]) {
			classification.OverdueForAction = append(classification.OverdueForAction, item)
		}
		if isRiskStale(risk, now) {
			classification.Stale = append(classification.Stale, item)
		}
		if isRiskReviewOverdue(risk, now) {
			classification.OverdueReview = append(classification.OverdueReview, item)
		}
		if isRiskDueForReview(risk, now) {
			classification.DueForReview = append(classification.DueForReview, item)
		}
	}

	sort.Slice(classification.NewSinceLastDigest, func(i, j int) bool {
		return classification.NewSinceLastDigest[i].Title < classification.NewSinceLastDigest[j].Title
	})
	sort.Slice(classification.OverdueForAction, func(i, j int) bool {
		return classification.OverdueForAction[i].Title < classification.OverdueForAction[j].Title
	})
	sort.Slice(classification.Stale, func(i, j int) bool { return classification.Stale[i].Title < classification.Stale[j].Title })
	sort.Slice(classification.OverdueReview, func(i, j int) bool {
		return classification.OverdueReview[i].Title < classification.OverdueReview[j].Title
	})
	sort.Slice(classification.DueForReview, func(i, j int) bool {
		return classification.DueForReview[i].Title < classification.DueForReview[j].Title
	})

	return classification, nil
}

func buildRiskDigestEmailItem(
	risk *riskrel.Risk,
	sspNamesByID map[uuid.UUID]string,
	ownerIDs []uuid.UUID,
	ownerNamesByUserID map[uuid.UUID]string,
	webBaseURL string,
) (RiskDigestEmailItem, bool) {
	if risk == nil || risk.ID == nil {
		return RiskDigestEmailItem{}, false
	}

	sspName := strings.TrimSpace(sspNamesByID[risk.SSPID])
	if sspName == "" {
		sspName = risk.SSPID.String()
	}

	item := RiskDigestEmailItem{
		Title:    strings.TrimSpace(risk.Title),
		SSPName:  sspName,
		Status:   risk.Status,
		Severity: formatRiskDigestSeverity(risk.Likelihood, risk.Impact),
		RiskURL:  resolveRiskURL(webBaseURL, *risk.ID),
	}
	if item.Title == "" {
		item.Title = risk.ID.String()
	}
	if risk.ReviewDeadline != nil {
		item.ReviewDeadline = formatDate(*risk.ReviewDeadline)
	}
	item.OwnerName = formatRiskDigestOwnerNames(ownerIDs, ownerNamesByUserID)
	return item, true
}

func loadRiskDigestOwnerNames(ctx context.Context, db *gorm.DB, ownersByRiskID map[uuid.UUID][]uuid.UUID) (map[uuid.UUID]string, error) {
	uniqueOwnerIDs := make([]uuid.UUID, 0)
	ownerSet := make(map[uuid.UUID]struct{})
	for _, ownerIDs := range ownersByRiskID {
		for _, ownerID := range ownerIDs {
			if _, ok := ownerSet[ownerID]; ok {
				continue
			}
			ownerSet[ownerID] = struct{}{}
			uniqueOwnerIDs = append(uniqueOwnerIDs, ownerID)
		}
	}
	if len(uniqueOwnerIDs) == 0 {
		return map[uuid.UUID]string{}, nil
	}

	var users []relational.User
	if err := db.WithContext(ctx).
		Where("id IN ?", uniqueOwnerIDs).
		Find(&users).Error; err != nil {
		return nil, err
	}

	names := make(map[uuid.UUID]string, len(users))
	for _, user := range users {
		if user.ID == nil {
			continue
		}
		name := strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName))
		if name == "" {
			name = user.Email
		}
		if name == "" {
			name = user.ID.String()
		}
		names[*user.ID] = name
	}
	return names, nil
}

func loadRiskDigestSSPNames(ctx context.Context, db *gorm.DB, risks []riskrel.Risk) (map[uuid.UUID]string, error) {
	sspIDs := make([]uuid.UUID, 0)
	sspSet := make(map[uuid.UUID]struct{})
	for i := range risks {
		sspID := risks[i].SSPID
		if _, ok := sspSet[sspID]; ok {
			continue
		}
		sspSet[sspID] = struct{}{}
		sspIDs = append(sspIDs, sspID)
	}
	if len(sspIDs) == 0 {
		return map[uuid.UUID]string{}, nil
	}

	var characteristics []relational.SystemCharacteristics
	if err := db.WithContext(ctx).
		Select("system_security_plan_id", "system_name_short", "system_name").
		Where("system_security_plan_id IN ?", sspIDs).
		Find(&characteristics).Error; err != nil {
		return nil, err
	}

	names := make(map[uuid.UUID]string, len(sspIDs))
	for _, sspID := range sspIDs {
		names[sspID] = sspID.String()
	}
	for _, characteristic := range characteristics {
		name := strings.TrimSpace(characteristic.SystemNameShort)
		if name == "" {
			name = strings.TrimSpace(characteristic.SystemName)
		}
		if name == "" {
			continue
		}
		names[characteristic.SystemSecurityPlanId] = name
	}
	return names, nil
}

func loadRiskDigestLastStatusChangeMap(ctx context.Context, db *gorm.DB, risks []riskrel.Risk) (map[uuid.UUID]time.Time, error) {
	riskIDs := make([]uuid.UUID, 0, len(risks))
	for i := range risks {
		if risks[i].ID != nil {
			riskIDs = append(riskIDs, *risks[i].ID)
		}
	}
	if len(riskIDs) == 0 {
		return map[uuid.UUID]time.Time{}, nil
	}

	type row struct {
		RiskID              uuid.UUID `gorm:"column:risk_id"`
		LastStatusChangedAt time.Time `gorm:"column:last_status_changed_at"`
	}

	var rows []row
	if err := db.WithContext(ctx).
		Table("risk_events").
		Select("risk_id, MAX(occurred_at) AS last_status_changed_at").
		Where("risk_id IN ? AND event_type = ?", riskIDs, string(riskrel.RiskEventTypeStatusChange)).
		Group("risk_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	result := make(map[uuid.UUID]time.Time, len(rows))
	for _, row := range rows {
		result[row.RiskID] = row.LastStatusChangedAt.UTC()
	}
	return result, nil
}

func isRiskNewSinceWindow(risk *riskrel.Risk, window riskDigestWindow) bool {
	return containsString(riskDigestUnaddressedStatuses, risk.Status) &&
		!risk.CreatedAt.Before(window.Start) &&
		risk.CreatedAt.Before(window.End)
}

func isRiskOverdueForAction(risk *riskrel.Risk, now time.Time, lastStatusChangedAt time.Time) bool {
	if !containsString(riskDigestUnaddressedStatuses, risk.Status) {
		return false
	}
	if now.Sub(risk.CreatedAt.UTC()) < riskDigestOverdueActionAge {
		return false
	}
	if lastStatusChangedAt.IsZero() {
		return true
	}
	return !lastStatusChangedAt.UTC().After(risk.CreatedAt.UTC().Add(riskDigestStatusChangeGrace))
}

func isRiskStale(risk *riskrel.Risk, now time.Time) bool {
	return containsString(riskDigestUnaddressedStatuses, risk.Status) &&
		!risk.LastSeenAt.UTC().After(now.Add(-riskDigestStaleAge))
}

func isRiskReviewOverdue(risk *riskrel.Risk, now time.Time) bool {
	return risk.Status == string(riskrel.RiskStatusRiskAccepted) &&
		risk.ReviewDeadline != nil &&
		!risk.ReviewDeadline.UTC().After(now)
}

func isRiskDueForReview(risk *riskrel.Risk, now time.Time) bool {
	return risk.Status == string(riskrel.RiskStatusRiskAccepted) &&
		risk.ReviewDeadline != nil &&
		risk.ReviewDeadline.UTC().After(now) &&
		!risk.ReviewDeadline.UTC().After(now.Add(riskDigestDueReviewHorizon))
}

func formatRiskDigestSeverity(likelihood, impact *string) string {
	parts := make([]string, 0, 2)
	if likelihood != nil && strings.TrimSpace(*likelihood) != "" {
		parts = append(parts, strings.TrimSpace(*likelihood))
	}
	if impact != nil && strings.TrimSpace(*impact) != "" {
		parts = append(parts, strings.TrimSpace(*impact))
	}
	return strings.Join(parts, " x ")
}

func formatRiskDigestOwnerNames(ownerIDs []uuid.UUID, ownerNamesByUserID map[uuid.UUID]string) string {
	if len(ownerIDs) == 0 {
		return ""
	}
	names := make([]string, 0, len(ownerIDs))
	for _, ownerID := range ownerIDs {
		name := ownerNamesByUserID[ownerID]
		if strings.TrimSpace(name) == "" {
			name = ownerID.String()
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

func formatRiskDigestPeriodLabel(window riskDigestWindow) string {
	switch window.Kind {
	case riskDigestWindowWeekly:
		return fmt.Sprintf("Weekly digest — %s to %s", formatDate(window.Start), formatDate(window.End.Add(-riskDigestDailyPeriod)))
	default:
		return "Daily digest — " + formatDate(window.Start)
	}
}

func normalizeRiskDigestWindow(windowKind string) string {
	switch strings.ToLower(strings.TrimSpace(windowKind)) {
	case "", riskDigestWindowDaily:
		return riskDigestWindowDaily
	case riskDigestWindowWeekly:
		return riskDigestWindowWeekly
	default:
		return strings.ToLower(strings.TrimSpace(windowKind))
	}
}

func startOfDayUTC(t time.Time) time.Time {
	return time.Date(t.UTC().Year(), t.UTC().Month(), t.UTC().Day(), 0, 0, 0, 0, time.UTC)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
