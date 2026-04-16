package worker

// poam_digest_worker.go — BCH-1186 Phase 3 (Digest)
//
// Implements two River workers:
//
//  1. PoamOpenDigestSchedulerWorker  (periodic, queue: digest)
//     Resolves all unique recipients who have open/in-progress/overdue POAM
//     items and enqueues one PoamOpenDigestArgs job per recipient.
//
//  2. PoamOpenDigestWorker  (per-recipient, queue: digest)
//     Loads all POAM items for the recipient, classifies them into five
//     buckets (new, overdue, approaching deadline, milestone due soon, stale),
//     and sends a single grouped digest email.
//
// Idempotency:
//   - Scheduler: ByArgs + ByPeriod (24h daily / 7d weekly) — running twice in
//     the same window produces no duplicate scheduler jobs.
//   - Digest worker: ByArgs (RecipientUserID + WindowStart + WindowEnd) +
//     ByPeriod — running the digest worker twice for the same recipient and
//     window sends only one email.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	poamDigestWindowDaily  = "daily"
	poamDigestWindowWeekly = "weekly"

	poamDigestDailyPeriod  = 24 * time.Hour
	poamDigestWeeklyPeriod = 7 * 24 * time.Hour

	// A POAM item is "approaching deadline" if its deadline is within 30 days.
	poamDigestApproachingHorizon = 30 * 24 * time.Hour
	// A milestone is "due soon" if its planned_completion_date is within 14 days.
	poamDigestMilestoneDueSoonHorizon = 14 * 24 * time.Hour
	// A POAM item is "stale" if it has been in open status with no update for > 30 days.
	poamDigestStaleAge = 30 * 24 * time.Hour
)

// Statuses that are considered "active" for digest purposes.
var poamDigestActiveStatuses = []string{
	string(poamsvc.PoamItemStatusOpen),
	string(poamsvc.PoamItemStatusInProgress),
	string(poamsvc.PoamItemStatusOverdue),
}

// ─── Digest window ────────────────────────────────────────────────────────────

type poamDigestWindow struct {
	Kind     string
	Start    time.Time
	End      time.Time
	ByPeriod time.Duration
}

func computePoamDigestWindow(now time.Time, kind string) (poamDigestWindow, error) {
	today := startOfDayUTC(now)
	switch kind {
	case poamDigestWindowWeekly:
		end := today
		start := end.Add(-poamDigestWeeklyPeriod)
		return poamDigestWindow{
			Kind:     poamDigestWindowWeekly,
			Start:    start,
			End:      end,
			ByPeriod: poamDigestWeeklyPeriod,
		}, nil
	case poamDigestWindowDaily, "":
		end := today
		start := end.Add(-poamDigestDailyPeriod)
		return poamDigestWindow{
			Kind:     poamDigestWindowDaily,
			Start:    start,
			End:      end,
			ByPeriod: poamDigestDailyPeriod,
		}, nil
	default:
		return poamDigestWindow{}, fmt.Errorf("unknown POAM digest window kind %q", kind)
	}
}

func parsePoamDigestWindowFromArgs(args PoamOpenDigestArgs) (poamDigestWindow, error) {
	start, err := time.Parse(time.RFC3339, args.WindowStart)
	if err != nil {
		return poamDigestWindow{}, fmt.Errorf("invalid window_start %q: %w", args.WindowStart, err)
	}
	end, err := time.Parse(time.RFC3339, args.WindowEnd)
	if err != nil {
		return poamDigestWindow{}, fmt.Errorf("invalid window_end %q: %w", args.WindowEnd, err)
	}
	byPeriod := poamDigestDailyPeriod
	if args.WindowKind == poamDigestWindowWeekly {
		byPeriod = poamDigestWeeklyPeriod
	}
	return poamDigestWindow{
		Kind:     args.WindowKind,
		Start:    start.UTC(),
		End:      end.UTC(),
		ByPeriod: byPeriod,
	}, nil
}

func normalizePoamDigestWindow(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case poamDigestWindowWeekly:
		return poamDigestWindowWeekly
	default:
		return poamDigestWindowDaily
	}
}

// ─── Email item types ─────────────────────────────────────────────────────────

// PoamDigestEmailItem represents a single POAM item row in the digest email.
// PoamItemID is carried for test assertions; it is not rendered in the template.
type PoamDigestEmailItem struct {
	PoamItemID     uuid.UUID // used for test assertions; not rendered in template
	Title          string
	SSPName        string
	Status         string
	Deadline       string // formatted date or "—"
	POCName        string
	MilestoneCount int
	PoamURL        string
}

// PoamMilestoneDigestEmailItem represents a single milestone row in the digest.
type PoamMilestoneDigestEmailItem struct {
	MilestoneTitle string
	PoamTitle      string
	SSPName        string
	DueDate        string
	PoamURL        string
}

// poamDigestClassification holds the five bucketed sections of the digest.
type poamDigestClassification struct {
	NewSinceLastDigest  []PoamDigestEmailItem
	Overdue             []PoamDigestEmailItem
	ApproachingDeadline []PoamDigestEmailItem
	Stale               []PoamDigestEmailItem
	MilestonesDueSoon   []PoamMilestoneDigestEmailItem
}

type poamOpenDigestNotificationData struct {
	RecipientName          string
	PeriodLabel            string
	NewSinceLastDigest     []PoamDigestEmailItem
	Overdue                []PoamDigestEmailItem
	ApproachingDeadline    []PoamDigestEmailItem
	MilestonesDueSoon      []PoamMilestoneDigestEmailItem
	Stale                  []PoamDigestEmailItem
	PoamListURL            string
	HasNewSinceLast        bool
	HasOverdue             bool
	HasApproachingDeadline bool
	HasMilestonesDueSoon   bool
	HasStale               bool
	GeneratedAt            time.Time
}

func (c poamDigestClassification) Empty() bool {
	return len(c.NewSinceLastDigest) == 0 &&
		len(c.Overdue) == 0 &&
		len(c.ApproachingDeadline) == 0 &&
		len(c.Stale) == 0 &&
		len(c.MilestonesDueSoon) == 0
}

// ─── Classification predicates ────────────────────────────────────────────────

func isPoamNewSinceWindow(item *poamsvc.PoamItem, window poamDigestWindow) bool {
	return containsPoamStatus(poamDigestActiveStatuses, item.Status) &&
		!item.CreatedAt.Before(window.Start) &&
		item.CreatedAt.Before(window.End)
}

func isPoamOverdue(item *poamsvc.PoamItem) bool {
	return item.Status == string(poamsvc.PoamItemStatusOverdue)
}

func isPoamApproachingDeadline(item *poamsvc.PoamItem, now time.Time) bool {
	if item.Status == string(poamsvc.PoamItemStatusOverdue) ||
		item.Status == string(poamsvc.PoamItemStatusCompleted) {
		return false
	}
	if item.PlannedCompletionDate == nil {
		return false
	}
	deadline := item.PlannedCompletionDate.UTC()
	return deadline.After(now) && !deadline.After(now.Add(poamDigestApproachingHorizon))
}

func isPoamStale(item *poamsvc.PoamItem, now time.Time) bool {
	if item.Status != string(poamsvc.PoamItemStatusOpen) {
		return false
	}
	lastUpdate := item.UpdatedAt
	if item.CreatedAt.After(lastUpdate) {
		lastUpdate = item.CreatedAt
	}
	return !lastUpdate.UTC().After(now.Add(-poamDigestStaleAge))
}

func isMilestoneDueSoon(milestone *poamsvc.PoamItemMilestone, now time.Time) bool {
	if milestone.Status == string(poamsvc.MilestoneStatusCompleted) {
		return false
	}
	if milestone.PlannedCompletionDate == nil {
		return false
	}
	due := milestone.PlannedCompletionDate.UTC()
	return due.After(now) && !due.After(now.Add(poamDigestMilestoneDueSoonHorizon))
}

func containsPoamStatus(statuses []string, target string) bool {
	for _, s := range statuses {
		if s == target {
			return true
		}
	}
	return false
}

// ─── DB query helpers ─────────────────────────────────────────────────────────

// loadPoamDigestRecipientUserIDs returns the distinct set of user IDs that are
// either the primary_owner_user_id of an active POAM item or an SSP owner of
// an SSP that has active POAM items.
func loadPoamDigestRecipientUserIDs(ctx context.Context, db *gorm.DB, logger *zap.SugaredLogger) ([]uuid.UUID, error) {
	type row struct {
		UserID string `gorm:"column:user_id"`
	}
	var rows []row
	query := `
		SELECT DISTINCT CAST(primary_owner_user_id AS TEXT) AS user_id
		FROM ccf_poam_items
		WHERE status IN ? AND primary_owner_user_id IS NOT NULL
	`
	if err := db.WithContext(ctx).Raw(query, poamDigestActiveStatuses).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("loadPoamDigestRecipientUserIDs: %w", err)
	}
	result := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		id, err := uuid.Parse(strings.TrimSpace(r.UserID))
		if err != nil {
			logger.Warnw("loadPoamDigestRecipientUserIDs: skipping unparseable user ID", "raw", r.UserID)
			continue
		}
		result = append(result, id)
	}
	return result, nil
}

// loadRecipientDigestPoamItems returns all active POAM items where the given
// user is the primary_owner_user_id, with Milestones preloaded.
func loadRecipientDigestPoamItems(ctx context.Context, db *gorm.DB, recipientUserID uuid.UUID) ([]poamsvc.PoamItem, error) {
	var items []poamsvc.PoamItem
	err := db.WithContext(ctx).
		Preload("Milestones").
		Where("status IN ? AND primary_owner_user_id = ?", poamDigestActiveStatuses, recipientUserID).
		Find(&items).Error
	if err != nil {
		return nil, fmt.Errorf("loadRecipientDigestPoamItems: %w", err)
	}
	return items, nil
}

// ─── Classification ───────────────────────────────────────────────────────────

func classifyPoamDigest(
	items []poamsvc.PoamItem,
	sspNames map[uuid.UUID]string,
	webBaseURL string,
	now time.Time,
	window poamDigestWindow,
) poamDigestClassification {
	var c poamDigestClassification

	for i := range items {
		item := &items[i]
		if item.ID == uuid.Nil {
			continue
		}

		sspName := sspNames[item.SspID]
		if sspName == "" {
			sspName = item.SspID.String()
		}

		deadline := "—"
		if item.PlannedCompletionDate != nil {
			deadline = item.PlannedCompletionDate.UTC().Format("02 Jan 2006")
		}

		pocName := ""
		if item.PrimaryOwnerUserID != nil {
			pocName = (*item.PrimaryOwnerUserID).String()
		}

		milestoneCount := len(item.Milestones)
		poamURL := fmt.Sprintf("%s/poam-items/%s", strings.TrimRight(webBaseURL, "/"), item.ID.String())
		emailItem := PoamDigestEmailItem{
			PoamItemID:     item.ID,
			Title:          item.Title,
			SSPName:        sspName,
			Status:         string(item.Status),
			Deadline:       deadline,
			POCName:        pocName,
			MilestoneCount: milestoneCount,
			PoamURL:        poamURL,
		}

		if isPoamNewSinceWindow(item, window) {
			c.NewSinceLastDigest = append(c.NewSinceLastDigest, emailItem)
		}
		if isPoamOverdue(item) {
			c.Overdue = append(c.Overdue, emailItem)
		}
		if isPoamApproachingDeadline(item, now) {
			c.ApproachingDeadline = append(c.ApproachingDeadline, emailItem)
		}
		if isPoamStale(item, now) {
			c.Stale = append(c.Stale, emailItem)
		}

		// Milestone due-soon bucket.
		for j := range item.Milestones {
			ms := &item.Milestones[j]
			if isMilestoneDueSoon(ms, now) {
				dueDate := "—"
				if ms.PlannedCompletionDate != nil {
					dueDate = ms.PlannedCompletionDate.UTC().Format("02 Jan 2006")
				}
				c.MilestonesDueSoon = append(c.MilestonesDueSoon, PoamMilestoneDigestEmailItem{
					MilestoneTitle: ms.Title,
					PoamTitle:      item.Title,
					SSPName:        sspName,
					DueDate:        dueDate,
					PoamURL:        poamURL,
				})
			}
		}
	}

	return c
}

// ─── Scheduler worker ─────────────────────────────────────────────────────────

// PoamOpenDigestSchedulerWorker is the periodic River job that resolves all
// POAM digest recipients and enqueues one PoamOpenDigestArgs job per recipient.
type PoamOpenDigestSchedulerWorker struct {
	db         *gorm.DB
	client     workflow.RiverClient
	windowKind string
	logger     *zap.SugaredLogger
	now        func() time.Time
}

func NewPoamOpenDigestSchedulerWorker(
	db *gorm.DB,
	client workflow.RiverClient,
	windowKind string,
	logger *zap.SugaredLogger,
) *PoamOpenDigestSchedulerWorker {
	return &PoamOpenDigestSchedulerWorker{
		db:         db,
		client:     client,
		windowKind: normalizePoamDigestWindow(windowKind),
		logger:     logger,
		now:        time.Now,
	}
}

func (w *PoamOpenDigestSchedulerWorker) Work(ctx context.Context, _ *river.Job[PoamOpenDigestSchedulerArgs]) error {
	window, err := computePoamDigestWindow(w.now().UTC(), w.windowKind)
	if err != nil {
		return fmt.Errorf("poam open digest scheduler: invalid window: %w", err)
	}

	recipientIDs, err := loadPoamDigestRecipientUserIDs(ctx, w.db, w.logger)
	if err != nil {
		return fmt.Errorf("poam open digest scheduler: resolve recipients failed: %w", err)
	}
	if len(recipientIDs) == 0 {
		w.logger.Infow("PoamOpenDigestSchedulerWorker: no recipients found")
		return nil
	}

	params := make([]river.InsertManyParams, 0, len(recipientIDs))
	for _, recipientID := range recipientIDs {
		params = append(params, river.InsertManyParams{
			Args: PoamOpenDigestArgs{
				RecipientUserID: recipientID,
				WindowStart:     window.Start.Format(time.RFC3339),
				WindowEnd:       window.End.Format(time.RFC3339),
				WindowKind:      window.Kind,
			},
			InsertOpts: JobInsertOptionsForPoamDigest(window.ByPeriod),
		})
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("poam open digest scheduler: enqueue failed: %w", err)
	}

	w.logger.Infow("PoamOpenDigestSchedulerWorker: enqueued digest jobs",
		"recipient_count", len(recipientIDs),
		"window_kind", window.Kind,
		"window_start", window.Start,
		"window_end", window.End,
	)
	return nil
}

// ─── Digest worker ────────────────────────────────────────────────────────────

// PoamOpenDigestWorker builds and dispatches the grouped POAM digest notification for a
// single recipient.
type PoamOpenDigestWorker struct {
	db                          *gorm.DB
	emailService                EmailService
	userRepo                    UserRepository
	webBaseURL                  string
	notificationRuntimeProvider notification.RuntimeProvider
	logger                      *zap.SugaredLogger
	now                         func() time.Time
}

func NewPoamOpenDigestWorker(
	db *gorm.DB,
	emailService EmailService,
	userRepo UserRepository,
	webBaseURL string,
	logger *zap.SugaredLogger,
) *PoamOpenDigestWorker {
	return NewPoamOpenDigestWorkerWithRuntimeProvider(
		db,
		emailService,
		userRepo,
		webBaseURL,
		newWorkerNotificationRuntimeProvider(emailService, nil, func() notification.WorkerEnqueuer { return nil }),
		logger,
	)
}

func NewPoamOpenDigestWorkerWithRuntimeProvider(
	db *gorm.DB,
	emailService EmailService,
	userRepo UserRepository,
	webBaseURL string,
	runtimeProvider notification.RuntimeProvider,
	logger *zap.SugaredLogger,
) *PoamOpenDigestWorker {
	worker := &PoamOpenDigestWorker{
		db:                          db,
		emailService:                emailService,
		userRepo:                    userRepo,
		webBaseURL:                  webBaseURL,
		notificationRuntimeProvider: runtimeProvider,
		logger:                      logger,
		now:                         time.Now,
	}
	if worker.notificationRuntimeProvider == nil {
		worker.notificationRuntimeProvider = newWorkerNotificationRuntimeProvider(
			emailService,
			nil,
			func() notification.WorkerEnqueuer { return nil },
		)
	}

	return worker
}

func (w *PoamOpenDigestWorker) Work(ctx context.Context, job *river.Job[PoamOpenDigestArgs]) error {
	args := job.Args

	user, err := w.userRepo.FindUserByID(ctx, args.RecipientUserID.String())
	if err != nil {
		w.logger.Warnw("PoamOpenDigestWorker: user not found, skipping",
			"user_id", args.RecipientUserID,
			"error", err,
		)
		return nil
	}

	if w.db == nil {
		return fmt.Errorf("PoamOpenDigestWorker: db is nil")
	}

	window, err := parsePoamDigestWindowFromArgs(args)
	if err != nil {
		return fmt.Errorf("poam open digest: invalid job args: %w", err)
	}

	items, err := loadRecipientDigestPoamItems(ctx, w.db, args.RecipientUserID)
	if err != nil {
		return fmt.Errorf("poam open digest: load items failed: %w", err)
	}
	if len(items) == 0 {
		w.logger.Debugw("PoamOpenDigestWorker: no POAM items for recipient, skipping",
			"user_id", args.RecipientUserID,
		)
		return nil
	}

	// Resolve SSP display names for all items (helper takes []PoamItem directly).
	sspNames, err := resolvePoamSSPDisplayNames(ctx, w.db, items)
	if err != nil {
		w.logger.Warnw("PoamOpenDigestWorker: SSP name resolution failed, using UUIDs", "error", err)
		sspNames = make(map[string]string)
	}

	// Convert map[string]string → map[uuid.UUID]string for classifyPoamDigest.
	sspNamesByUUID := make(map[uuid.UUID]string, len(sspNames))
	for k, v := range sspNames {
		if id, parseErr := uuid.Parse(k); parseErr == nil {
			sspNamesByUUID[id] = v
		}
	}

	classification := classifyPoamDigest(items, sspNamesByUUID, w.webBaseURL, w.now().UTC(), window)
	if classification.Empty() {
		w.logger.Debugw("PoamOpenDigestWorker: no digestable items after classification, skipping",
			"user_id", args.RecipientUserID,
		)
		return nil
	}

	periodLabel := formatPoamDigestPeriodLabel(window)
	poamListURL := fmt.Sprintf("%s/poam-items", strings.TrimRight(w.webBaseURL, "/"))

	data := poamOpenDigestNotificationData{
		RecipientName:          user.FullName(),
		PeriodLabel:            periodLabel,
		NewSinceLastDigest:     classification.NewSinceLastDigest,
		Overdue:                classification.Overdue,
		ApproachingDeadline:    classification.ApproachingDeadline,
		MilestonesDueSoon:      classification.MilestonesDueSoon,
		Stale:                  classification.Stale,
		PoamListURL:            poamListURL,
		HasNewSinceLast:        len(classification.NewSinceLastDigest) > 0,
		HasOverdue:             len(classification.Overdue) > 0,
		HasApproachingDeadline: len(classification.ApproachingDeadline) > 0,
		HasMilestonesDueSoon:   len(classification.MilestonesDueSoon) > 0,
		HasStale:               len(classification.Stale) > 0,
		GeneratedAt:            w.now().UTC(),
	}

	notificationService := newPoamNotificationServiceFromFactory(
		w.notificationRuntimeProvider.NewRuntimeFactory(nil),
		w.emailService,
		newNotificationUserRepositoryAdapter(w.userRepo, user),
	)

	if err := notificationService.Dispatch(
		ctx,
		buildPoamOpenDigestNotificationRequest(args, data),
	); err != nil {
		return fmt.Errorf("dispatch poam-open-digest notification: %w", err)
	}

	w.logger.Infow("PoamOpenDigestWorker: digest notifications sent",
		"user_id", args.RecipientUserID,
		"new_count", len(classification.NewSinceLastDigest),
		"overdue_count", len(classification.Overdue),
		"approaching_count", len(classification.ApproachingDeadline),
		"milestones_due_soon_count", len(classification.MilestonesDueSoon),
		"stale_count", len(classification.Stale),
	)
	return nil
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

func formatPoamDigestPeriodLabel(window poamDigestWindow) string {
	switch window.Kind {
	case poamDigestWindowWeekly:
		return fmt.Sprintf("Weekly digest — %s to %s",
			window.Start.Format("02 Jan 2006"),
			window.End.Add(-poamDigestDailyPeriod).Format("02 Jan 2006"),
		)
	default:
		return "Daily digest — " + window.Start.Format("02 Jan 2006")
	}
}
