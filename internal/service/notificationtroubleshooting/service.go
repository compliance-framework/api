package notificationtroubleshooting

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

const (
	ProviderStaleThresholdSeconds = 600
	SourceStaleThresholdSeconds   = 1800

	StatusPass    = "pass"
	StatusWarning = "warning"
	StatusFail    = "fail"
)

var notificationQueues = []string{"email", "slack", "digest", "workflow", "risk", "poam", "scheduler"}

var notificationJobKinds = []string{
	worker.JobTypeSendEmail,
	worker.JobTypeSendEmailFrom,
	worker.JobTypeSendSlackChannel,
	worker.JobTypeSendSlackDM,
	worker.JobTypeSendGlobalDigest,
	worker.JobTypeWorkflowTaskAssigned,
	worker.JobTypeWorkflowTaskDueSoon,
	worker.JobTypeWorkflowTaskDigest,
	worker.JobTypeWorkflowExecutionFailed,
	worker.JobTypeWorkflowDueSoonChecker,
	"workflow_task_digest_checker",
	"schedule_workflows",
	worker.JobTypeRiskReviewDeadlineReminderScanner,
	worker.JobTypeRiskReviewOverdueEscalationScanner,
	worker.JobTypeRiskStaleRiskScanner,
	worker.JobTypeRiskOpenDigestScheduler,
	worker.JobTypeRiskReviewDueReminder,
	worker.JobTypeRiskReviewOverdueEscalation,
	worker.JobTypeRiskStaleOpenReminder,
	worker.JobTypeRiskOpenDigest,
	worker.JobTypePoamDeadlineReminderScanner,
	worker.JobTypePoamOverdueTransitionScanner,
	worker.JobTypeMilestoneOverdueScannerScanner,
	worker.JobTypePoamOpenDigestScheduler,
	worker.JobTypePoamDeadlineReminder,
	worker.JobTypePoamOverdueNotification,
	worker.JobTypeMilestoneOverdueReminder,
	worker.JobTypePoamOpenDigest,
}

var providerJobKinds = map[string]struct{}{
	worker.JobTypeSendEmail:        {},
	worker.JobTypeSendEmailFrom:    {},
	worker.JobTypeSendSlackChannel: {},
	worker.JobTypeSendSlackDM:      {},
}

var (
	ErrInvalidJobsQuery            = errors.New("invalid notification troubleshooting jobs query")
	ErrUnsupportedNotificationName = errors.New("unsupported notification name")
)

func IsInvalidJobsQuery(err error) bool {
	return errors.Is(err, ErrInvalidJobsQuery)
}

func IsUnsupportedNotificationName(err error) bool {
	return errors.Is(err, ErrUnsupportedNotificationName)
}

type Service struct {
	db        *gorm.DB
	cfg       *config.Config
	providers notification.ProviderLookup
	now       func() time.Time
}

func New(db *gorm.DB, cfg *config.Config) *Service {
	return &Service{
		db:        db,
		cfg:       cfg,
		providers: notificationproviders.NewLookup(notificationproviders.WithConfig(cfg)),
		now:       time.Now,
	}
}

type HealthResponse struct {
	Worker        WorkerHealth             `json:"worker"`
	Providers     []ProviderStatus         `json:"providers"`
	Notifications []NotificationHealth     `json:"notifications"`
	Schedules     []ScheduleHealth         `json:"schedules"`
	Warnings      []TroubleshootingWarning `json:"warnings"`
}

type WorkerHealth struct {
	Enabled  bool           `json:"enabled"`
	Mode     string         `json:"mode"`
	PollOnly bool           `json:"pollOnly"`
	Queues   []QueueSummary `json:"queues"`
}

type QueueSummary struct {
	Name                  string     `json:"name"`
	MaxWorkers            int        `json:"maxWorkers"`
	Available             int64      `json:"available"`
	Retryable             int64      `json:"retryable"`
	Running               int64      `json:"running"`
	Scheduled             int64      `json:"scheduled"`
	Completed24h          int64      `json:"completed24h"`
	Discarded24h          int64      `json:"discarded24h"`
	OldestAvailableAt     *time.Time `json:"oldestAvailableAt"`
	StaleCount            int64      `json:"staleCount"`
	StaleThresholdSeconds int64      `json:"staleThresholdSeconds"`
}

type ProviderStatus struct {
	ProviderType string            `json:"providerType"`
	Enabled      bool              `json:"enabled"`
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type NotificationHealth struct {
	Name                   string                                `json:"name"`
	ConfiguredDestinations []ConfiguredSystemDestinationResponse `json:"configuredDestinations"`
	SubscriberCounts       SubscriberCounts                      `json:"subscriberCounts"`
	Warnings               []TroubleshootingWarning              `json:"warnings"`
}

type ConfiguredSystemDestinationResponse struct {
	ProviderType      string `json:"providerType"`
	DestinationTarget string `json:"destinationTarget"`
}

type SubscriberCounts struct {
	Email      int64 `json:"email"`
	Slack      int64 `json:"slack"`
	TotalUsers int64 `json:"totalUsers"`
}

type ScheduleHealth struct {
	Name         string      `json:"name"`
	JobKind      string      `json:"jobKind"`
	DeliveryKind string      `json:"deliveryKind,omitempty"`
	Queue        string      `json:"queue"`
	Enabled      bool        `json:"enabled"`
	Schedule     string      `json:"schedule"`
	NextRunAt    *time.Time  `json:"nextRunAt"`
	LastJob      *JobSummary `json:"lastJob,omitempty"`
}

type JobSummary struct {
	ID          int64      `json:"id"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"createdAt" format:"date-time"`
	FinalizedAt *time.Time `json:"finalizedAt" format:"date-time"`
}

type TroubleshootingWarning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Target   string `json:"target,omitempty"`
}

type JobsQuery struct {
	Queues           []string
	Provider         string
	NotificationKind string
	States           []string
	Since            *time.Time
	Limit            int
	Cursor           string
}

type JobsListResponse struct {
	Data       []JobListItem `json:"data"`
	Pagination Pagination    `json:"pagination"`
}

type Pagination struct {
	NextCursor string `json:"nextCursor,omitempty"`
}

type JobListItem struct {
	ID               int64      `json:"id"`
	State            string     `json:"state"`
	Queue            string     `json:"queue"`
	Kind             string     `json:"kind"`
	Attempt          int        `json:"attempt"`
	MaxAttempts      int        `json:"maxAttempts"`
	CreatedAt        time.Time  `json:"createdAt" format:"date-time"`
	ScheduledAt      time.Time  `json:"scheduledAt" format:"date-time"`
	AttemptedAt      *time.Time `json:"attemptedAt" format:"date-time"`
	FinalizedAt      *time.Time `json:"finalizedAt" format:"date-time"`
	NotificationKind string     `json:"notificationKind,omitempty"`
	Provider         string     `json:"provider,omitempty"`
	Target           string     `json:"target,omitempty"`
	CorrelationID    string     `json:"correlationId,omitempty"`
	SourceJobKind    string     `json:"sourceJobKind,omitempty"`
	SourceJobID      string     `json:"sourceJobId,omitempty"`
	LastError        *string    `json:"lastError"`
	Stale            bool       `json:"stale"`
}

type JobDetail struct {
	JobListItem
	Metadata map[string]string       `json:"metadata"`
	Args     map[string]any          `json:"args"`
	Errors   []SanitizedAttemptError `json:"errors"`
}

type SanitizedAttemptError struct {
	Attempt int       `json:"attempt"`
	At      time.Time `json:"at"`
	Error   string    `json:"error"`
}

type DiagnosticsResponse struct {
	NotificationName   string            `json:"notificationName"`
	Status             string            `json:"status"`
	Checks             []DiagnosticCheck `json:"checks"`
	RecommendedActions []string          `json:"recommendedActions"`
}

type DiagnosticCheck struct {
	Code    string `json:"code"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Message string `json:"message"`
	JobID   int64  `json:"jobId,omitempty"`
}

type riverJobRecord struct {
	ID          int64
	State       string
	Queue       string
	Kind        string
	Attempt     int
	MaxAttempts int
	CreatedAt   time.Time
	ScheduledAt time.Time
	AttemptedAt *time.Time
	FinalizedAt *time.Time
	Args        []byte
	Metadata    []byte
	ErrorsJSON  []byte `gorm:"column:errors_json"`
}

func (s *Service) Health(ctx context.Context) (HealthResponse, error) {
	queues, err := s.queueSummaries(ctx)
	if err != nil {
		return HealthResponse{}, err
	}

	providers, err := s.providerStatuses()
	if err != nil {
		return HealthResponse{}, err
	}
	schedules, err := s.scheduleHealth(ctx)
	if err != nil {
		return HealthResponse{}, err
	}
	notifications, err := s.notificationHealth(ctx, providers)
	if err != nil {
		return HealthResponse{}, err
	}

	response := HealthResponse{
		Worker: WorkerHealth{
			Enabled:  s.workerEnabled(),
			Mode:     s.workerMode(),
			PollOnly: s.workerPollOnly(),
			Queues:   queues,
		},
		Providers:     providers,
		Notifications: notifications,
		Schedules:     schedules,
	}
	response.Warnings = s.healthWarnings(response)
	return response, nil
}

func (s *Service) Jobs(ctx context.Context, query JobsQuery) (JobsListResponse, error) {
	if err := validateJobsQuery(&query); err != nil {
		return JobsListResponse{}, fmt.Errorf("%w: %w", ErrInvalidJobsQuery, err)
	}
	if !s.hasRiverJobsTable() {
		return JobsListResponse{Data: []JobListItem{}}, nil
	}

	limit := normalizeLimit(query.Limit)
	cursorID, err := decodeCursor(query.Cursor)
	if err != nil {
		return JobsListResponse{}, err
	}

	dbq := s.db.WithContext(ctx).Table("river_job").
		Select("id, state::text AS state, queue, kind, attempt, max_attempts, created_at, scheduled_at, attempted_at, finalized_at, args, metadata, COALESCE(to_jsonb(errors), '[]'::jsonb) AS errors_json").
		Where("kind IN ?", notificationJobKinds)

	if len(query.Queues) > 0 {
		dbq = dbq.Where("queue IN ?", query.Queues)
	}
	if query.Provider != "" {
		switch query.Provider {
		case notification.DeliveryChannelEmail:
			dbq = dbq.Where("kind IN ?", []string{worker.JobTypeSendEmail, worker.JobTypeSendEmailFrom})
		case notification.DeliveryChannelSlack:
			dbq = dbq.Where("kind IN ?", []string{worker.JobTypeSendSlackChannel, worker.JobTypeSendSlackDM})
		}
	}
	if query.NotificationKind != "" {
		dbq = dbq.Where("args ->> 'notification_kind' = ?", query.NotificationKind)
	}
	if len(query.States) > 0 {
		dbq = dbq.Where("state::text IN ?", query.States)
	}
	if query.Since != nil {
		dbq = dbq.Where("created_at >= ?", *query.Since)
	}
	if cursorID > 0 {
		dbq = dbq.Where("id < ?", cursorID)
	}

	var rows []riverJobRecord
	if err := dbq.Order("id DESC").Limit(limit + 1).Find(&rows).Error; err != nil {
		return JobsListResponse{}, err
	}

	nextCursor := ""
	if len(rows) > limit {
		nextCursor = encodeCursor(rows[limit-1].ID)
		rows = rows[:limit]
	}

	items := make([]JobListItem, 0, len(rows))
	for i := range rows {
		items = append(items, s.jobListItem(rows[i]))
	}

	return JobsListResponse{Data: items, Pagination: Pagination{NextCursor: nextCursor}}, nil
}

func (s *Service) Job(ctx context.Context, id int64) (JobDetail, bool, error) {
	if id <= 0 {
		return JobDetail{}, false, fmt.Errorf("job id must be positive")
	}
	if !s.hasRiverJobsTable() {
		return JobDetail{}, false, nil
	}

	var row riverJobRecord
	err := s.db.WithContext(ctx).Table("river_job").
		Select("id, state::text AS state, queue, kind, attempt, max_attempts, created_at, scheduled_at, attempted_at, finalized_at, args, metadata, COALESCE(to_jsonb(errors), '[]'::jsonb) AS errors_json").
		Where("id = ? AND kind IN ?", id, notificationJobKinds).
		First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return JobDetail{}, false, nil
		}
		return JobDetail{}, false, err
	}

	item := s.jobListItem(row)
	detail := JobDetail{
		JobListItem: item,
		Metadata:    metadataForArgs(row.Args, row.Metadata, item),
		Args:        sanitizeArgs(row.Kind, parseJSONMap(row.Args)),
		Errors:      parseAttemptErrors(row.ErrorsJSON),
	}
	return detail, true, nil
}

func (s *Service) Diagnostics(ctx context.Context, rawName string) (DiagnosticsResponse, error) {
	family, displayName, ok := normalizeDiagnosticsName(rawName)
	if !ok {
		return DiagnosticsResponse{}, fmt.Errorf("%w %q", ErrUnsupportedNotificationName, rawName)
	}

	checks := []DiagnosticCheck{}
	actions := []string{}
	providers, err := s.providerStatuses()
	if err != nil {
		return DiagnosticsResponse{}, err
	}
	providerEnabled := map[string]bool{}
	for _, provider := range providers {
		providerEnabled[provider.ProviderType] = provider.Enabled
	}

	for _, provider := range []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack} {
		providerLabel := titleASCII(provider)
		status := StatusPass
		message := providerLabel + " provider is enabled."
		if !providerEnabled[provider] {
			status = StatusWarning
			message = providerLabel + " provider is disabled."
			actions = append(actions, "Enable the "+providerLabel+" provider if this notification should use "+provider+".")
		}
		checks = append(checks, DiagnosticCheck{
			Code:    "provider_" + provider + "_enabled",
			Label:   providerLabel + " provider enabled",
			Status:  status,
			Message: message,
		})
	}

	for _, gate := range subscriptionGatesForFamily(family) {
		counts, err := s.subscriberCounts(ctx, gate)
		if err != nil {
			return DiagnosticsResponse{}, err
		}
		status := StatusPass
		message := fmt.Sprintf("%d active users are subscribed.", counts.TotalUsers)
		if counts.TotalUsers == 0 {
			status = StatusWarning
			message = "No active users are subscribed."
			actions = append(actions, "Review user notification subscriptions for "+displayName+".")
		}
		checks = append(checks, DiagnosticCheck{
			Code:    "subscribers_" + gate,
			Label:   "Subscribed users",
			Status:  status,
			Message: message,
		})
	}

	for _, name := range systemNotificationsForFamily(family) {
		destinations, err := s.configuredDestinations(ctx, name)
		if err != nil {
			return DiagnosticsResponse{}, err
		}
		status := StatusPass
		message := fmt.Sprintf("%d configured system destinations found.", len(destinations))
		if len(destinations) == 0 {
			status = StatusWarning
			message = "No configured system destination was found."
			actions = append(actions, "Add a system destination for "+strings.ToUpper(name)+".")
		}
		checks = append(checks, DiagnosticCheck{
			Code:    "configured_destination_" + name,
			Label:   "System destination configured",
			Status:  status,
			Message: message,
		})
	}

	for _, schedule := range schedulesForFamily(s.cfg, family) {
		checks = append(checks, s.scheduleCheck(ctx, schedule))
	}

	sourceKinds, deliveryKinds := jobKindsForFamily(family)
	providerSourceKinds := append([]string{}, sourceKinds...)
	providerSourceKinds = append(providerSourceKinds, deliveryKinds...)
	latestSource, hasSource, err := s.latestJobForKinds(ctx, append(sourceKinds, deliveryKinds...))
	if err != nil {
		return DiagnosticsResponse{}, err
	}
	if hasSource {
		checks = append(checks, DiagnosticCheck{
			Code:    "recent_source_job",
			Label:   "Recent source job",
			Status:  statusForFinalState(latestSource.State),
			Message: fmt.Sprintf("Latest source job %s at %s.", latestSource.State, latestSource.CreatedAt.UTC().Format(time.RFC3339)),
			JobID:   latestSource.ID,
		})
	} else {
		checks = append(checks, DiagnosticCheck{
			Code:    "recent_source_job",
			Label:   "Recent source job",
			Status:  StatusWarning,
			Message: "No recent source or scanner job was found.",
		})
	}

	providerJobs, err := s.recentProviderJobs(ctx, providerSourceKinds, latestSource)
	if err != nil {
		return DiagnosticsResponse{}, err
	}
	if len(providerJobs) == 0 {
		checks = append(checks, DiagnosticCheck{
			Code:    "downstream_provider_jobs",
			Label:   "Downstream provider jobs",
			Status:  StatusFail,
			Message: "No downstream email or Slack provider jobs were found.",
		})
		actions = append(actions, "Check whether the source job created provider fanout jobs.")
	} else {
		checks = append(checks, DiagnosticCheck{
			Code:    "downstream_provider_jobs",
			Label:   "Downstream provider jobs",
			Status:  providerJobsStatus(providerJobs),
			Message: fmt.Sprintf("%d downstream provider jobs found.", len(providerJobs)),
		})
	}

	staleCount, discardedCount, latestError, err := s.providerQueueProblems(ctx, providerSourceKinds)
	if err != nil {
		return DiagnosticsResponse{}, err
	}
	checks = append(checks, DiagnosticCheck{
		Code:    "stale_provider_jobs",
		Label:   "Stale provider jobs",
		Status:  warningIfCount(staleCount),
		Message: fmt.Sprintf("%d stale provider jobs found.", staleCount),
	})
	discardedMessage := fmt.Sprintf("%d discarded or retryable provider jobs found.", discardedCount)
	if latestError != "" {
		discardedMessage += " Latest error: " + latestError
	}
	checks = append(checks, DiagnosticCheck{
		Code:    "failed_provider_jobs",
		Label:   "Failed provider jobs",
		Status:  warningIfCount(discardedCount),
		Message: discardedMessage,
	})

	checks = append(checks, s.correlationCoverageCheck(providerJobs))

	return DiagnosticsResponse{
		NotificationName:   displayName,
		Status:             aggregateStatus(checks),
		Checks:             checks,
		RecommendedActions: dedupeStrings(actions),
	}, nil
}

func (s *Service) workerEnabled() bool {
	return s.cfg == nil || s.cfg.Worker == nil || s.cfg.Worker.Enabled
}

func (s *Service) workerPollOnly() bool {
	return s.cfg != nil && s.cfg.Worker != nil && s.cfg.Worker.UsePolling
}

func (s *Service) workerMode() string {
	if s.workerPollOnly() {
		return "polling"
	}
	return "notify"
}

func (s *Service) providerStatuses() ([]ProviderStatus, error) {
	catalog, ok := s.providers.(notification.ProviderCatalog)
	if !ok {
		return nil, fmt.Errorf("notification provider catalog is not configured")
	}
	providers := catalog.Providers()
	response := make([]ProviderStatus, 0, len(providers))
	for _, provider := range providers {
		response = append(response, ProviderStatus{
			ProviderType: provider.ProviderType,
			Enabled:      provider.Enabled,
			DisplayName:  provider.DisplayName,
			Description:  provider.Description,
			Metadata:     provider.Metadata,
		})
	}
	return response, nil
}

func (s *Service) queueSummaries(ctx context.Context) ([]QueueSummary, error) {
	if !s.hasRiverJobsTable() {
		summaries := make([]QueueSummary, 0, len(notificationQueues))
		for _, queue := range notificationQueues {
			summaries = append(summaries, QueueSummary{Name: queue, MaxWorkers: s.maxWorkersForQueue(queue), StaleThresholdSeconds: thresholdForQueue(queue)})
		}
		return summaries, nil
	}

	now := s.now().UTC()
	summaryByQueue := make(map[string]*QueueSummary, len(notificationQueues))
	for _, queue := range notificationQueues {
		summary := QueueSummary{Name: queue, MaxWorkers: s.maxWorkersForQueue(queue), StaleThresholdSeconds: thresholdForQueue(queue)}
		summaryByQueue[queue] = &summary
	}

	var stateRows []struct {
		Queue string
		State string
		Count int64
	}
	if err := s.db.WithContext(ctx).Table("river_job").
		Select("queue, state::text AS state, count(*) AS count").
		Where("queue IN ? AND kind IN ?", notificationQueues, notificationJobKinds).
		Group("queue, state").
		Find(&stateRows).Error; err != nil {
		return nil, fmt.Errorf("computing queue state health: %w", err)
	}
	for _, row := range stateRows {
		summary, ok := summaryByQueue[row.Queue]
		if !ok {
			continue
		}
		switch row.State {
		case "available":
			summary.Available = row.Count
		case "retryable":
			summary.Retryable = row.Count
		case "running":
			summary.Running = row.Count
		case "scheduled":
			summary.Scheduled = row.Count
		}
	}

	var finalizedRows []struct {
		Queue        string `gorm:"column:queue"`
		Completed24h int64  `gorm:"column:completed24h"`
		Discarded24h int64  `gorm:"column:discarded24h"`
	}
	if err := s.db.WithContext(ctx).Table("river_job").
		Select(`
			queue,
			sum(CASE WHEN state = 'completed' AND finalized_at >= ? THEN 1 ELSE 0 END) AS completed24h,
			sum(CASE WHEN state = 'discarded' AND finalized_at >= ? THEN 1 ELSE 0 END) AS discarded24h
		`, now.Add(-24*time.Hour), now.Add(-24*time.Hour)).
		Where("queue IN ? AND kind IN ?", notificationQueues, notificationJobKinds).
		Group("queue").
		Find(&finalizedRows).Error; err != nil {
		return nil, fmt.Errorf("computing queue finalized health: %w", err)
	}
	for _, row := range finalizedRows {
		if summary, ok := summaryByQueue[row.Queue]; ok {
			summary.Completed24h = row.Completed24h
			summary.Discarded24h = row.Discarded24h
		}
	}

	var waitingRows []struct {
		Queue             string     `gorm:"column:queue"`
		OldestAvailableAt *time.Time `gorm:"column:oldest_available_at"`
		StaleCount        int64      `gorm:"column:stale_count"`
	}
	if err := s.db.WithContext(ctx).Table("river_job").
		Select(`
			queue,
			min(CASE WHEN state IN ? AND scheduled_at <= ? THEN scheduled_at END) AS oldest_available_at,
			sum(CASE WHEN state IN ? AND scheduled_at <= ? AND ((kind IN ? AND scheduled_at <= ?) OR (kind NOT IN ? AND scheduled_at <= ?)) THEN 1 ELSE 0 END) AS stale_count
		`,
			waitingStates(), now,
			waitingStates(), now,
			providerKindList(), now.Add(-ProviderStaleThresholdSeconds*time.Second),
			providerKindList(), now.Add(-SourceStaleThresholdSeconds*time.Second),
		).
		Where("queue IN ? AND kind IN ?", notificationQueues, notificationJobKinds).
		Group("queue").
		Find(&waitingRows).Error; err != nil {
		return nil, fmt.Errorf("computing queue waiting health: %w", err)
	}
	for _, row := range waitingRows {
		if summary, ok := summaryByQueue[row.Queue]; ok {
			summary.OldestAvailableAt = row.OldestAvailableAt
			summary.StaleCount = row.StaleCount
		}
	}

	summaries := make([]QueueSummary, 0, len(notificationQueues))
	for _, queue := range notificationQueues {
		summaries = append(summaries, *summaryByQueue[queue])
	}
	return summaries, nil
}

func (s *Service) maxWorkersForQueue(queue string) int {
	workers := 5
	if s.cfg != nil && s.cfg.Worker != nil && s.cfg.Worker.Workers > 0 {
		workers = s.cfg.Worker.Workers
	}
	switch queue {
	case "digest", "scheduler":
		return 1
	case "workflow":
		return 2
	case "risk":
		return 20
	case "poam":
		return 10
	default:
		return workers
	}
}

func thresholdForQueue(queue string) int64 {
	if queue == "email" || queue == "slack" {
		return ProviderStaleThresholdSeconds
	}
	return SourceStaleThresholdSeconds
}

func (s *Service) notificationHealth(ctx context.Context, providers []ProviderStatus) ([]NotificationHealth, error) {
	names := []string{
		notification.SubscriptionGateEvidenceDigest,
		notification.SubscriptionGateTaskAvailable,
		notification.SubscriptionGateTaskDailyDigest,
		notification.SystemNotificationNameWorkflowExecutionFailed,
		notification.SubscriptionGateRiskNotifications,
	}
	response := make([]NotificationHealth, 0, len(names))
	for _, name := range names {
		destinations, err := s.configuredDestinations(ctx, name)
		if err != nil {
			return nil, err
		}
		counts, err := s.subscriberCounts(ctx, subscriptionGateForSystemName(name))
		if err != nil {
			return nil, err
		}
		item := NotificationHealth{
			Name:                   strings.ToUpper(name),
			ConfiguredDestinations: destinations,
			SubscriberCounts:       counts,
		}
		if len(destinations) == 0 && supportsSystemDestination(name) {
			item.Warnings = append(item.Warnings, TroubleshootingWarning{
				Code:     "missing_destination",
				Severity: "warning",
				Message:  "No system destination is configured.",
				Target:   strings.ToUpper(name),
			})
		}
		response = append(response, item)
	}
	return response, nil
}

func (s *Service) configuredDestinations(ctx context.Context, name string) ([]ConfiguredSystemDestinationResponse, error) {
	var rows []relational.SystemNotificationDestination
	if s.db == nil {
		return []ConfiguredSystemDestinationResponse{}, nil
	}
	if err := s.db.WithContext(ctx).
		Where("notification_type = ?", name).
		Order("provider ASC, created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("loading configured destinations for %s: %w", name, err)
	}
	destinations := make([]ConfiguredSystemDestinationResponse, 0, len(rows))
	seen := map[string]struct{}{}
	for _, row := range rows {
		target := notification.Target{Provider: row.Provider, Address: row.Target.Data().Address}
		configurator, ok := notification.LookupTargetConfigurator(s.providers, row.Provider)
		if !ok {
			continue
		}
		normalized, err := configurator.NormalizeTarget(target)
		if err != nil {
			continue
		}
		display, err := configurator.DisplayTarget(normalized)
		if err != nil {
			continue
		}
		key := row.Provider + ":" + strings.ToLower(display)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		destinations = append(destinations, ConfiguredSystemDestinationResponse{ProviderType: row.Provider, DestinationTarget: display})
	}
	return destinations, nil
}

func (s *Service) subscriberCounts(ctx context.Context, gate string) (SubscriberCounts, error) {
	if gate == "" || s.db == nil {
		return SubscriberCounts{}, nil
	}
	var rows []relational.UserNotificationSubscription
	if err := s.db.WithContext(ctx).
		Joins("JOIN ccf_users ON ccf_users.id::text = ccf_user_notification_subscriptions.user_id").
		Where("ccf_user_notification_subscriptions.notification_type = ?", gate).
		Where("ccf_users.is_active = ? AND ccf_users.is_locked = ?", true, false).
		Find(&rows).Error; err != nil {
		return SubscriberCounts{}, fmt.Errorf("loading subscriber counts for %s: %w", gate, err)
	}
	userIDs := map[string]struct{}{}
	var counts SubscriberCounts
	for _, row := range rows {
		userIDs[row.UserID] = struct{}{}
		seenChannels := map[string]struct{}{}
		for _, raw := range row.Channels {
			channel, ok := notification.NormalizeDeliveryChannel(raw)
			if !ok {
				continue
			}
			seenChannels[channel] = struct{}{}
		}
		if _, ok := seenChannels[notification.DeliveryChannelEmail]; ok {
			counts.Email++
		}
		if _, ok := seenChannels[notification.DeliveryChannelSlack]; ok {
			counts.Slack++
		}
	}
	counts.TotalUsers = int64(len(userIDs))
	return counts, nil
}

func (s *Service) scheduleHealth(ctx context.Context) ([]ScheduleHealth, error) {
	defs := allScheduleDefinitions(s.cfg)
	items := make([]ScheduleHealth, 0, len(defs))
	for _, def := range defs {
		item := ScheduleHealth{
			Name:         def.Name,
			JobKind:      def.JobKind,
			DeliveryKind: def.DeliveryKind,
			Queue:        def.Queue,
			Enabled:      def.Enabled,
			Schedule:     def.Schedule,
		}
		if def.Enabled {
			next, err := nextRun(def.Schedule, s.now())
			if err == nil {
				item.NextRunAt = &next
			}
		}
		if last, ok, err := s.latestJobForKind(ctx, def.JobKind); err != nil {
			return nil, err
		} else if ok {
			item.LastJob = &JobSummary{ID: last.ID, State: last.State, CreatedAt: last.CreatedAt, FinalizedAt: last.FinalizedAt}
		}
		items = append(items, item)
	}
	return items, nil
}

type scheduleDefinition struct {
	Name         string
	JobKind      string
	DeliveryKind string
	Queue        string
	Enabled      bool
	Schedule     string
}

func allScheduleDefinitions(cfg *config.Config) []scheduleDefinition {
	workflowCfg := config.DefaultWorkflowConfig()
	if cfg != nil && cfg.Workflow != nil {
		workflowCfg = cfg.Workflow
	}
	riskCfg := config.DefaultRiskConfig()
	if cfg != nil && cfg.Risk != nil {
		riskCfg = cfg.Risk
	}
	poamCfg := config.DefaultPoamConfig()
	if cfg != nil && cfg.Poam != nil {
		poamCfg = cfg.Poam
	}
	digestEnabled := cfg == nil || cfg.DigestEnabled
	digestSchedule := "@weekly"
	if cfg != nil && strings.TrimSpace(cfg.DigestSchedule) != "" {
		digestSchedule = cfg.DigestSchedule
	}
	return []scheduleDefinition{
		{"EVIDENCE_DIGEST", worker.JobTypeSendGlobalDigest, "", "digest", digestEnabled, digestSchedule},
		{"WORKFLOW_DUE_SOON", "workflow_due_soon_checker", worker.JobTypeWorkflowTaskDueSoon, "email", workflowCfg.DueSoonEnabled, workflowCfg.DueSoonSchedule},
		{"WORKFLOW_TASK_DIGEST", "workflow_task_digest_checker", worker.JobTypeWorkflowTaskDigest, "digest", workflowCfg.TaskDigestEnabled, workflowCfg.TaskDigestSchedule},
		{"RISK_REVIEW_DEADLINE_REMINDER", worker.JobTypeRiskReviewDeadlineReminderScanner, worker.JobTypeRiskReviewDueReminder, "risk", riskCfg.ReviewDeadlineReminderEnabled, riskCfg.ReviewDeadlineReminderSchedule},
		{"RISK_REVIEW_OVERDUE_ESCALATION", worker.JobTypeRiskReviewOverdueEscalationScanner, worker.JobTypeRiskReviewOverdueEscalation, "risk", riskCfg.ReviewOverdueEscalationEnabled, riskCfg.ReviewOverdueEscalationSchedule},
		{"RISK_STALE_REMINDER", worker.JobTypeRiskStaleRiskScanner, worker.JobTypeRiskStaleOpenReminder, "risk", riskCfg.StaleRiskScannerEnabled, riskCfg.StaleRiskScannerSchedule},
		{"RISK_OPEN_DIGEST", worker.JobTypeRiskOpenDigestScheduler, worker.JobTypeRiskOpenDigest, "risk", riskCfg.OpenDigestEnabled, riskCfg.OpenDigestSchedule},
		{"POAM_DEADLINE_REMINDER", worker.JobTypePoamDeadlineReminderScanner, worker.JobTypePoamDeadlineReminder, "poam", poamCfg.DeadlineReminderEnabled, poamCfg.DeadlineReminderSchedule},
		{"POAM_OVERDUE_NOTIFICATION", worker.JobTypePoamOverdueTransitionScanner, worker.JobTypePoamOverdueNotification, "poam", poamCfg.OverdueTransitionEnabled, poamCfg.OverdueTransitionSchedule},
		{"POAM_MILESTONE_OVERDUE_REMINDER", worker.JobTypeMilestoneOverdueScannerScanner, worker.JobTypeMilestoneOverdueReminder, "poam", poamCfg.MilestoneOverdueEnabled, poamCfg.MilestoneOverdueSchedule},
		{"POAM_OPEN_DIGEST", worker.JobTypePoamOpenDigestScheduler, worker.JobTypePoamOpenDigest, "digest", poamCfg.OpenDigestEnabled, poamCfg.OpenDigestSchedule},
	}
}

func nextRun(schedule string, now time.Time) (time.Time, error) {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	parsed, err := parser.Parse(schedule)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.Next(now.UTC()).UTC(), nil
}

func (s *Service) latestJobForKind(ctx context.Context, kind string) (riverJobRecord, bool, error) {
	return s.latestJobForKinds(ctx, []string{kind})
}

func (s *Service) latestJobForKinds(ctx context.Context, kinds []string) (riverJobRecord, bool, error) {
	if !s.hasRiverJobsTable() || len(kinds) == 0 {
		return riverJobRecord{}, false, nil
	}
	var row riverJobRecord
	err := s.db.WithContext(ctx).Table("river_job").
		Select("id, state::text AS state, queue, kind, attempt, max_attempts, created_at, scheduled_at, attempted_at, finalized_at, args, metadata, COALESCE(to_jsonb(errors), '[]'::jsonb) AS errors_json").
		Where("kind IN ?", kinds).
		Order("id DESC").
		Limit(1).
		First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return riverJobRecord{}, false, nil
		}
		return riverJobRecord{}, false, err
	}
	return row, true, nil
}

func (s *Service) jobListItem(row riverJobRecord) JobListItem {
	args := parseJSONMap(row.Args)
	metadata := parseJSONMap(row.Metadata)
	item := JobListItem{
		ID:          row.ID,
		State:       row.State,
		Queue:       row.Queue,
		Kind:        row.Kind,
		Attempt:     row.Attempt,
		MaxAttempts: row.MaxAttempts,
		CreatedAt:   row.CreatedAt,
		ScheduledAt: row.ScheduledAt,
		AttemptedAt: row.AttemptedAt,
		FinalizedAt: row.FinalizedAt,
		LastError:   lastAttemptError(row.ErrorsJSON),
		Stale:       isStaleJob(row.Kind, row.State, row.ScheduledAt, s.now()),
	}
	item.NotificationKind = stringValue(args, metadata, "notification_kind")
	item.CorrelationID = stringValue(args, metadata, "correlation_id")
	item.SourceJobKind = stringValue(args, metadata, "source_job_kind")
	item.SourceJobID = stringValue(args, metadata, "source_job_id")
	item.Provider = providerForJob(row.Kind, args)
	item.Target = targetForJob(row.Kind, args)
	return item
}

func metadataForArgs(argsJSON []byte, metadataJSON []byte, item JobListItem) map[string]string {
	args := parseJSONMap(argsJSON)
	metadata := parseJSONMap(metadataJSON)
	result := map[string]string{}
	fields := map[string]string{
		"notificationKind": item.NotificationKind,
		"correlationId":    item.CorrelationID,
		"sourceJobKind":    item.SourceJobKind,
		"sourceJobId":      item.SourceJobID,
		"provider":         item.Provider,
		"target":           item.Target,
	}
	for k, v := range fields {
		if v != "" {
			result[k] = v
		}
	}
	for _, key := range []string{"notification_kind", "correlation_id", "source_job_kind", "source_job_id", "recipient_user_id"} {
		if value := stringValue(args, metadata, key); value != "" {
			result[toCamel(key)] = value
		}
	}
	return result
}

func sanitizeArgs(kind string, args map[string]any) map[string]any {
	safe := map[string]any{}
	switch kind {
	case worker.JobTypeSendEmail, worker.JobTypeSendEmailFrom:
		copyIfPresent(safe, args, "to")
		copyIfPresent(safe, args, "cc")
		copyIfPresent(safe, args, "bcc")
		copyIfPresent(safe, args, "from")
		copyIfPresent(safe, args, "subject")
		copyIfPresent(safe, args, "provider")
	case worker.JobTypeSendSlackChannel, worker.JobTypeSendSlackDM:
		copyIfPresent(safe, args, "channel")
		copyIfPresent(safe, args, "target_type")
	default:
		for k, v := range args {
			key := strings.ToLower(k)
			if strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "password") ||
				strings.Contains(key, "html_body") || strings.Contains(key, "text_body") || strings.Contains(key, "blocks") ||
				strings.Contains(key, "attachments") {
				continue
			}
			safe[k] = v
		}
	}
	return safe
}

func providerForJob(kind string, args map[string]any) string {
	switch kind {
	case worker.JobTypeSendEmail, worker.JobTypeSendEmailFrom:
		return notification.DeliveryChannelEmail
	case worker.JobTypeSendSlackChannel, worker.JobTypeSendSlackDM:
		return notification.DeliveryChannelSlack
	default:
		return stringFromAny(args["provider"])
	}
}

func targetForJob(kind string, args map[string]any) string {
	switch kind {
	case worker.JobTypeSendEmail, worker.JobTypeSendEmailFrom:
		if values, ok := args["to"].([]any); ok && len(values) > 0 {
			return stringFromAny(values[0])
		}
	case worker.JobTypeSendSlackChannel, worker.JobTypeSendSlackDM:
		return stringFromAny(args["channel"])
	}
	return ""
}

func isStaleJob(kind, state string, scheduledAt time.Time, now time.Time) bool {
	if state != "available" && state != "retryable" && state != "scheduled" {
		return false
	}
	if scheduledAt.After(now) {
		return false
	}
	threshold := SourceStaleThresholdSeconds * time.Second
	if _, ok := providerJobKinds[kind]; ok {
		threshold = ProviderStaleThresholdSeconds * time.Second
	}
	return scheduledAt.Before(now.Add(-threshold)) || scheduledAt.Equal(now.Add(-threshold))
}

func validateJobsQuery(query *JobsQuery) error {
	query.Queues = normalizeStringList(query.Queues)
	query.States = normalizeStringList(query.States)
	allowedQueues := setOf(notificationQueues)
	for _, queue := range query.Queues {
		if _, ok := allowedQueues[queue]; !ok {
			return fmt.Errorf("unsupported queue %q", queue)
		}
	}
	if query.Provider != "" {
		provider, ok := notification.NormalizeDeliveryChannel(query.Provider)
		if !ok || (provider != notification.DeliveryChannelEmail && provider != notification.DeliveryChannelSlack) {
			return fmt.Errorf("unsupported provider %q", query.Provider)
		}
		query.Provider = provider
	}
	allowedStates := setOf([]string{"available", "cancelled", "completed", "discarded", "pending", "retryable", "running", "scheduled"})
	for _, state := range query.States {
		if _, ok := allowedStates[state]; !ok {
			return fmt.Errorf("unsupported state %q", state)
		}
	}
	return nil
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 200 {
		return 200
	}
	return limit
}

func (s *Service) hasRiverJobsTable() bool {
	return s != nil && s.db != nil && s.db.Migrator().HasTable("river_job")
}

func waitingStates() []string {
	return []string{"available", "retryable", "scheduled"}
}

func providerKindList() []string {
	return []string{worker.JobTypeSendEmail, worker.JobTypeSendEmailFrom, worker.JobTypeSendSlackChannel, worker.JobTypeSendSlackDM}
}

func parseJSONMap(data []byte) map[string]any {
	if len(data) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func parseAttemptErrors(data []byte) []SanitizedAttemptError {
	if len(data) == 0 {
		return []SanitizedAttemptError{}
	}
	var raw []struct {
		Attempt int       `json:"attempt"`
		At      time.Time `json:"at"`
		Error   string    `json:"error"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return []SanitizedAttemptError{}
	}
	result := make([]SanitizedAttemptError, 0, len(raw))
	for _, item := range raw {
		result = append(result, SanitizedAttemptError{Attempt: item.Attempt, At: item.At, Error: item.Error})
	}
	return result
}

func lastAttemptError(data []byte) *string {
	errors := parseAttemptErrors(data)
	if len(errors) == 0 {
		return nil
	}
	value := errors[len(errors)-1].Error
	return &value
}

func stringValue(args map[string]any, metadata map[string]any, key string) string {
	if value := stringFromAny(args[key]); value != "" {
		return value
	}
	return stringFromAny(metadata[key])
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func copyIfPresent(dst map[string]any, src map[string]any, key string) {
	if value, ok := src[key]; ok {
		dst[toCamel(key)] = value
	}
}

func toCamel(value string) string {
	parts := strings.Split(value, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func encodeCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

func decodeCursor(cursor string) (int64, error) {
	if strings.TrimSpace(cursor) == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("invalid cursor")
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || id < 0 {
		return 0, fmt.Errorf("invalid cursor")
	}
	return id, nil
}

func normalizeStringList(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			trimmed := strings.ToLower(strings.TrimSpace(part))
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return result
}

func setOf(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func titleASCII(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	return strings.ToUpper(trimmed[:1]) + trimmed[1:]
}

func subscriptionGateForSystemName(name string) string {
	switch name {
	case notification.SystemNotificationNameWorkflowExecutionFailed:
		return notification.SubscriptionGateTaskAvailable
	default:
		if gate, ok := notification.NormalizeSubscriptionGate(name); ok {
			return gate
		}
		return ""
	}
}

func supportsSystemDestination(name string) bool {
	_, ok := notification.NormalizeSystemNotificationName(name)
	return ok
}

func (s *Service) healthWarnings(response HealthResponse) []TroubleshootingWarning {
	warnings := []TroubleshootingWarning{}
	for _, provider := range response.Providers {
		if !provider.Enabled {
			warnings = append(warnings, TroubleshootingWarning{
				Code:     provider.ProviderType + "_provider_disabled",
				Severity: "warning",
				Message:  provider.DisplayName + " provider is disabled.",
				Target:   provider.ProviderType,
			})
		}
	}
	for _, queue := range response.Worker.Queues {
		if queue.StaleCount > 0 {
			warnings = append(warnings, TroubleshootingWarning{
				Code:     queue.Name + "_queue_backlog",
				Severity: "warning",
				Message:  fmt.Sprintf("%s queue has %d stale notification jobs.", titleASCII(queue.Name), queue.StaleCount),
				Target:   queue.Name,
			})
		}
		if queue.Discarded24h > 0 {
			warnings = append(warnings, TroubleshootingWarning{
				Code:     queue.Name + "_discarded_jobs",
				Severity: "warning",
				Message:  fmt.Sprintf("%s queue has %d discarded notification jobs in the last 24 hours.", titleASCII(queue.Name), queue.Discarded24h),
				Target:   queue.Name,
			})
		}
	}
	for _, item := range response.Notifications {
		warnings = append(warnings, item.Warnings...)
	}
	for _, schedule := range response.Schedules {
		if schedule.Enabled && schedule.LastJob == nil {
			warnings = append(warnings, TroubleshootingWarning{
				Code:     "missing_schedule_run",
				Severity: "warning",
				Message:  "No River job was found for enabled schedule " + schedule.Name + ".",
				Target:   schedule.Name,
			})
		}
	}
	return warnings
}

func normalizeDiagnosticsName(raw string) (string, string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	switch normalized {
	case "evidence_digest", "evidencedigest":
		return "evidence", "EVIDENCE_DIGEST", true
	case "workflow", "task_available", "task_daily_digest", "workflow_execution_failed":
		return "workflow", "WORKFLOW", true
	case "risk", "risk_notifications", "risknotifications":
		return "risk", "RISK", true
	case "poam":
		return "poam", "POAM", true
	default:
		return "", "", false
	}
}

func subscriptionGatesForFamily(family string) []string {
	switch family {
	case "evidence":
		return []string{notification.SubscriptionGateEvidenceDigest}
	case "workflow":
		return []string{notification.SubscriptionGateTaskAvailable, notification.SubscriptionGateTaskDailyDigest}
	case "risk", "poam":
		return []string{notification.SubscriptionGateRiskNotifications}
	default:
		return nil
	}
}

func systemNotificationsForFamily(family string) []string {
	switch family {
	case "evidence":
		return []string{notification.SystemNotificationNameEvidenceDigest}
	case "workflow":
		return []string{notification.SystemNotificationNameWorkflowExecutionFailed}
	default:
		return nil
	}
}

func schedulesForFamily(cfg *config.Config, family string) []scheduleDefinition {
	all := allScheduleDefinitions(cfg)
	result := []scheduleDefinition{}
	for _, def := range all {
		switch family {
		case "evidence":
			if strings.HasPrefix(def.Name, "EVIDENCE_") {
				result = append(result, def)
			}
		case "workflow":
			if strings.HasPrefix(def.Name, "WORKFLOW_") {
				result = append(result, def)
			}
		case "risk":
			if strings.HasPrefix(def.Name, "RISK_") {
				result = append(result, def)
			}
		case "poam":
			if strings.HasPrefix(def.Name, "POAM_") {
				result = append(result, def)
			}
		}
	}
	return result
}

func jobKindsForFamily(family string) ([]string, []string) {
	switch family {
	case "evidence":
		return []string{worker.JobTypeSendGlobalDigest}, []string{worker.JobTypeSendGlobalDigest}
	case "workflow":
		return []string{worker.JobTypeWorkflowDueSoonChecker, "workflow_task_digest_checker"}, []string{
			worker.JobTypeWorkflowTaskAssigned,
			worker.JobTypeWorkflowTaskDueSoon,
			worker.JobTypeWorkflowTaskDigest,
			worker.JobTypeWorkflowExecutionFailed,
		}
	case "risk":
		return []string{
				worker.JobTypeRiskReviewDeadlineReminderScanner,
				worker.JobTypeRiskReviewOverdueEscalationScanner,
				worker.JobTypeRiskStaleRiskScanner,
				worker.JobTypeRiskOpenDigestScheduler,
			}, []string{
				worker.JobTypeRiskReviewDueReminder,
				worker.JobTypeRiskReviewOverdueEscalation,
				worker.JobTypeRiskStaleOpenReminder,
				worker.JobTypeRiskOpenDigest,
			}
	case "poam":
		return []string{
				worker.JobTypePoamDeadlineReminderScanner,
				worker.JobTypePoamOverdueTransitionScanner,
				worker.JobTypeMilestoneOverdueScannerScanner,
				worker.JobTypePoamOpenDigestScheduler,
			}, []string{
				worker.JobTypePoamDeadlineReminder,
				worker.JobTypePoamOverdueNotification,
				worker.JobTypeMilestoneOverdueReminder,
				worker.JobTypePoamOpenDigest,
			}
	default:
		return nil, nil
	}
}

func (s *Service) scheduleCheck(ctx context.Context, def scheduleDefinition) DiagnosticCheck {
	if !def.Enabled {
		return DiagnosticCheck{
			Code:    "schedule_" + strings.ToLower(def.Name),
			Label:   def.Name + " schedule",
			Status:  StatusWarning,
			Message: "Schedule is disabled.",
		}
	}
	next, err := nextRun(def.Schedule, s.now())
	if err != nil {
		return DiagnosticCheck{
			Code:    "schedule_" + strings.ToLower(def.Name),
			Label:   def.Name + " schedule",
			Status:  StatusFail,
			Message: "Schedule cannot be parsed: " + err.Error(),
		}
	}
	last, ok, err := s.latestJobForKind(ctx, def.JobKind)
	if err != nil {
		return DiagnosticCheck{
			Code:    "schedule_" + strings.ToLower(def.Name),
			Label:   def.Name + " schedule",
			Status:  StatusFail,
			Message: "Failed to read latest schedule job: " + err.Error(),
		}
	}
	message := "Next scheduled run is " + next.Format(time.RFC3339) + "."
	check := DiagnosticCheck{
		Code:    "schedule_" + strings.ToLower(def.Name),
		Label:   def.Name + " schedule",
		Status:  StatusPass,
		Message: message,
	}
	if ok {
		check.JobID = last.ID
		check.Message = message + " Latest job state is " + last.State + "."
	}
	return check
}

func (s *Service) recentProviderJobs(ctx context.Context, sourceKinds []string, latestSource riverJobRecord) ([]JobListItem, error) {
	if !s.hasRiverJobsTable() {
		return []JobListItem{}, nil
	}
	q := s.db.WithContext(ctx).Table("river_job").
		Select("id, state::text AS state, queue, kind, attempt, max_attempts, created_at, scheduled_at, attempted_at, finalized_at, args, metadata, COALESCE(to_jsonb(errors), '[]'::jsonb) AS errors_json").
		Where("kind IN ?", providerKindList()).
		Order("id DESC").
		Limit(50)
	if len(sourceKinds) > 0 {
		predicate, args := providerJobSourcePredicate(sourceKinds, latestSource)
		q = q.Where(predicate, args...)
	}
	var rows []riverJobRecord
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	items := make([]JobListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, s.jobListItem(row))
	}
	return items, nil
}

func providerJobSourcePredicate(sourceKinds []string, latestSource riverJobRecord) (string, []any) {
	sourceJobKindExpr := "COALESCE(NULLIF(args ->> 'source_job_kind', ''), NULLIF(metadata ->> 'source_job_kind', ''), '')"
	sourceJobIDExpr := "COALESCE(NULLIF(args ->> 'source_job_id', ''), NULLIF(metadata ->> 'source_job_id', ''), '')"
	if latestSource.ID > 0 {
		return fmt.Sprintf("((%s IN ? AND (%s = ? OR %s = '')) OR (%s = '' AND created_at >= ?))", sourceJobKindExpr, sourceJobIDExpr, sourceJobIDExpr, sourceJobKindExpr),
			[]any{sourceKinds, strconv.FormatInt(latestSource.ID, 10), latestSource.CreatedAt}
	}
	return fmt.Sprintf("(%s IN ?) OR (%s = '' AND created_at >= ?)", sourceJobKindExpr, sourceJobKindExpr),
		[]any{sourceKinds, latestSource.CreatedAt}
}

func (s *Service) providerQueueProblems(ctx context.Context, sourceKinds []string) (int64, int64, string, error) {
	jobs, err := s.recentProviderJobs(ctx, sourceKinds, riverJobRecord{CreatedAt: s.now().Add(-30 * 24 * time.Hour)})
	if err != nil {
		return 0, 0, "", err
	}
	var stale int64
	var failed int64
	latestError := ""
	for _, job := range jobs {
		if job.Stale {
			stale++
		}
		if job.State == "discarded" || job.State == "retryable" {
			failed++
			if latestError == "" && job.LastError != nil {
				latestError = *job.LastError
			}
		}
	}
	return stale, failed, latestError, nil
}

func providerJobsStatus(jobs []JobListItem) string {
	for _, job := range jobs {
		if job.State == "discarded" {
			return StatusFail
		}
		if job.State == "available" || job.State == "retryable" || job.State == "scheduled" || job.Stale {
			return StatusWarning
		}
	}
	return StatusPass
}

func statusForFinalState(state string) string {
	switch state {
	case "completed":
		return StatusPass
	case "discarded", "cancelled":
		return StatusFail
	default:
		return StatusWarning
	}
}

func warningIfCount(count int64) string {
	if count > 0 {
		return StatusWarning
	}
	return StatusPass
}

func (s *Service) correlationCoverageCheck(jobs []JobListItem) DiagnosticCheck {
	if len(jobs) == 0 {
		return DiagnosticCheck{
			Code:    "correlation_coverage",
			Label:   "Correlation coverage",
			Status:  StatusWarning,
			Message: "No provider jobs were available to evaluate correlation metadata.",
		}
	}
	var withCorrelation int
	for _, job := range jobs {
		if job.CorrelationID != "" && job.SourceJobKind != "" && job.SourceJobID != "" {
			withCorrelation++
		}
	}
	status := StatusPass
	if withCorrelation < len(jobs) {
		status = StatusWarning
	}
	return DiagnosticCheck{
		Code:    "correlation_coverage",
		Label:   "Correlation coverage",
		Status:  status,
		Message: fmt.Sprintf("%d of %d provider jobs include correlation ID, source job kind, and source job ID metadata.", withCorrelation, len(jobs)),
	}
}

func aggregateStatus(checks []DiagnosticCheck) string {
	status := StatusPass
	for _, check := range checks {
		if check.Status == StatusFail {
			return StatusFail
		}
		if check.Status == StatusWarning {
			status = StatusWarning
		}
	}
	return status
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}
