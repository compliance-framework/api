package worker

import (
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const (
	JobTypeRiskReviewDeadlineReminderScanner  = "risk_review_deadline_reminder_scanner"
	JobTypeRiskReviewOverdueEscalationScanner = "risk_review_overdue_escalation_scanner"
	JobTypeRiskStaleRiskScanner               = "risk_stale_risk_scanner"
	JobTypeRiskEvidenceReconciliationScanner  = "risk_evidence_reconciliation_scanner"
	JobTypeRiskOpenDigestScheduler            = "risk_open_digest_scheduler"

	JobTypeRiskReviewDueReminder       = "risk_review_due_reminder"
	JobTypeRiskReviewOverdueEscalation = "risk_review_overdue_escalation"
	JobTypeRiskStaleOpenReminder       = "risk_stale_open_reminder"
	JobTypeRiskReconcileDuplicates     = "risk_reconcile_duplicates"
	JobTypeRiskReviewOverdueReopen     = "risk_review_overdue_reopen"
	JobTypeRiskOpenDigest              = "risk_open_digest"
	JobTypeRiskOrphanedCleanup         = "risk_orphaned_cleanup"
)

type RiskReviewDeadlineReminderScannerArgs struct{}
type RiskReviewOverdueEscalationScannerArgs struct{}
type RiskStaleRiskScannerArgs struct{}
type RiskEvidenceReconciliationScannerArgs struct{}
type RiskOpenDigestSchedulerArgs struct{}

type RiskReviewDueReminderArgs struct {
	RiskID         uuid.UUID `json:"risk_id"`
	OwnerUserID    uuid.UUID `json:"owner_user_id"`
	ReviewDeadline string    `json:"review_deadline"`
	ReminderWindow string    `json:"reminder_window"`
}

type RiskReviewOverdueEscalationArgs struct {
	RiskID         uuid.UUID `json:"risk_id"`
	OwnerUserID    uuid.UUID `json:"owner_user_id"`
	ReviewDeadline string    `json:"review_deadline"`
	OverdueWindow  string    `json:"overdue_window"`
}

type RiskStaleOpenReminderArgs struct {
	RiskID          uuid.UUID `json:"risk_id"`
	OwnerUserID     uuid.UUID `json:"owner_user_id"`
	LastSeenAt      string    `json:"last_seen_at"`
	StaleBucketDate string    `json:"stale_bucket_date"`
}

type RiskReconcileDuplicatesArgs struct {
	DedupeKey string `json:"dedupe_key"`
}

type RiskReviewOverdueReopenArgs struct {
	RiskID         uuid.UUID `json:"risk_id"`
	ReviewDeadline string    `json:"review_deadline"`
	ThresholdDays  int       `json:"threshold_days"`
}

// RiskOrphanedCleanupArgs is enqueued by the SSP profile attach/update endpoints whenever
// the profile binding changes. The worker resolves the new profile's control set and
// transitions any open auto-generated risks whose controls are no longer present to remediated.
//
// Deduplication uses river:"unique" tags on ssp_id and new_profile_id only. OldProfileID
// is kept for observability/logging but excluded from the uniqueness hash. This means:
//   - Two rapid changes to the same target profile → one job (correct: second is a no-op)
//   - Two rapid changes to different target profiles → two independent jobs (correct)
type RiskOrphanedCleanupArgs struct {
	SSPID        uuid.UUID  `json:"ssp_id"                  river:"unique"`
	OldProfileID *uuid.UUID `json:"old_profile_id,omitempty"`
	NewProfileID *uuid.UUID `json:"new_profile_id,omitempty" river:"unique"`
}

type RiskOpenDigestArgs struct {
	RecipientUserID uuid.UUID `json:"recipient_user_id"`
	WindowStart     string    `json:"window_start"`
	WindowEnd       string    `json:"window_end"`
	WindowKind      string    `json:"window_kind"`
}

func (RiskReviewDeadlineReminderScannerArgs) Kind() string {
	return JobTypeRiskReviewDeadlineReminderScanner
}
func (RiskReviewOverdueEscalationScannerArgs) Kind() string {
	return JobTypeRiskReviewOverdueEscalationScanner
}
func (RiskStaleRiskScannerArgs) Kind() string { return JobTypeRiskStaleRiskScanner }
func (RiskEvidenceReconciliationScannerArgs) Kind() string {
	return JobTypeRiskEvidenceReconciliationScanner
}
func (RiskOpenDigestSchedulerArgs) Kind() string     { return JobTypeRiskOpenDigestScheduler }
func (RiskReviewDueReminderArgs) Kind() string       { return JobTypeRiskReviewDueReminder }
func (RiskReviewOverdueEscalationArgs) Kind() string { return JobTypeRiskReviewOverdueEscalation }
func (RiskStaleOpenReminderArgs) Kind() string       { return JobTypeRiskStaleOpenReminder }
func (RiskReconcileDuplicatesArgs) Kind() string     { return JobTypeRiskReconcileDuplicates }
func (RiskReviewOverdueReopenArgs) Kind() string     { return JobTypeRiskReviewOverdueReopen }
func (RiskOpenDigestArgs) Kind() string              { return JobTypeRiskOpenDigest }
func (RiskOrphanedCleanupArgs) Kind() string         { return JobTypeRiskOrphanedCleanup }

func (RiskReviewDeadlineReminderScannerArgs) Timeout() time.Duration  { return 5 * time.Minute }
func (RiskReviewOverdueEscalationScannerArgs) Timeout() time.Duration { return 5 * time.Minute }
func (RiskStaleRiskScannerArgs) Timeout() time.Duration               { return 5 * time.Minute }
func (RiskEvidenceReconciliationScannerArgs) Timeout() time.Duration  { return 5 * time.Minute }
func (RiskOpenDigestSchedulerArgs) Timeout() time.Duration            { return 5 * time.Minute }
func (RiskReviewDueReminderArgs) Timeout() time.Duration              { return 30 * time.Second }
func (RiskReviewOverdueEscalationArgs) Timeout() time.Duration        { return 30 * time.Second }
func (RiskStaleOpenReminderArgs) Timeout() time.Duration              { return 30 * time.Second }
func (RiskReconcileDuplicatesArgs) Timeout() time.Duration            { return 2 * time.Minute }
func (RiskReviewOverdueReopenArgs) Timeout() time.Duration            { return 30 * time.Second }
func (RiskOpenDigestArgs) Timeout() time.Duration                     { return 30 * time.Second }
func (RiskOrphanedCleanupArgs) Timeout() time.Duration                { return 2 * time.Minute }

func JobInsertOptionsForRiskNotification(byPeriod time.Duration) *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: byPeriod,
		},
	}
}

func JobInsertOptionsForRiskWorkerUnique(byPeriod time.Duration) *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "risk",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: byPeriod,
		},
	}
}

func JobInsertOptionsForRiskDigest(byPeriod time.Duration) *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "digest",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: byPeriod,
		},
	}
}

// JobInsertOptionsForRiskOrphanedCleanup returns insert options for the orphaned risk cleanup job.
// ByArgs deduplication uses the river:"unique" fields on RiskOrphanedCleanupArgs, so active
// jobs are unique by (ssp_id, new_profile_id). Repeated changes to the same target profile are
// collapsed while an equivalent job is active; changes to different target profiles can enqueue
// independent jobs.
//
// ByState is explicitly set to exclude JobStateCompleted and JobStateCancelled so that a second
// profile change to the same target profile re-inserts a fresh cleanup job even if the previous
// one completed but has not yet been removed by River's job-cleaner maintenance process.
func JobInsertOptionsForRiskOrphanedCleanup() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "risk",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRunning,
				rivertype.JobStateRetryable,
				rivertype.JobStateScheduled,
			},
		},
	}
}
