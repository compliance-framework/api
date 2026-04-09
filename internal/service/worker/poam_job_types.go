package worker

import (
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
)

// ─── Job type constants ───────────────────────────────────────────────────────

const (
	// Scanner job kinds — one per periodic trigger.
	JobTypePoamDeadlineReminderScanner    = "poam_deadline_reminder_scanner"
	JobTypePoamOverdueTransitionScanner   = "poam_overdue_transition_scanner"
	JobTypeMilestoneOverdueScannerScanner = "poam_milestone_overdue_scanner"

	// Notification / action job kinds — one per item per recipient.
	JobTypePoamDeadlineReminder     = "poam_deadline_reminder"
	JobTypePoamOverdueNotification  = "poam_overdue_notification"
	JobTypeMilestoneOverdueReminder = "poam_milestone_overdue_reminder"

	// Digest job kinds.
	JobTypePoamOpenDigestScheduler = "poam_open_digest_scheduler"
	JobTypePoamOpenDigest          = "poam_open_digest"
)

// ─── Scanner args (no payload — scanner reads DB itself) ─────────────────────

// PoamDeadlineReminderScannerArgs is the args type for the daily POAM deadline
// reminder scanner job (cron: 0 0 8 * * *, i.e. 08:00 UTC daily).
// The scanner queries for open/in-progress POAM items whose deadline falls
// within the configured reminder window and enqueues a PoamDeadlineReminderArgs job per
// item per recipient.
type PoamDeadlineReminderScannerArgs struct{}

// PoamOverdueTransitionScannerArgs is the args type for the daily POAM overdue
// transition scanner job (cron: 0 0 9 * * *, i.e. 09:00 UTC daily).
// The scanner queries for open/in-progress POAM items whose deadline has
// already passed, transitions their status to "overdue" in the DB, and
// enqueues a PoamOverdueNotificationArgs job per item per recipient.
type PoamOverdueTransitionScannerArgs struct{}

// MilestoneOverdueScannerArgs is the args type for the weekly incomplete
// milestone scanner job (cron: 0 0 10 * * 1, i.e. Monday 10:00 UTC).
// The scanner queries for milestones in "planned" status whose due_date has
// passed and whose parent POAM item is not completed, then enqueues a
// MilestoneOverdueReminderArgs job per milestone per recipient.
type MilestoneOverdueScannerArgs struct{}

// ─── Notification / action args ──────────────────────────────────────────────

// PoamDeadlineReminderArgs carries the data needed to send a single
// POAM deadline approaching reminder email to one recipient.
// Idempotency key: PoamItemID + Deadline + ReminderWindowBucket (ByArgs + ByPeriod 24h).
type PoamDeadlineReminderArgs struct {
	PoamItemID           uuid.UUID `json:"poam_item_id"`
	RecipientUserID      uuid.UUID `json:"recipient_user_id"`
	PoamTitle            string    `json:"poam_title"`
	SspID                uuid.UUID `json:"ssp_id"`
	SspDisplayName       string    `json:"ssp_display_name"`
	CurrentStatus        string    `json:"current_status"`
	Deadline             string    `json:"deadline"` // RFC3339
	MilestoneCount       int       `json:"milestone_count"`
	PoamURL              string    `json:"poam_url"`
	ReminderWindowBucket string    `json:"reminder_window_bucket"` // e.g. "2026-03-31"
}

// PoamOverdueNotificationArgs carries the data needed to send a single
// POAM overdue notification email to one recipient.
// Idempotency key: PoamItemID + Deadline + OverdueWindow (ByArgs + ByPeriod 24h).
type PoamOverdueNotificationArgs struct {
	PoamItemID      uuid.UUID `json:"poam_item_id"`
	RecipientUserID uuid.UUID `json:"recipient_user_id"`
	PoamTitle       string    `json:"poam_title"`
	SspID           uuid.UUID `json:"ssp_id"`
	SspDisplayName  string    `json:"ssp_display_name"`
	Deadline        string    `json:"deadline"` // RFC3339
	PoamURL         string    `json:"poam_url"`
	OverdueWindow   string    `json:"overdue_window"` // e.g. "2026-03-31"
}

// PoamOpenDigestSchedulerArgs is the args type for the periodic POAM digest
// scheduler job. It has no payload — the scheduler resolves recipients from DB.
type PoamOpenDigestSchedulerArgs struct{}

// PoamOpenDigestArgs carries the data needed to build and send the grouped
// POAM digest email for a single recipient.
// Idempotency key: RecipientUserID + WindowStart + WindowEnd (ByArgs + ByPeriod).
type PoamOpenDigestArgs struct {
	RecipientUserID uuid.UUID `json:"recipient_user_id"`
	WindowStart     string    `json:"window_start"` // RFC3339
	WindowEnd       string    `json:"window_end"`   // RFC3339
	WindowKind      string    `json:"window_kind"`  // "daily" | "weekly"
}

// MilestoneOverdueReminderArgs carries the data needed to send a single
// incomplete milestone overdue reminder email to one recipient.
// Idempotency key: MilestoneID + DueDate + WeeklyBucket (ByArgs + ByPeriod 7 days).
type MilestoneOverdueReminderArgs struct {
	MilestoneID     uuid.UUID `json:"milestone_id"`
	PoamItemID      uuid.UUID `json:"poam_item_id"`
	RecipientUserID uuid.UUID `json:"recipient_user_id"`
	MilestoneTitle  string    `json:"milestone_title"`
	PoamTitle       string    `json:"poam_title"`
	SspID           uuid.UUID `json:"ssp_id"`
	SspDisplayName  string    `json:"ssp_display_name"`
	DueDate         string    `json:"due_date"` // RFC3339
	PoamURL         string    `json:"poam_url"`
	WeeklyBucket    string    `json:"weekly_bucket"` // e.g. "2026-W14"
}

// ─── Kind() methods ──────────────────────────────────────────────────────────

func (PoamDeadlineReminderScannerArgs) Kind() string  { return JobTypePoamDeadlineReminderScanner }
func (PoamOverdueTransitionScannerArgs) Kind() string { return JobTypePoamOverdueTransitionScanner }
func (MilestoneOverdueScannerArgs) Kind() string      { return JobTypeMilestoneOverdueScannerScanner }
func (PoamDeadlineReminderArgs) Kind() string         { return JobTypePoamDeadlineReminder }
func (PoamOverdueNotificationArgs) Kind() string      { return JobTypePoamOverdueNotification }
func (MilestoneOverdueReminderArgs) Kind() string     { return JobTypeMilestoneOverdueReminder }
func (PoamOpenDigestSchedulerArgs) Kind() string      { return JobTypePoamOpenDigestScheduler }
func (PoamOpenDigestArgs) Kind() string               { return JobTypePoamOpenDigest }

// ─── Timeout() methods ───────────────────────────────────────────────────────

func (PoamDeadlineReminderScannerArgs) Timeout() time.Duration  { return 30 * time.Second }
func (PoamOverdueTransitionScannerArgs) Timeout() time.Duration { return 30 * time.Second }
func (MilestoneOverdueScannerArgs) Timeout() time.Duration      { return 30 * time.Second }
func (PoamDeadlineReminderArgs) Timeout() time.Duration         { return 30 * time.Second }
func (PoamOverdueNotificationArgs) Timeout() time.Duration      { return 30 * time.Second }
func (MilestoneOverdueReminderArgs) Timeout() time.Duration     { return 30 * time.Second }
func (PoamOpenDigestSchedulerArgs) Timeout() time.Duration      { return 5 * time.Minute }
func (PoamOpenDigestArgs) Timeout() time.Duration               { return 30 * time.Second }

// ─── Insert option helpers ───────────────────────────────────────────────────

// JobInsertOptionsForPoamNotification returns insert options for POAM notification
// email jobs with 24-hour idempotency window (daily scanners).
func JobInsertOptionsForPoamNotification(byPeriod time.Duration) *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: byPeriod,
		},
	}
}

// JobInsertOptionsForPoamDigest returns insert options for POAM digest jobs on
// the "digest" queue. Idempotency is enforced via ByArgs + ByPeriod.
func JobInsertOptionsForPoamDigest(byPeriod time.Duration) *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "digest",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: byPeriod,
		},
	}
}

// JobInsertOptionsForPoamWorker returns insert options for POAM scanner/worker
// jobs on the "poam" queue with idempotency.
func JobInsertOptionsForPoamWorker(byPeriod time.Duration) *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "poam",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: byPeriod,
		},
	}
}
