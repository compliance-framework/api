package worker

// poam_periodic_jobs.go — PeriodicJob constructors and scanner worker registration
// for BCH-1186 Phase 3 POAM background jobs.
//
// Three jobs are registered:
//   1. PoamDeadlineReminderScanner  — daily 08:00 UTC (0 0 8 * * *)
//   2. PoamOverdueTransitionScanner — daily 09:00 UTC (0 0 9 * * *)
//   3. MilestoneOverdueScanner      — weekly Monday 10:00 UTC (0 0 10 * * 1)

import (
	"time"

	"github.com/riverqueue/river"
	"go.uber.org/zap"
)

// NewPoamDeadlineReminderPeriodicJob creates the River PeriodicJob for the daily
// POAM deadline reminder scanner. Default cron: "0 0 8 * * *" (08:00 UTC).
func NewPoamDeadlineReminderPeriodicJob(schedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	sched := parseCronScheduleWithFallback(schedule, "0 0 8 * * *", "poam deadline reminder scanner", logger)
	return river.NewPeriodicJob(
		sched,
		func() (river.JobArgs, *river.InsertOpts) {
			return &PoamDeadlineReminderScannerArgs{}, &river.InsertOpts{
				Queue:       "poam",
				MaxAttempts: 3,
				UniqueOpts: river.UniqueOpts{
					ByArgs:   true,
					ByPeriod: 24 * time.Hour,
				},
			}
		},
		&river.PeriodicJobOpts{
			RunOnStart: false,
		},
	)
}

// NewPoamOverdueTransitionPeriodicJob creates the River PeriodicJob for the daily
// POAM overdue transition scanner. Default cron: "0 0 9 * * *" (09:00 UTC).
func NewPoamOverdueTransitionPeriodicJob(schedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	sched := parseCronScheduleWithFallback(schedule, "0 0 9 * * *", "poam overdue transition scanner", logger)
	return river.NewPeriodicJob(
		sched,
		func() (river.JobArgs, *river.InsertOpts) {
			return &PoamOverdueTransitionScannerArgs{}, &river.InsertOpts{
				Queue:       "poam",
				MaxAttempts: 3,
				UniqueOpts: river.UniqueOpts{
					ByArgs:   true,
					ByPeriod: 24 * time.Hour,
				},
			}
		},
		&river.PeriodicJobOpts{
			RunOnStart: false,
		},
	)
}

// NewMilestoneOverduePeriodicJob creates the River PeriodicJob for the weekly
// incomplete milestone scanner. Default cron: "0 0 10 * * 1" (Monday 10:00 UTC).
func NewMilestoneOverduePeriodicJob(schedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	sched := parseCronScheduleWithFallback(schedule, "0 0 10 * * 1", "milestone overdue scanner", logger)
	return river.NewPeriodicJob(
		sched,
		func() (river.JobArgs, *river.InsertOpts) {
			return &MilestoneOverdueScannerArgs{}, &river.InsertOpts{
				Queue:       "poam",
				MaxAttempts: 3,
				UniqueOpts: river.UniqueOpts{
					ByArgs:   true,
					ByPeriod: 7 * 24 * time.Hour,
				},
			}
		},
		&river.PeriodicJobOpts{
			RunOnStart: false,
		},
	)
}

