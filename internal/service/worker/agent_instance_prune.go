package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// JobTypeAgentInstancePrune prunes agent instances that are no longer reporting (R37).
const JobTypeAgentInstancePrune = "agent_instance_prune"

// defaultAgentInstancePruneSchedule is hourly, River 6-field (seconds first).
const defaultAgentInstancePruneSchedule = "0 17 * * * *"

// AgentInstancePruneArgs are the (empty) args of the periodic prune job.
type AgentInstancePruneArgs struct{}

// Kind implements river.JobArgs.
func (AgentInstancePruneArgs) Kind() string { return JobTypeAgentInstancePrune }

// AgentInstancePruneWorker deletes one-shot instances (daemon=false) not seen for the
// one-shot retention (24h) and any instance not seen for the retention (720h).
type AgentInstancePruneWorker struct {
	db       *gorm.DB
	settings agentcfg.Settings
	logger   *zap.SugaredLogger
	now      func() time.Time
}

// NewAgentInstancePruneWorker builds the worker.
func NewAgentInstancePruneWorker(db *gorm.DB, settings agentcfg.Settings, logger *zap.SugaredLogger) *AgentInstancePruneWorker {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &AgentInstancePruneWorker{db: db, settings: settings.WithDefaults(), logger: logger, now: func() time.Time { return time.Now().UTC() }}
}

// Work implements the River worker function.
func (w *AgentInstancePruneWorker) Work(ctx context.Context, _ *river.Job[AgentInstancePruneArgs]) error {
	deleted, err := agentcfg.PruneInstances(ctx, w.db, w.settings, w.now())
	if err != nil {
		return fmt.Errorf("agent instance prune: %w", err)
	}
	if deleted > 0 {
		w.logger.Infow("Pruned agent instances", "deleted", deleted)
	}
	return nil
}

// NewAgentInstancePrunePeriodicJob schedules the prune job on the "scheduler" queue.
func NewAgentInstancePrunePeriodicJob(schedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	sched := parseCronScheduleWithFallback(schedule, defaultAgentInstancePruneSchedule, "agent instance prune", logger)
	return river.NewPeriodicJob(
		sched,
		func() (river.JobArgs, *river.InsertOpts) {
			return &AgentInstancePruneArgs{}, &river.InsertOpts{
				Queue:       "scheduler",
				MaxAttempts: 3,
				UniqueOpts: river.UniqueOpts{
					ByArgs:   true,
					ByPeriod: time.Hour,
				},
			}
		},
		&river.PeriodicJobOpts{RunOnStart: false},
	)
}
