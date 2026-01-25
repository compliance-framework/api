package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type mockJob struct {
	name      string
	executed  bool
	execCount int
}

func (j *mockJob) Name() string {
	return j.name
}

func (j *mockJob) Execute(ctx context.Context) error {
	j.executed = true
	j.execCount++
	return nil
}

func TestCronScheduler_Schedule(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sched := NewCronScheduler(logger)

	job := &mockJob{name: "test-job"}

	err := sched.Schedule(ScheduleDaily, job)
	require.NoError(t, err)

	jobs := sched.ListJobs()
	assert.Contains(t, jobs, "test-job")
}

func TestCronScheduler_ScheduleDuplicate(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sched := NewCronScheduler(logger)

	job1 := &mockJob{name: "test-job"}
	job2 := &mockJob{name: "test-job"}

	err := sched.Schedule(ScheduleDaily, job1)
	require.NoError(t, err)

	err = sched.Schedule(ScheduleWeekly, job2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestCronScheduler_RunNow(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sched := NewCronScheduler(logger)

	job := &mockJob{name: "test-job"}

	err := sched.Schedule(ScheduleDaily, job)
	require.NoError(t, err)

	ctx := context.Background()
	err = sched.RunNow(ctx, "test-job")
	require.NoError(t, err)

	assert.True(t, job.executed)
	assert.Equal(t, 1, job.execCount)
}

func TestCronScheduler_RunNow_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sched := NewCronScheduler(logger)

	ctx := context.Background()
	err := sched.RunNow(ctx, "nonexistent-job")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCronScheduler_StartStop(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sched := NewCronScheduler(logger)

	job := &mockJob{name: "test-job"}
	err := sched.ScheduleCron("* * * * * *", job) // Every second
	require.NoError(t, err)

	sched.Start()

	// Wait a bit for the job to potentially execute
	time.Sleep(1500 * time.Millisecond)

	ctx := sched.Stop()
	<-ctx.Done()

	// Job should have executed at least once
	assert.True(t, job.executed)
	assert.GreaterOrEqual(t, job.execCount, 1)
}

func TestScheduleConstants(t *testing.T) {
	assert.Equal(t, Schedule("@daily"), ScheduleDaily)
	assert.Equal(t, Schedule("@weekly"), ScheduleWeekly)
	assert.Equal(t, Schedule("@monthly"), ScheduleMonthly)
}
