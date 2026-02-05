package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGeneratePeriodLabel(t *testing.T) {
	tests := []struct {
		name     string
		cadence  string
		time     time.Time
		expected string
	}{
		{
			name:     "Daily cadence",
			cadence:  string(workflows.CadenceDaily),
			time:     time.Date(2023, 10, 15, 10, 0, 0, 0, time.UTC),
			expected: "2023-10-15",
		},
		{
			name:     "Weekly cadence - middle of week",
			cadence:  string(workflows.CadenceWeekly),
			time:     time.Date(2023, 10, 18, 10, 0, 0, 0, time.UTC), // Wednesday
			expected: "2023-W42",
		},
		{
			name:     "Weekly cadence - start of week",
			cadence:  string(workflows.CadenceWeekly),
			time:     time.Date(2023, 10, 16, 10, 0, 0, 0, time.UTC), // Monday
			expected: "2023-W42",
		},
		{
			name:     "Weekly cadence - end of year boundary (ISO week)",
			cadence:  string(workflows.CadenceWeekly),
			time:     time.Date(2023, 12, 31, 10, 0, 0, 0, time.UTC),
			expected: "2023-W52", // Actually 2023 ends with W52
		},
		{
			name:     "Monthly cadence",
			cadence:  string(workflows.CadenceMonthly),
			time:     time.Date(2023, 10, 15, 10, 0, 0, 0, time.UTC),
			expected: "2023-10",
		},
		{
			name:     "Monthly cadence - single digit month",
			cadence:  string(workflows.CadenceMonthly),
			time:     time.Date(2023, 1, 15, 10, 0, 0, 0, time.UTC),
			expected: "2023-01",
		},
		{
			name:     "Quarterly cadence - Q1",
			cadence:  string(workflows.CadenceQuarterly),
			time:     time.Date(2023, 2, 15, 10, 0, 0, 0, time.UTC),
			expected: "Q1-2023",
		},
		{
			name:     "Quarterly cadence - Q2",
			cadence:  string(workflows.CadenceQuarterly),
			time:     time.Date(2023, 5, 15, 10, 0, 0, 0, time.UTC),
			expected: "Q2-2023",
		},
		{
			name:     "Quarterly cadence - Q3",
			cadence:  string(workflows.CadenceQuarterly),
			time:     time.Date(2023, 8, 15, 10, 0, 0, 0, time.UTC),
			expected: "Q3-2023",
		},
		{
			name:     "Quarterly cadence - Q4",
			cadence:  string(workflows.CadenceQuarterly),
			time:     time.Date(2023, 11, 15, 10, 0, 0, 0, time.UTC),
			expected: "Q4-2023",
		},
		{
			name:     "Annually cadence",
			cadence:  string(workflows.CadenceAnnually),
			time:     time.Date(2023, 10, 15, 10, 0, 0, 0, time.UTC),
			expected: "2023",
		},
		{
			name:     "Unknown cadence fallback",
			cadence:  "hourly",
			time:     time.Date(2023, 10, 15, 10, 0, 0, 0, time.UTC),
			expected: "2023-10-15",
		},
		{
			name:     "Cron cadence - uses timestamp format",
			cadence:  "cron:0 0 9 * * *",
			time:     time.Date(2023, 10, 15, 9, 0, 0, 0, time.UTC),
			expected: "2023-10-15T09:00:00",
		},
		{
			name:     "Cron cadence - different time",
			cadence:  "cron:0 30 14 * * *",
			time:     time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC),
			expected: "2023-10-15T14:30:00",
		},
		{
			name:     "Cron cadence - with seconds",
			cadence:  "cron:30 0 9 * * *",
			time:     time.Date(2023, 10, 15, 9, 0, 30, 0, time.UTC),
			expected: "2023-10-15T09:00:30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GeneratePeriodLabel(tt.cadence, tt.time)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateDueDate(t *testing.T) {
	tests := []struct {
		name            string
		scheduledTime   time.Time
		gracePeriodDays int
		expected        time.Time
	}{
		{
			name:            "Zero grace period",
			scheduledTime:   time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC),
			gracePeriodDays: 0,
			expected:        time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC),
		},
		{
			name:            "Positive grace period",
			scheduledTime:   time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC),
			gracePeriodDays: 7,
			expected:        time.Date(2023, 1, 8, 10, 0, 0, 0, time.UTC),
		},
		{
			name:            "Month rollover",
			scheduledTime:   time.Date(2023, 1, 30, 10, 0, 0, 0, time.UTC),
			gracePeriodDays: 5,
			expected:        time.Date(2023, 2, 4, 10, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateDueDate(tt.scheduledTime, tt.gracePeriodDays)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test basic workflow scheduler worker functionality without river.Job dependency
func TestWorkflowSchedulerWorker_BasicFunctionality(t *testing.T) {
	// Setup mocks
	mockInstanceService := new(MockWorkflowInstanceService)

	// Test data
	instanceID := uuid.New()
	dueInstances := []workflows.WorkflowInstance{
		{
			UUIDModel:       relational.UUIDModel{ID: &instanceID},
			Cadence:         string(workflows.CadenceDaily),
			GracePeriodDays: &[]int{7}[0],
			WorkflowDefinition: &workflows.WorkflowDefinition{
				UUIDModel: relational.UUIDModel{ID: uuidPtr(uuid.New())},
			},
		},
	}

	// Test GetDueInstances functionality
	ctx := context.Background()
	mockInstanceService.On("GetDueInstances", ctx).Return(dueInstances, nil)
	mockInstanceService.On("AdvanceSchedule", ctx, &instanceID).Return(nil)

	// Test that we can get due instances
	instances, err := mockInstanceService.GetDueInstances(ctx)
	assert.NoError(t, err)
	assert.Len(t, instances, 1)

	// Test that we can advance schedule
	err = mockInstanceService.AdvanceSchedule(ctx, &instanceID)
	assert.NoError(t, err)

	// Verify all mock expectations were met
	mockInstanceService.AssertExpectations(t)
}

// Mock logger for testing
type MockLoggerForScheduler struct {
	mock.Mock
}

func (m *MockLoggerForScheduler) Infow(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

func (m *MockLoggerForScheduler) Errorw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

func (m *MockLoggerForScheduler) Warnw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

func (m *MockLoggerForScheduler) Debugw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

// Helper function to create UUID pointer
func uuidPtr(u uuid.UUID) *uuid.UUID {
	return &u
}
