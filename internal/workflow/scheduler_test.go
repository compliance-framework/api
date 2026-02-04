package workflow

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/stretchr/testify/assert"
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
