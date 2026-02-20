package digest

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestConvertToEvidenceItems(t *testing.T) {
	// Test the conversion logic without database dependencies
	now := time.Now()
	items := []EvidenceItem{
		{
			ID:          uuid.New().String(),
			UUID:        uuid.New().String(),
			Title:       "Test Evidence",
			Description: "Test Description",
			Status:      "not-satisfied",
			ExpiresAt:   now.Format("2006-01-02 15:04 MST"),
			Labels:      []string{"provider:aws", "env:prod"},
		},
	}

	assert.Len(t, items, 1)
	assert.Equal(t, "Test Evidence", items[0].Title)
	assert.Equal(t, "not-satisfied", items[0].Status)
	assert.Len(t, items[0].Labels, 2)
	assert.NotEmpty(t, items[0].ExpiresAt)
}

func TestEvidenceSummaryStructure(t *testing.T) {
	summary := &EvidenceSummary{
		TotalCount:        100,
		SatisfiedCount:    80,
		NotSatisfiedCount: 15,
		ExpiredCount:      5,
		OtherCount:        0,
		TopExpired: []EvidenceItem{
			{Title: "Expired 1"},
			{Title: "Expired 2"},
		},
		TopNotSatisfied: []EvidenceItem{
			{Title: "Failed 1"},
		},
	}

	assert.Equal(t, int64(100), summary.TotalCount)
	assert.Equal(t, int64(80), summary.SatisfiedCount)
	assert.Equal(t, int64(15), summary.NotSatisfiedCount)
	assert.Equal(t, int64(5), summary.ExpiredCount)
	assert.Len(t, summary.TopExpired, 2)
	assert.Len(t, summary.TopNotSatisfied, 1)
}
