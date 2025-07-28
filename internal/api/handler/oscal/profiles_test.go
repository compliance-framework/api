package oscal

import (
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProfileControlMerging(t *testing.T) {
	t.Run("Simple", func(t *testing.T) {
		merged := mergeControls([]relational.Control{
			{
				ID:    "AC",
				Title: "asd",
			},
			{
				ID:    "AC",
				Title: "asd",
			},
		}...)
		assert.Len(t, merged, 1)
		assert.Equal(t, "AC", merged[0].ID)
	})

	t.Run("Sub", func(t *testing.T) {
		merged := mergeControls([]relational.Control{
			{
				ID:    "AC",
				Title: "asd",
				Controls: []relational.Control{
					{
						ID: "AC-1",
					},
					{
						ID: "AC-2",
					},
				},
			},
			{
				ID:    "AC",
				Title: "asd",
				Controls: []relational.Control{
					{
						ID: "AC-1",
					},
				},
			},
		}...)
		assert.Len(t, merged, 1)
		assert.Equal(t, "AC", merged[0].ID)
		assert.Len(t, merged[0].Controls, 2)
	})
}
