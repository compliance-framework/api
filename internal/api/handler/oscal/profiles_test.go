package oscal

import (
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
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

	t.Run("CrossCatalog", func(t *testing.T) {
		catalogA := uuid.New()
		catalogB := uuid.New()

		merged := mergeControls([]relational.Control{
			{
				CatalogID: catalogA,
				ID:        "AC",
				Title:     "from-a",
			},
			{
				CatalogID: catalogB,
				ID:        "AC",
				Title:     "from-b",
			},
		}...)

		assert.Len(t, merged, 2)
		catalogs := map[uuid.UUID]struct{}{}
		for _, control := range merged {
			catalogs[control.CatalogID] = struct{}{}
		}
		assert.Len(t, catalogs, 2)
	})
}

func TestProfileGroupMerging(t *testing.T) {
	catalogA := uuid.New()
	catalogB := uuid.New()

	merged := mergeGroups([]relational.Group{
		{CatalogID: catalogA, ID: "G-1", Title: "A"},
		{CatalogID: catalogB, ID: "G-1", Title: "B"},
	}...)

	assert.Len(t, merged, 2)
}
