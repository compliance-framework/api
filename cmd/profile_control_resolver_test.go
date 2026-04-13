package cmd

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestOscalProfileControlResolver_ReturnsPivotQueryError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	resolver := &oscalProfileControlResolver{db: db}
	_, err = resolver.ResolveProfileControlKeys(context.Background(), uuid.New())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "profile_controls query failed")
}

func TestOscalProfileControlResolver_ReturnsPivotRows(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`
		CREATE TABLE profile_controls (
			profile_id TEXT NOT NULL,
			control_catalog_id TEXT NOT NULL,
			control_id TEXT NOT NULL
		)
	`).Error)

	profileID := uuid.New()
	require.NoError(t, db.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID.String(),
		"catalog-1",
		"AC-1",
	).Error)

	resolver := &oscalProfileControlResolver{db: db}
	keys, err := resolver.ResolveProfileControlKeys(context.Background(), profileID)

	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "catalog-1", keys[0].CatalogID)
	assert.Equal(t, "AC-1", keys[0].ControlID)
}
