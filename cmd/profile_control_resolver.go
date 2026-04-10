package cmd

import (
	"context"
	"fmt"

	oscalhandler "github.com/compliance-framework/api/internal/api/handler/oscal"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// oscalProfileControlResolver implements worker.ProfileControlResolver using the oscal handler
// package's profile resolution functions. It lives in the cmd package to break the circular
// import that would result from importing the oscal handler directly from the worker package.
//
// Resolution strategy:
//  1. Fast path — query the profile_controls pivot table (populated by SyncProfileControls).
//     Returns both control_id and control_catalog_id so the full ControlKey is available.
//  2. Fallback — if the pivot table is empty (SyncProfileControls has not yet run for a
//     newly created profile), perform a full recursive resolution via FindFullProfile and
//     GetControlIDsMapFromProfile. This guarantees correctness even before the pivot is populated.
type oscalProfileControlResolver struct {
	db *gorm.DB
}

func (r *oscalProfileControlResolver) ResolveProfileControlKeys(ctx context.Context, profileID uuid.UUID) ([]riskrel.ControlKey, error) {
	// Step 1: pivot table fast path.
	type pivotRow struct {
		ControlCatalogID string `gorm:"column:control_catalog_id"`
		ControlID        string `gorm:"column:control_id"`
	}
	var rows []pivotRow
	if err := r.db.WithContext(ctx).
		Table("profile_controls").
		Select("control_catalog_id, control_id").
		Where("profile_id = ?", profileID).
		Find(&rows).Error; err == nil && len(rows) > 0 {
		keys := make([]riskrel.ControlKey, 0, len(rows))
		for _, row := range rows {
			keys = append(keys, riskrel.ControlKey{
				CatalogID: row.ControlCatalogID,
				ControlID: row.ControlID,
			})
		}
		return keys, nil
	}

	// Step 2: full recursive resolution — pivot table is empty or query failed.
	profile, err := oscalhandler.FindFullProfile(r.db.WithContext(ctx), profileID)
	if err != nil {
		return nil, fmt.Errorf("oscalProfileControlResolver: FindFullProfile failed for profile %s: %w", profileID, err)
	}

	idsMap, err := oscalhandler.GetControlIDsMapFromProfile(profile, r.db.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("oscalProfileControlResolver: GetControlIDsMapFromProfile failed for profile %s: %w", profileID, err)
	}

	keys := make([]riskrel.ControlKey, 0, len(idsMap))
	for controlID, catalogID := range idsMap {
		keys = append(keys, riskrel.ControlKey{
			CatalogID: catalogID.String(),
			ControlID: controlID,
		})
	}
	return keys, nil
}
