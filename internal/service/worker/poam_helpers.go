package worker

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// resolvePoamRecipients returns the unique set of recipient user IDs for a
// POAM item. Currently this is the PrimaryOwnerUserID if set.
// Future iterations can expand this to SSP owner assignments.
func resolvePoamRecipients(item *poam.PoamItem) []uuid.UUID {
	if item.PrimaryOwnerUserID != nil {
		return []uuid.UUID{*item.PrimaryOwnerUserID}
	}
	return nil
}

// resolvePoamRecipientsFromOwner resolves a recipient slice from a raw owner
// UUID string pointer (used when reading from a JOIN query result).
func resolvePoamRecipientsFromOwner(ownerStr *string) []uuid.UUID {
	if ownerStr == nil || *ownerStr == "" {
		return nil
	}
	id, err := uuid.Parse(*ownerStr)
	if err != nil {
		return nil
	}
	return []uuid.UUID{id}
}

// resolvePoamSSPDisplayNames resolves a map of sspID → display name for a
// batch of POAM items. Falls back to the UUID string if the SSP record is not
// found or has no name.
func resolvePoamSSPDisplayNames(ctx context.Context, db *gorm.DB, items []poam.PoamItem) (map[string]string, error) {
	result := make(map[string]string, len(items))

	// Collect unique SSP IDs.
	seen := make(map[uuid.UUID]struct{}, len(items))
	sspIDs := make([]uuid.UUID, 0, len(items))
	for i := range items {
		id := items[i].SspID
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			sspIDs = append(sspIDs, id)
		}
	}
	if len(sspIDs) == 0 {
		return result, nil
	}

	// Query system_characteristics for display names.
	type row struct {
		SystemSecurityPlanID string
		SystemNameShort      string
		SystemName           string
	}
	var rows []row
	if err := db.WithContext(ctx).
		Table("system_characteristics").
		Select("system_security_plan_id, system_name_short, system_name").
		Where("system_security_plan_id IN ?", sspIDs).
		Scan(&rows).Error; err != nil {
		return result, fmt.Errorf("resolvePoamSSPDisplayNames: query failed: %w", err)
	}

	for _, r := range rows {
		name := strings.TrimSpace(r.SystemNameShort)
		if name == "" {
			name = strings.TrimSpace(r.SystemName)
		}
		if name == "" {
			name = r.SystemSecurityPlanID
		}
		result[r.SystemSecurityPlanID] = name
	}
	return result, nil
}

// resolvePoamURL builds the direct link to a POAM item in the web UI.
func resolvePoamURL(webBaseURL string, poamItemID uuid.UUID) string {
	base := strings.TrimRight(webBaseURL, "/")
	return base + "/poam-items/" + poamItemID.String()
}
