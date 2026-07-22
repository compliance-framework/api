package leverage

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
)

// ResponsibilityPosture computes per-responsibility compliance posture (satisfied /
// not-satisfied / unknown) for a downstream SSP, using the same evidence
// status-count/collapse logic as control-keyed posture
// (relational.CollapseEvidenceStatus), but keyed by responsibility_uuid via
// filter_responsibilities instead of by (catalogId, controlId) via filter_controls
// (BCH-1339). Feeds the Inherited Capability projection so a downstream can see
// whether an inherited responsibility is actually backed by satisfying evidence, not
// just recorded as satisfied at subscribe time. Every requested uuid is always
// present in the returned map — defaulting to "unknown" when no filter targets it —
// never an absent key, matching BulkResolveUpstreamResponsibilities's convention.
func ResponsibilityPosture(db *gorm.DB, downstreamSSPID uuid.UUID, responsibilityUUIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	posture := make(map[uuid.UUID]string, len(responsibilityUUIDs))
	for _, id := range responsibilityUUIDs {
		posture[id] = "unknown"
	}
	if len(responsibilityUUIDs) == 0 {
		return posture, nil
	}

	var links []relational.FilterResponsibility
	if err := db.Where("ssp_id = ? AND responsibility_uuid IN ?", downstreamSSPID, responsibilityUUIDs).
		Find(&links).Error; err != nil {
		return nil, err
	}
	if len(links) == 0 {
		return posture, nil
	}

	filterIDs := make([]uuid.UUID, 0, len(links))
	seenFilterIDs := make(map[uuid.UUID]bool, len(links))
	for _, link := range links {
		if !seenFilterIDs[link.FilterID] {
			seenFilterIDs[link.FilterID] = true
			filterIDs = append(filterIDs, link.FilterID)
		}
	}

	var filters []relational.Filter
	if err := db.Where("id IN ?", filterIDs).Find(&filters).Error; err != nil {
		return nil, err
	}
	filterByID := make(map[uuid.UUID]relational.Filter, len(filters))
	for _, f := range filters {
		filterByID[*f.ID] = f
	}

	filtersByResponsibility := make(map[uuid.UUID][]labelfilter.Filter, len(links))
	for _, link := range links {
		f, ok := filterByID[link.FilterID]
		if !ok {
			continue
		}
		filtersByResponsibility[link.ResponsibilityUUID] = append(filtersByResponsibility[link.ResponsibilityUUID], f.Filter.Data())
	}

	for respID, filterList := range filtersByResponsibility {
		statusCounts, err := relational.EvidenceStatusCountsForFilters(db, filterList)
		if err != nil {
			return nil, err
		}
		posture[respID] = relational.CollapseEvidenceStatus(statusCounts)
	}

	return posture, nil
}
