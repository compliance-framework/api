package leverage

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
)

// Project builds the Projection for every leverage link on one downstream SSP in six
// queries at THIS level, independent of link count — the batching that replaced this
// code's original four-queries-per-link loop, preserved here so no caller can
// regress it into an N+1. In particular the ResponsibilityPosture(db, sspID,
// allResponsibilityUUIDs) call below must stay a single call for every uuid, never
// one per link.
//
// The end-to-end cost is ~6 + N, not six: ResponsibilityPosture finishes with a
// per-responsibility loop (relational.EvidenceStatusCountsForFilters) that issues one
// evidence aggregate — count(DISTINCT uuid) grouped by status->>state, over the
// latest-evidence-stream subquery and the label-filter joins — for every
// responsibility carrying at least one FilterResponsibility link. Those N queries are
// the expensive ones, and both /leveraged-controls and GET /:id/shared-responsibility
// pay them. Hoisting that loop rewrites evidence aggregation and belongs in its own
// change.
func Project(db *gorm.DB, sspID uuid.UUID) ([]Projection, error) {
	var links []relational.SSPLeverageLink
	if err := db.Where("downstream_ssp_id = ?", sspID).Order("id ASC").Find(&links).Error; err != nil {
		return nil, fmt.Errorf("failed to list leverage links: %w", err)
	}
	if len(links) == 0 {
		return []Projection{}, nil
	}
	return projectLinks(db, sspID, links)
}

// projectLinks is the shared body of Project (one downstream SSP) and ProjectForControl
// (one control-id across every downstream SSP). It assumes all links belong to the
// single downstream SSP identified by sspID — ResponsibilityPosture and the drift-risk
// lookup are both scoped to it — so ProjectForControl calls it once per SSP group.
func projectLinks(db *gorm.DB, sspID uuid.UUID, links []relational.SSPLeverageLink) ([]Projection, error) {
	offeringIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.OfferingID })
	var offerings []relational.SSPExportOffering
	if err := db.Select("id, title").Where("id IN ?", offeringIDs).Find(&offerings).Error; err != nil {
		return nil, fmt.Errorf("failed to load offerings for leverage links: %w", err)
	}
	offeringTitleByID := make(map[uuid.UUID]string, len(offerings))
	for _, o := range offerings {
		offeringTitleByID[*o.ID] = o.Title
	}

	inheritedIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.InheritedUUID })
	var inheritedRows []relational.InheritedControlImplementation
	if err := db.Where("id IN ?", inheritedIDs).Find(&inheritedRows).Error; err != nil {
		return nil, fmt.Errorf("failed to load inherited control implementations for leverage links: %w", err)
	}
	inheritedByID := make(map[uuid.UUID]relational.InheritedControlImplementation, len(inheritedRows))
	for _, i := range inheritedRows {
		inheritedByID[*i.ID] = i
	}

	providedUUIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.ProvidedUUID })
	fullSetByProvided, err := BulkResolveUpstreamResponsibilities(db, providedUUIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve upstream responsibilities for leverage links: %w", err)
	}

	byComponentIDs := uniqueUUIDs(inheritedRows, func(i relational.InheritedControlImplementation) uuid.UUID { return i.ByComponentId })
	var satisfiedRows []relational.SatisfiedControlImplementationResponsibility
	if len(byComponentIDs) > 0 {
		if err := db.Where("by_component_id IN ?", byComponentIDs).Find(&satisfiedRows).Error; err != nil {
			return nil, fmt.Errorf("failed to load satisfied responsibilities for leverage links: %w", err)
		}
	}
	satisfiedByComponent := make(map[uuid.UUID]map[uuid.UUID]bool, len(byComponentIDs))
	for _, s := range satisfiedRows {
		if satisfiedByComponent[s.ByComponentId] == nil {
			satisfiedByComponent[s.ByComponentId] = make(map[uuid.UUID]bool)
		}
		satisfiedByComponent[s.ByComponentId][s.ResponsibilityUuid] = true
	}

	// Batch every responsibility uuid under every link's provided-uuid into a single
	// ResponsibilityPosture call, rather than one call per link.
	var allResponsibilityUUIDs []uuid.UUID
	for _, full := range fullSetByProvided {
		for _, r := range full {
			allResponsibilityUUIDs = append(allResponsibilityUUIDs, r.ResponsibilityUUID)
		}
	}
	posture, err := ResponsibilityPosture(db, sspID, allResponsibilityUUIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute responsibility posture for leverage links: %w", err)
	}

	// Batch-resolve every drifted link's open drift risk in one query, keyed by the
	// dedupe_key convention DriftDedupeKey/applyDriftToLink already use — rather than a
	// lookup per drifted link.
	dedupeKeyToLinkID := make(map[string]uuid.UUID)
	dedupeKeys := make([]string, 0, len(links))
	for _, link := range links {
		if link.Status != relational.SSPLeverageStatusDrifted {
			continue
		}
		key := DriftDedupeKey(*link.ID)
		dedupeKeyToLinkID[key] = *link.ID
		dedupeKeys = append(dedupeKeys, key)
	}
	driftRiskIDByLinkID := make(map[uuid.UUID]uuid.UUID, len(dedupeKeys))
	if len(dedupeKeys) > 0 {
		var driftRisks []risks.Risk
		if err := db.Select("id, dedupe_key").
			Where("ssp_id = ? AND dedupe_key IN ? AND status != ?", sspID, dedupeKeys, risks.RiskStatusClosed).
			Find(&driftRisks).Error; err != nil {
			return nil, fmt.Errorf("failed to load drift risks for leverage links: %w", err)
		}
		for _, r := range driftRisks {
			if linkID, ok := dedupeKeyToLinkID[r.DedupeKey]; ok {
				driftRiskIDByLinkID[linkID] = *r.ID
			}
		}
	}

	result := make([]Projection, 0, len(links))
	for _, link := range links {
		var inherited *relational.InheritedControlImplementation
		var byComponentID uuid.UUID
		if row, ok := inheritedByID[link.InheritedUUID]; ok {
			inherited = &row
			byComponentID = row.ByComponentId
		}

		full := fullSetByProvided[link.ProvidedUUID]
		satisfaction, outstanding := DeriveSatisfaction(full, satisfiedByComponent[byComponentID])

		linkPosture := make(map[uuid.UUID]string, len(full))
		for _, r := range full {
			linkPosture[r.ResponsibilityUUID] = posture[r.ResponsibilityUUID]
		}

		var driftRiskID *uuid.UUID
		if id, ok := driftRiskIDByLinkID[*link.ID]; ok {
			driftRiskID = &id
		}

		result = append(result, Projection{
			Link:             link,
			OfferingTitle:    offeringTitleByID[link.OfferingID],
			ByComponentID:    byComponentID,
			Inherited:        inherited,
			Satisfaction:     satisfaction,
			Outstanding:      outstanding,
			Responsibilities: full,
			Posture:          linkPosture,
			DriftRiskID:      driftRiskID,
		})
	}

	return result, nil
}

// ProjectForControl builds the Projection for every downstream SSP holding at least
// one leverage link for controlID (UPPER-folded match, no catalog id — the same
// keying every leverage read uses). It groups the links by downstream SSP and runs
// the same batched resolution projectLinks performs per SSP, so ResponsibilityPosture
// and the drift-risk lookup (both SSP-scoped) run once per involved downstream SSP —
// bounded by subscriber count, acceptable because this backs the drawer endpoint only.
// The returned map is keyed by downstream SSP id.
func ProjectForControl(db *gorm.DB, controlID string) (map[uuid.UUID][]Projection, error) {
	var links []relational.SSPLeverageLink
	if err := db.Where("UPPER(control_id) = UPPER(?)", controlID).Order("id ASC").Find(&links).Error; err != nil {
		return nil, fmt.Errorf("failed to list leverage links for control: %w", err)
	}
	result := make(map[uuid.UUID][]Projection)
	if len(links) == 0 {
		return result, nil
	}

	linksBySSP := make(map[uuid.UUID][]relational.SSPLeverageLink)
	sspOrder := make([]uuid.UUID, 0)
	for _, link := range links {
		if _, seen := linksBySSP[link.DownstreamSSPID]; !seen {
			sspOrder = append(sspOrder, link.DownstreamSSPID)
		}
		linksBySSP[link.DownstreamSSPID] = append(linksBySSP[link.DownstreamSSPID], link)
	}

	for _, sspID := range sspOrder {
		projections, err := projectLinks(db, sspID, linksBySSP[sspID])
		if err != nil {
			return nil, err
		}
		result[sspID] = projections
	}
	return result, nil
}
