package leverage

import (
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/service/relational"
)

// LinkSummary is one leverage link reduced to what the cross-SSP compliance and
// lineage read surfaces need: the identity of the link, the upstream it came from
// (with resolved titles), its lifecycle Status, and its LIVE-derived Satisfaction and
// responsibility counts. Satisfaction is recomputed from the current satisfied rows
// via DeriveSatisfaction — never the link's stored satisfaction column, which can rot
// when the upstream changes its responsibility set.
type LinkSummary struct {
	LinkID          uuid.UUID
	DownstreamSSPID uuid.UUID
	UpstreamSSPID   uuid.UUID
	OfferingID      uuid.UUID

	UpstreamSSPTitle string
	OfferingTitle    string
	OfferingVersion  int

	ControlID   string // as stored (casing preserved); folded only when aggregating
	StatementID *string

	Status       relational.SSPLeverageStatus
	Satisfaction relational.SSPLeverageSatisfaction

	OutstandingCount      int
	TotalResponsibilities int
}

// Summarize builds a LinkSummary for every leverage link, live-deriving satisfaction,
// in ~7 bulk queries regardless of link count. sspID nil summarizes every downstream
// SSP (lineage global scope); non-nil restricts to that one downstream SSP.
//
// It is deliberately lighter than Project: no per-responsibility posture and no drift
// risk id (those back the drawer/detail views, not the counts), so it stays cheap
// enough to run on every lineage engine build.
func Summarize(db *gorm.DB, sspID *uuid.UUID) ([]LinkSummary, error) {
	var links []relational.SSPLeverageLink
	query := db.Order("id ASC")
	if sspID != nil {
		query = query.Where("downstream_ssp_id = ?", *sspID)
	}
	if err := query.Find(&links).Error; err != nil {
		return nil, err
	}
	if len(links) == 0 {
		return []LinkSummary{}, nil
	}

	// Inherited rows resolve each link's by-component (the anchor its satisfied rows
	// hang off).
	inheritedIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.InheritedUUID })
	var inheritedRows []relational.InheritedControlImplementation
	if err := db.Where("id IN ?", inheritedIDs).Find(&inheritedRows).Error; err != nil {
		return nil, err
	}
	byComponentByInherited := make(map[uuid.UUID]uuid.UUID, len(inheritedRows))
	for _, i := range inheritedRows {
		byComponentByInherited[*i.ID] = i.ByComponentId
	}

	// Full upstream responsibility set per provided-uuid (2 queries inside).
	providedUUIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.ProvidedUUID })
	fullSetByProvided, err := BulkResolveUpstreamResponsibilities(db, providedUUIDs)
	if err != nil {
		return nil, err
	}

	// Satisfied rows per by-component, for the live satisfaction derivation.
	byComponentIDs := uniqueUUIDs(inheritedRows, func(i relational.InheritedControlImplementation) uuid.UUID { return i.ByComponentId })
	var satisfiedRows []relational.SatisfiedControlImplementationResponsibility
	if len(byComponentIDs) > 0 {
		if err := db.Where("by_component_id IN ?", byComponentIDs).Find(&satisfiedRows).Error; err != nil {
			return nil, err
		}
	}
	satisfiedByComponent := make(map[uuid.UUID]map[uuid.UUID]bool, len(byComponentIDs))
	for _, s := range satisfiedRows {
		if satisfiedByComponent[s.ByComponentId] == nil {
			satisfiedByComponent[s.ByComponentId] = make(map[uuid.UUID]bool)
		}
		satisfiedByComponent[s.ByComponentId][s.ResponsibilityUuid] = true
	}

	// Offering titles.
	offeringIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.OfferingID })
	var offerings []relational.SSPExportOffering
	if err := db.Select("id, title").Where("id IN ?", offeringIDs).Find(&offerings).Error; err != nil {
		return nil, err
	}
	offeringTitleByID := make(map[uuid.UUID]string, len(offerings))
	for _, o := range offerings {
		offeringTitleByID[*o.ID] = o.Title
	}

	// Upstream SSP titles (Preload Metadata mirrors collectInheritedSharedResponsibility).
	upstreamIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.UpstreamSSPID })
	var upstreams []relational.SystemSecurityPlan
	if err := db.Preload("Metadata").Where("id IN ?", upstreamIDs).Find(&upstreams).Error; err != nil {
		return nil, err
	}
	upstreamTitleByID := make(map[uuid.UUID]string, len(upstreams))
	for _, s := range upstreams {
		upstreamTitleByID[*s.ID] = s.Metadata.Title
	}

	result := make([]LinkSummary, 0, len(links))
	for _, link := range links {
		byComponentID := byComponentByInherited[link.InheritedUUID]
		full := fullSetByProvided[link.ProvidedUUID]
		satisfaction, outstanding := DeriveSatisfaction(full, satisfiedByComponent[byComponentID])

		result = append(result, LinkSummary{
			LinkID:                *link.ID,
			DownstreamSSPID:       link.DownstreamSSPID,
			UpstreamSSPID:         link.UpstreamSSPID,
			OfferingID:            link.OfferingID,
			UpstreamSSPTitle:      upstreamTitleByID[link.UpstreamSSPID],
			OfferingTitle:         offeringTitleByID[link.OfferingID],
			OfferingVersion:       link.OfferingVersion,
			ControlID:             link.ControlID,
			StatementID:           link.StatementID,
			Status:                link.Status,
			Satisfaction:          satisfaction,
			OutstandingCount:      len(outstanding),
			TotalResponsibilities: len(full),
		})
	}
	return result, nil
}

// ControlKey identifies a (downstream SSP, control-id) pair. ControlID must be
// UPPER-folded and trimmed via NormalizeControlID before use as a key — leverage links
// are matched by control-id alone (no catalog id), the established precedent shared with
// implStatusBySSP and implemented requirements.
type ControlKey struct {
	SSPID     uuid.UUID
	ControlID string
}

// NormalizeControlID folds a control-id to the canonical key form (trimmed, upper).
func NormalizeControlID(controlID string) string {
	return strings.ToUpper(strings.TrimSpace(controlID))
}

// Origin is one upstream capability an inherited control draws from, deduped by
// (UpstreamSSPID, OfferingID) within a ControlAggregate.
type Origin struct {
	UpstreamSSPID    uuid.UUID
	UpstreamSSPTitle string
	OfferingID       uuid.UUID
	OfferingTitle    string
	OfferingVersion  int
}

// ControlAggregate is the per-control rollup of every leverage link sharing a
// ControlKey — the unit the compliance and lineage surfaces read.
type ControlAggregate struct {
	Links int
	// Credit is the inherited-credit rule at the leverage layer: ≥1 link AND every link
	// Status == active AND every link (live-derived) Satisfaction == full AND
	// TotalResponsibilities > 0. The last clause denies credit to a link whose upstream
	// responsibilities resolve to empty — a dangling link (upstream Provided/responsibility
	// rows deleted, so BulkResolve returns []) or a genuinely zero-responsibility offering
	// — which would otherwise silently inflate compliance before drift detection runs.
	// The evidence-wins and in-scope conditions are applied by the consumer, not here.
	Credit bool
	// Status is the worst link status: drifted > revoked > superseded > active.
	Status relational.SSPLeverageStatus
	// Satisfaction is full iff every link is full, else partial.
	Satisfaction relational.SSPLeverageSatisfaction
	// OutstandingCount and TotalResponsibilities are summed across links.
	OutstandingCount      int
	TotalResponsibilities int
	// InheritedFrom is the deduped set of upstream origins, in first-seen order.
	InheritedFrom []Origin
}

// statusRank orders leverage statuses so the worst (highest rank) wins the display
// status: drifted > revoked > superseded > active.
func statusRank(s relational.SSPLeverageStatus) int {
	switch s {
	case relational.SSPLeverageStatusDrifted:
		return 3
	case relational.SSPLeverageStatusRevoked:
		return 2
	case relational.SSPLeverageStatusSuperseded:
		return 1
	default: // active
		return 0
	}
}

// AggregateByControl folds link summaries into per-control aggregates. Pure and
// unit-testable: statement-scoped and control-scoped links for the same control-id
// collapse into one ControlKey, statuses take the worst, satisfaction is full only if
// all links are full, counts sum, origins dedupe by (upstream SSP, offering), and
// Credit holds only when every link is active and full.
func AggregateByControl(summaries []LinkSummary) map[ControlKey]ControlAggregate {
	type acc struct {
		agg       ControlAggregate
		allActive bool
		allFull   bool
		seenOrig  map[[2]uuid.UUID]bool
	}
	byKey := make(map[ControlKey]*acc)

	for _, s := range summaries {
		key := ControlKey{SSPID: s.DownstreamSSPID, ControlID: NormalizeControlID(s.ControlID)}
		a := byKey[key]
		if a == nil {
			a = &acc{
				agg:       ControlAggregate{Status: relational.SSPLeverageStatusActive},
				allActive: true,
				allFull:   true,
				seenOrig:  make(map[[2]uuid.UUID]bool),
			}
			byKey[key] = a
		}

		a.agg.Links++
		a.agg.OutstandingCount += s.OutstandingCount
		a.agg.TotalResponsibilities += s.TotalResponsibilities

		if statusRank(s.Status) > statusRank(a.agg.Status) {
			a.agg.Status = s.Status
		}
		if s.Status != relational.SSPLeverageStatusActive {
			a.allActive = false
		}
		if s.Satisfaction != relational.SSPLeverageSatisfactionFull {
			a.allFull = false
		}

		origKey := [2]uuid.UUID{s.UpstreamSSPID, s.OfferingID}
		if !a.seenOrig[origKey] {
			a.seenOrig[origKey] = true
			a.agg.InheritedFrom = append(a.agg.InheritedFrom, Origin{
				UpstreamSSPID:    s.UpstreamSSPID,
				UpstreamSSPTitle: s.UpstreamSSPTitle,
				OfferingID:       s.OfferingID,
				OfferingTitle:    s.OfferingTitle,
				OfferingVersion:  s.OfferingVersion,
			})
		}
	}

	result := make(map[ControlKey]ControlAggregate, len(byKey))
	for key, a := range byKey {
		if a.allFull {
			a.agg.Satisfaction = relational.SSPLeverageSatisfactionFull
		} else {
			a.agg.Satisfaction = relational.SSPLeverageSatisfactionPartial
		}
		a.agg.Credit = a.agg.Links > 0 && a.allActive && a.allFull && a.agg.TotalResponsibilities > 0
		result[key] = a.agg
	}
	return result
}
