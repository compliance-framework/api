package leverage

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/service/relational"
)

// BulkResolveUpstreamResponsibilities is the batched resolver: two queries total
// regardless of how many providedUUIDs are requested, rather than two queries per
// item (the catalog list and the leveraged-controls projection each resolve
// responsibilities for many items/links in one request). The two-step lookup is
// unavoidable because ControlImplementationResponsibility and
// ProvidedControlImplementation are siblings under Export with no direct FK between
// them — only the shared OSCAL-level provided-uuid value — so responsibilities are
// scoped by (export_id, provided_uuid) pairs, not provided_uuid alone, since
// provided-uuid values are only unique within a single upstream's Export.
// providedUUIDs with no matching ProvidedControlImplementation row (e.g. the
// upstream row was since deleted) map to an empty slice, not an error or a missing
// key.
func BulkResolveUpstreamResponsibilities(db *gorm.DB, providedUUIDs []uuid.UUID) (map[uuid.UUID][]Responsibility, error) {
	result := make(map[uuid.UUID][]Responsibility, len(providedUUIDs))
	for _, id := range providedUUIDs {
		result[id] = []Responsibility{}
	}
	if len(providedUUIDs) == 0 {
		return result, nil
	}

	var provided []relational.ProvidedControlImplementation
	if err := db.Where("id IN ?", providedUUIDs).Find(&provided).Error; err != nil {
		return nil, err
	}
	if len(provided) == 0 {
		return result, nil
	}
	exportIDByProvided := make(map[uuid.UUID]uuid.UUID, len(provided))
	for _, p := range provided {
		exportIDByProvided[*p.ID] = p.ExportId
	}

	var responsibilities []relational.ControlImplementationResponsibility
	if err := db.Where("provided_uuid IN ?", providedUUIDs).Find(&responsibilities).Error; err != nil {
		return nil, err
	}
	for _, r := range responsibilities {
		// Scope by export_id too: provided-uuid values are only unique within a single
		// upstream's Export, so a bulk provided_uuid-only match could in principle pick
		// up a same-valued responsibility from an unrelated Export.
		if exportIDByProvided[r.ProvidedUuid] != r.ExportId {
			continue
		}
		result[r.ProvidedUuid] = append(result[r.ProvidedUuid], Responsibility{
			ResponsibilityUUID: *r.ID,
			Description:        r.Description,
		})
	}
	return result, nil
}

// DeriveSatisfaction is the single definition of "full iff every upstream
// responsibility has a matching downstream satisfied" (vacuously full when full is
// empty), shared by Subscribe (computing the satisfaction to store on a new leverage
// link) and every read path (recomputing it live rather than trusting the stored
// value). Returns the subset of full not covered by satisfiedUUIDs as outstanding.
func DeriveSatisfaction(full []Responsibility, satisfiedUUIDs map[uuid.UUID]bool) (relational.SSPLeverageSatisfaction, []Responsibility) {
	outstanding := make([]Responsibility, 0)
	for _, r := range full {
		if !satisfiedUUIDs[r.ResponsibilityUUID] {
			outstanding = append(outstanding, r)
		}
	}
	if len(outstanding) == 0 {
		return relational.SSPLeverageSatisfactionFull, outstanding
	}
	return relational.SSPLeverageSatisfactionPartial, outstanding
}

// DriftDedupeKey returns the dedupe key for the drift risk associated with a single
// SSPLeverageLink. One risk per leverage link: the link itself is the natural,
// deterministic scope (no risk template is involved, unlike evidence-driven risks),
// and the key is directly parseable back to the link that produced it without
// needing a separate link table. The "leverage-drift:%s" format keeps the drift
// writer (applyDriftToLink) and the projection reader in lockstep.
func DriftDedupeKey(linkID uuid.UUID) string {
	return fmt.Sprintf("leverage-drift:%s", linkID)
}
