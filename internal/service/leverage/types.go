// Package leverage is the neutral home for the cross-SSP leveraged-authorization
// projection and aggregation. It was extracted from internal/api/handler/oscal so
// that internal/api/handler (which oscal imports, not the other way round) can read
// the same leverage data without an import cycle — the compliance-progress endpoint
// (package oscal) and the lineage engine (package handler) both build on it.
//
// It may import relational, relational/risks and converters/labelfilter; it must NOT
// import anything under internal/api.
package leverage

import (
	"github.com/google/uuid"

	"github.com/compliance-framework/api/internal/service/relational"
)

// Responsibility is the minimal upstream-responsibility shape both the catalog
// exposure and the subscribe/projection paths need: enough to let a downstream
// subscriber pick specific responsibility UUIDs to satisfy, and to compute
// full/partial coverage. Its JSON tags are the wire contract (responsibilityUuid,
// description); oscal aliases upstreamResponsibility to it so those surfaces are
// unchanged.
type Responsibility struct {
	ResponsibilityUUID uuid.UUID `json:"responsibilityUuid"`
	Description        string    `json:"description"`
}

// Projection is one downstream leverage link with everything the read models need
// already resolved: the live-recomputed satisfaction (never the link's cached
// value), the outstanding responsibilities, the evidence-backed posture, the open
// drift risk, the offering title, and the by-component + inherited row the link
// hangs off.
//
// Both the /leveraged-controls endpoint and the shared-responsibility rollup read
// this, so satisfaction is derived in exactly one place and neither surface can
// drift from the other. oscal aliases leveragedControlProjection to it.
type Projection struct {
	Link          relational.SSPLeverageLink
	OfferingTitle string
	ByComponentID uuid.UUID
	// Inherited is the downstream's own InheritedControlImplementation row this link
	// created; nil only if it has since been deleted out from under the link.
	Inherited    *relational.InheritedControlImplementation
	Satisfaction relational.SSPLeverageSatisfaction
	Outstanding  []Responsibility
	// Responsibilities is the FULL upstream responsibility set under this link (uuid +
	// description), so downstream surfaces can label every responsibility — including
	// ones already satisfied — with the upstream's own text. Outstanding is the subset
	// of this with no matching downstream satisfied entry.
	Responsibilities []Responsibility
	Posture          map[uuid.UUID]string
	DriftRiskID      *uuid.UUID
}

// uniqueUUIDs extracts the deduplicated set of UUIDs from items, preserving
// first-seen order — used to build IN-clause batches from a list of rows that may
// repeat the same referenced id (e.g. several leverage links pointing at the same
// offering). A copy of the oscal helper of the same name; oscal keeps its own.
func uniqueUUIDs[T any](items []T, extract func(T) uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(items))
	result := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		id := extract(item)
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result
}
