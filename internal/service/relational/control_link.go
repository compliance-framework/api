package relational

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ControlLink is a typed directed edge between two controls. Direction is always
// concrete -> abstract: the source "satisfies/refines" the target. It mirrors the
// (catalog_id uuid, control_id text) key shape of risk_control_links deliberately;
// do NOT copy the text catalog-id inconsistency that filter_controls carries.
type ControlLink struct {
	SourceCatalogID  uuid.UUID  `json:"sourceCatalogId"  gorm:"type:uuid;primaryKey"`
	SourceControlID  string     `json:"sourceControlId"  gorm:"type:text;primaryKey"`
	TargetCatalogID  uuid.UUID  `json:"targetCatalogId"  gorm:"type:uuid;primaryKey;index:idx_control_links_target"`
	TargetControlID  string     `json:"targetControlId"  gorm:"type:text;primaryKey;index:idx_control_links_target"`
	RelationshipType string     `json:"relationshipType" gorm:"type:text;primaryKey"`
	CreatedAt        time.Time  `json:"createdAt"`
	CreatedByID      *uuid.UUID `json:"createdById" gorm:"type:uuid"`
}

func (ControlLink) TableName() string {
	return "control_links"
}

// Relationship vocabulary. Only implements/documents are accepted in this PoC;
// related/supersedes/equivalent are reserved and rejected on create.
const (
	RelationshipImplements = "implements"
	RelationshipDocuments  = "documents"
	RelationshipRelated    = "related"
	RelationshipSupersedes = "supersedes"
	RelationshipEquivalent = "equivalent"
)

// Source returns the (catalog, control) reference for this link's source end.
func (l ControlLink) Source() ControlRef {
	return ControlRef{CatalogID: l.SourceCatalogID, ControlID: l.SourceControlID}
}

// Target returns the (catalog, control) reference for this link's target end.
func (l ControlLink) Target() ControlRef {
	return ControlRef{CatalogID: l.TargetCatalogID, ControlID: l.TargetControlID}
}

// ControlRef identifies a control node by (catalog, control). It is comparable so
// it can key maps/sets directly in the in-memory lineage graph.
type ControlRef struct {
	CatalogID uuid.UUID `json:"catalogId"`
	ControlID string    `json:"controlId"`
}

// ValidateRelationship enforces the closed-set vocabulary matrix against the
// catalog types of the two endpoints. Direction is concrete -> abstract.
//
// An "operational-control" is any control in an operational-type catalog
// (standard, internal or other) acting as an implementer — see
// IsOperationalCatalogType. All three collapse to the same "standard" slot here.
//
//	implements: policy      -> operational  (policy-control implements standard-control)
//	            operational -> policy        (operational-control implements policy-control)
//	            operational -> operational   (operational-control -> standard-control, escape hatch)
//	documents:  procedure   -> policy        (procedure-control documents policy-control)
//
// Any other combination — including the reserved relationship types — is rejected.
// A non-nil error here maps to HTTP 422.
func ValidateRelationship(relationshipType, sourceType, targetType string) error {
	switch relationshipType {
	case RelationshipImplements:
		switch {
		case sourceType == CatalogTypePolicy && IsOperationalCatalogType(targetType):
			return nil
		case IsOperationalCatalogType(sourceType) && targetType == CatalogTypePolicy:
			return nil
		case IsOperationalCatalogType(sourceType) && IsOperationalCatalogType(targetType):
			return nil
		}
		return fmt.Errorf("relationship %q not permitted from %s-control to %s-control", relationshipType, sourceType, targetType)
	case RelationshipDocuments:
		if sourceType == CatalogTypeProcedure && targetType == CatalogTypePolicy {
			return nil
		}
		return fmt.Errorf("relationship %q only permitted from procedure-control to policy-control (got %s -> %s)", relationshipType, sourceType, targetType)
	case RelationshipRelated, RelationshipSupersedes, RelationshipEquivalent:
		return fmt.Errorf("relationship %q is reserved and not supported in this PoC", relationshipType)
	default:
		return fmt.Errorf("unknown relationship type %q", relationshipType)
	}
}

// ControlLinkGraph is an in-memory view of the control_links table. The table is
// small, so lineage loads every edge once and walks it here rather than issuing
// recursive SQL. It is cycle-tolerant: every walk carries a visited set.
type ControlLinkGraph struct {
	// implementedBy maps a target control to the sources that `implements` it.
	// This is the reverse of the stored edge and is the tree/rollup direction:
	// a standard control's children are the controls that implement it.
	implementedBy map[ControlRef][]ControlRef
	// documentedBy maps a policy control to the procedure controls that `documents` it.
	// Structural only — excluded from evidence/risk math per the vocabulary matrix.
	documentedBy map[ControlRef][]ControlRef
	// forward maps a source to its targets across ALL edge types, used only for
	// acyclicity checks on create.
	forward map[ControlRef][]ControlRef
	// outgoingImplements records, per source, the implements targets — used to
	// decide whether a policy control is anchored to a standard control.
	outgoingImplements map[ControlRef][]ControlRef
}

// NewControlLinkGraph indexes a flat edge list into the adjacency maps lineage needs.
func NewControlLinkGraph(links []ControlLink) *ControlLinkGraph {
	g := &ControlLinkGraph{
		implementedBy:      map[ControlRef][]ControlRef{},
		documentedBy:       map[ControlRef][]ControlRef{},
		forward:            map[ControlRef][]ControlRef{},
		outgoingImplements: map[ControlRef][]ControlRef{},
	}
	for _, l := range links {
		s := l.Source()
		t := l.Target()
		g.forward[s] = append(g.forward[s], t)
		switch l.RelationshipType {
		case RelationshipImplements:
			g.implementedBy[t] = append(g.implementedBy[t], s)
			g.outgoingImplements[s] = append(g.outgoingImplements[s], t)
		case RelationshipDocuments:
			g.documentedBy[t] = append(g.documentedBy[t], s)
		}
	}
	return g
}

// Children returns the direct lineage children of node: everything that
// `implements` it plus everything that `documents` it, in a stable order
// (implements first, then documents), de-duplicated.
func (g *ControlLinkGraph) Children(node ControlRef) []ControlRef {
	seen := map[ControlRef]struct{}{}
	children := make([]ControlRef, 0, len(g.implementedBy[node])+len(g.documentedBy[node]))
	for _, src := range g.implementedBy[node] {
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		children = append(children, src)
	}
	for _, src := range g.documentedBy[node] {
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		children = append(children, src)
	}
	return children
}

// ImplementsChildren returns the controls that directly `implements` node.
func (g *ControlLinkGraph) ImplementsChildren(node ControlRef) []ControlRef {
	return append([]ControlRef(nil), g.implementedBy[node]...)
}

// DocumentsChildren returns the controls that directly `documents` node.
func (g *ControlLinkGraph) DocumentsChildren(node ControlRef) []ControlRef {
	return append([]ControlRef(nil), g.documentedBy[node]...)
}

// EvidenceClosure returns the set of controls whose evidence/risk rolls up into
// node: node itself plus every control that implements it transitively. Only
// `implements` edges are followed — `documents` is presence-only and excluded
// from the math. The walk tolerates cycles via the visited set.
func (g *ControlLinkGraph) EvidenceClosure(node ControlRef) map[ControlRef]struct{} {
	visited := map[ControlRef]struct{}{}
	var walk func(n ControlRef)
	walk = func(n ControlRef) {
		if _, ok := visited[n]; ok {
			return
		}
		visited[n] = struct{}{}
		for _, child := range g.implementedBy[n] {
			walk(child)
		}
	}
	walk(node)
	return visited
}

// StructuralClosure is EvidenceClosure widened to also follow `documents` edges.
// Used for structural counts (subtree membership, linkage) that include procedures.
func (g *ControlLinkGraph) StructuralClosure(node ControlRef) map[ControlRef]struct{} {
	visited := map[ControlRef]struct{}{}
	var walk func(n ControlRef)
	walk = func(n ControlRef) {
		if _, ok := visited[n]; ok {
			return
		}
		visited[n] = struct{}{}
		for _, child := range g.implementedBy[n] {
			walk(child)
		}
		for _, child := range g.documentedBy[n] {
			walk(child)
		}
	}
	walk(node)
	return visited
}

// HasOutgoingImplements reports whether node has at least one `implements` edge
// pointing at a control in one of the anchorCatalogs (typically standard catalogs).
// A policy control with no such edge is "unanchored".
func (g *ControlLinkGraph) HasOutgoingImplements(node ControlRef, anchorCatalogs map[uuid.UUID]struct{}) bool {
	for _, tgt := range g.outgoingImplements[node] {
		if anchorCatalogs == nil {
			return true
		}
		if _, ok := anchorCatalogs[tgt.CatalogID]; ok {
			return true
		}
	}
	return false
}

// WouldCreateCycle reports whether adding source -> target would introduce a
// cycle in the combined (all-relationship) directed graph, i.e. whether target
// can already reach source by following stored edges forward, or the edge is a
// self-loop. Acyclicity is checked across all edge types so no relationship can
// smuggle in a loop.
func (g *ControlLinkGraph) WouldCreateCycle(source, target ControlRef) bool {
	if source == target {
		return true
	}
	visited := map[ControlRef]struct{}{}
	var reaches func(n ControlRef) bool
	reaches = func(n ControlRef) bool {
		if n == source {
			return true
		}
		if _, ok := visited[n]; ok {
			return false
		}
		visited[n] = struct{}{}
		for _, next := range g.forward[n] {
			if reaches(next) {
				return true
			}
		}
		return false
	}
	return reaches(target)
}
