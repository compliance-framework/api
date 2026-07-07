package relational

import (
	"testing"

	"github.com/google/uuid"
)

var (
	standardCat  = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	policyCat    = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	procedureCat = uuid.MustParse("33333333-3333-3333-3333-333333333333")
)

func ref(cat uuid.UUID, id string) ControlRef { return ControlRef{CatalogID: cat, ControlID: id} }

func implementsLink(s, t ControlRef) ControlLink {
	return ControlLink{
		SourceCatalogID: s.CatalogID, SourceControlID: s.ControlID,
		TargetCatalogID: t.CatalogID, TargetControlID: t.ControlID,
		RelationshipType: RelationshipImplements,
	}
}

func documentsLink(s, t ControlRef) ControlLink {
	return ControlLink{
		SourceCatalogID: s.CatalogID, SourceControlID: s.ControlID,
		TargetCatalogID: t.CatalogID, TargetControlID: t.ControlID,
		RelationshipType: RelationshipDocuments,
	}
}

func TestValidateRelationshipMatrix(t *testing.T) {
	cases := []struct {
		name       string
		rel        string
		sourceType string
		targetType string
		wantErr    bool
	}{
		// implements — valid rows
		{"policy implements standard", RelationshipImplements, CatalogTypePolicy, CatalogTypeStandard, false},
		{"operational implements policy", RelationshipImplements, CatalogTypeStandard, CatalogTypePolicy, false},
		{"operational implements standard (escape hatch)", RelationshipImplements, CatalogTypeStandard, CatalogTypeStandard, false},
		// implements — internal/other collapse to the standard/operational slot
		{"policy implements internal", RelationshipImplements, CatalogTypePolicy, CatalogTypeInternal, false},
		{"policy implements other", RelationshipImplements, CatalogTypePolicy, CatalogTypeOther, false},
		{"internal implements policy", RelationshipImplements, CatalogTypeInternal, CatalogTypePolicy, false},
		{"other implements policy", RelationshipImplements, CatalogTypeOther, CatalogTypePolicy, false},
		{"internal implements other (escape hatch)", RelationshipImplements, CatalogTypeInternal, CatalogTypeOther, false},
		{"internal implements standard (escape hatch)", RelationshipImplements, CatalogTypeInternal, CatalogTypeStandard, false},
		// implements — invalid rows
		{"procedure implements policy", RelationshipImplements, CatalogTypeProcedure, CatalogTypePolicy, true},
		{"policy implements policy", RelationshipImplements, CatalogTypePolicy, CatalogTypePolicy, true},
		{"policy implements procedure", RelationshipImplements, CatalogTypePolicy, CatalogTypeProcedure, true},
		{"procedure implements standard", RelationshipImplements, CatalogTypeProcedure, CatalogTypeStandard, true},
		// documents — valid row
		{"procedure documents policy", RelationshipDocuments, CatalogTypeProcedure, CatalogTypePolicy, false},
		// documents — invalid rows
		{"policy documents standard", RelationshipDocuments, CatalogTypePolicy, CatalogTypeStandard, true},
		{"standard documents policy", RelationshipDocuments, CatalogTypeStandard, CatalogTypePolicy, true},
		{"procedure documents standard", RelationshipDocuments, CatalogTypeProcedure, CatalogTypeStandard, true},
		{"procedure documents internal", RelationshipDocuments, CatalogTypeProcedure, CatalogTypeInternal, true},
		{"internal documents policy", RelationshipDocuments, CatalogTypeInternal, CatalogTypePolicy, true},
		// reserved vocabulary — always rejected
		{"related reserved", RelationshipRelated, CatalogTypePolicy, CatalogTypeStandard, true},
		{"supersedes reserved", RelationshipSupersedes, CatalogTypeStandard, CatalogTypeStandard, true},
		{"equivalent reserved", RelationshipEquivalent, CatalogTypePolicy, CatalogTypeStandard, true},
		// unknown relationship
		{"unknown relationship", "invents", CatalogTypePolicy, CatalogTypeStandard, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRelationship(tc.rel, tc.sourceType, tc.targetType)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestWouldCreateCycle(t *testing.T) {
	a := ref(standardCat, "a")
	b := ref(policyCat, "b")
	c := ref(standardCat, "c")

	// Existing DAG: a -> b -> c (forward edges).
	g := NewControlLinkGraph([]ControlLink{
		{SourceCatalogID: a.CatalogID, SourceControlID: a.ControlID, TargetCatalogID: b.CatalogID, TargetControlID: b.ControlID, RelationshipType: RelationshipImplements},
		{SourceCatalogID: b.CatalogID, SourceControlID: b.ControlID, TargetCatalogID: c.CatalogID, TargetControlID: c.ControlID, RelationshipType: RelationshipImplements},
	})

	if !g.WouldCreateCycle(c, a) {
		t.Error("c -> a should close the a->b->c chain into a cycle")
	}
	if g.WouldCreateCycle(a, c) {
		t.Error("a -> c is a DAG shortcut, not a cycle")
	}
	if !g.WouldCreateCycle(a, a) {
		t.Error("self-loop a -> a must be rejected")
	}
	// A brand new edge touching disconnected nodes is fine.
	if g.WouldCreateCycle(ref(policyCat, "x"), ref(standardCat, "y")) {
		t.Error("disconnected edge should not be a cycle")
	}
}

func TestEvidenceClosureDiamondAndEscapeHatch(t *testing.T) {
	s := ref(standardCat, "s")
	p1 := ref(policyCat, "p1")
	p2 := ref(policyCat, "p2")
	o := ref(standardCat, "o")   // operational control implementing both policies
	o2 := ref(standardCat, "o2") // operational control implementing the standard directly

	g := NewControlLinkGraph([]ControlLink{
		implementsLink(p1, s), // policy implements standard
		implementsLink(p2, s), // policy implements standard
		implementsLink(o, p1), // operational implements policy
		implementsLink(o, p2), // operational implements policy (diamond join)
		implementsLink(o2, s), // escape hatch: operational implements standard directly
	})

	closure := g.EvidenceClosure(s)
	want := []ControlRef{s, p1, p2, o, o2}
	if len(closure) != len(want) {
		t.Fatalf("closure size = %d, want %d (%v)", len(closure), len(want), closure)
	}
	for _, w := range want {
		if _, ok := closure[w]; !ok {
			t.Errorf("closure missing %v", w)
		}
	}
}

func TestEvidenceClosureOrphanPolicy(t *testing.T) {
	s := ref(standardCat, "s")
	anchored := ref(policyCat, "anchored")
	orphan := ref(policyCat, "orphan") // no implements edge to any standard

	g := NewControlLinkGraph([]ControlLink{
		implementsLink(anchored, s),
	})

	// Orphan's closure is just itself.
	oc := g.EvidenceClosure(orphan)
	if len(oc) != 1 {
		t.Fatalf("orphan closure size = %d, want 1", len(oc))
	}
	if _, ok := oc[orphan]; !ok {
		t.Errorf("orphan closure must contain itself")
	}

	// Orphan does not leak into the standard's closure.
	sc := g.EvidenceClosure(s)
	if _, ok := sc[orphan]; ok {
		t.Errorf("standard closure should not include the orphan policy")
	}

	// Unanchored detection: orphan has no implements edge to a standard catalog.
	standards := map[uuid.UUID]struct{}{standardCat: {}}
	if g.HasOutgoingImplements(orphan, standards) {
		t.Errorf("orphan policy must be reported as unanchored")
	}
	if !g.HasOutgoingImplements(anchored, standards) {
		t.Errorf("anchored policy must be reported as anchored")
	}
}

func TestEvidenceClosureToleratesCycles(t *testing.T) {
	s := ref(standardCat, "s")
	p := ref(policyCat, "p")

	// Pathological cycle: p implements s AND s "implements" p. The walk must terminate.
	g := NewControlLinkGraph([]ControlLink{
		implementsLink(p, s),
		implementsLink(s, p),
	})

	closure := g.EvidenceClosure(s)
	if len(closure) != 2 {
		t.Fatalf("cyclic closure size = %d, want 2", len(closure))
	}
	if _, ok := closure[s]; !ok {
		t.Errorf("closure missing s")
	}
	if _, ok := closure[p]; !ok {
		t.Errorf("closure missing p")
	}
}

func TestStructuralClosureIncludesDocuments(t *testing.T) {
	s := ref(standardCat, "s")
	p := ref(policyCat, "p")
	proc := ref(procedureCat, "proc")

	g := NewControlLinkGraph([]ControlLink{
		implementsLink(p, s),
		documentsLink(proc, p),
	})

	// EvidenceClosure follows implements only: proc is excluded.
	ec := g.EvidenceClosure(s)
	if _, ok := ec[proc]; ok {
		t.Errorf("evidence closure must exclude documents-linked procedures")
	}

	// StructuralClosure follows documents too: proc is included.
	sc := g.StructuralClosure(s)
	if _, ok := sc[proc]; !ok {
		t.Errorf("structural closure must include documents-linked procedures")
	}
}
