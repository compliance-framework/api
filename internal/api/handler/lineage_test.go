package handler

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
)

func TestBucketRisks(t *testing.T) {
	r1 := uuid.New()
	r2 := uuid.New()
	r3 := uuid.New()
	r4 := uuid.New()
	r5 := uuid.New()
	r6 := uuid.New()
	r7 := uuid.New()

	entries := []riskEntry{
		{riskID: r1, status: string(riskrel.RiskStatusOpen), score: 20},
		{riskID: r2, status: string(riskrel.RiskStatusInvestigating), score: 5},
		{riskID: r3, status: string(riskrel.RiskStatusMitigatingPlanned), score: 12},
		{riskID: r4, status: string(riskrel.RiskStatusRiskAccepted), score: 9},
		{riskID: r5, status: string(riskrel.RiskStatusMitigatingImplemented), score: 3},
		{riskID: r6, status: string(riskrel.RiskStatusRemediated), score: 25}, // excluded
		{riskID: r7, status: string(riskrel.RiskStatusClosed), score: 25},     // excluded
		// Duplicate of r1 (same risk linked to two controls in the closure) must not double count.
		{riskID: r1, status: string(riskrel.RiskStatusOpen), score: 20},
	}

	got := bucketRisks(entries)

	if got.OpenScoreSum != 20+5+12 {
		t.Errorf("OpenScoreSum = %d, want %d", got.OpenScoreSum, 20+5+12)
	}
	if got.MutedScoreSum != 9+3 {
		t.Errorf("MutedScoreSum = %d, want %d", got.MutedScoreSum, 9+3)
	}
	if got.Counts.Open != 1 || got.Counts.Investigating != 1 || got.Counts.MitigatingPlanned != 1 {
		t.Errorf("open-bucket counts wrong: %+v", got.Counts)
	}
	if got.Counts.RiskAccepted != 1 || got.Counts.MitigatingImplemented != 1 {
		t.Errorf("muted-bucket counts wrong: %+v", got.Counts)
	}
}

func TestBucketRisksEmpty(t *testing.T) {
	got := bucketRisks(nil)
	if got.OpenScoreSum != 0 || got.MutedScoreSum != 0 {
		t.Errorf("empty risk bucket should be zero, got %+v", got)
	}
}

func TestComputeLineageStatus(t *testing.T) {
	cases := []struct {
		name string
		rows []relational.StatusCount
		want string
	}{
		{"no evidence is unknown", nil, "unknown"},
		{"any not-satisfied wins", []relational.StatusCount{
			{Status: "satisfied", Count: 10},
			{Status: "not-satisfied", Count: 1},
		}, relational.EvidenceStatusNotSatisfied},
		{"satisfied without failures", []relational.StatusCount{
			{Status: "satisfied", Count: 3},
		}, relational.EvidenceStatusSatisfied},
		{"zero counts ignored", []relational.StatusCount{
			{Status: "not-satisfied", Count: 0},
			{Status: "satisfied", Count: 0},
		}, "unknown"},
		{"case-insensitive states", []relational.StatusCount{
			{Status: "SATISFIED", Count: 2},
		}, relational.EvidenceStatusSatisfied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := computeLineageStatus(tc.rows); got != tc.want {
				t.Errorf("computeLineageStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestControlStatement(t *testing.T) {
	// A statement part with prose split across nested item parts should join into
	// one block, depth-first, skipping empty prose.
	ctrl := relational.Control{
		ID:    "ac-1",
		Title: "Access Control Policy and Procedures",
		Parts: []relational.Part{
			{Name: "statement", Prose: "The organization:", Parts: []relational.Part{
				{Name: "item", Prose: "a. Develops an access control policy;"},
				{Name: "item", Prose: "b. Reviews it annually;", Parts: []relational.Part{
					{Name: "item", Prose: "1. and after significant changes."},
				}},
			}},
			{Name: "guidance", Prose: "This guidance should NOT appear."},
		},
	}
	got := controlStatement(ctrl)
	want := "The organization:\na. Develops an access control policy;\nb. Reviews it annually;\n1. and after significant changes."
	if got != want {
		t.Errorf("controlStatement mismatch:\n got %q\nwant %q", got, want)
	}

	// No statement part -> empty string (field is omitempty on the wire).
	if s := controlStatement(relational.Control{ID: "ac-2", Parts: []relational.Part{{Name: "guidance", Prose: "x"}}}); s != "" {
		t.Errorf("expected empty statement, got %q", s)
	}
	if s := controlStatement(relational.Control{ID: "ac-3"}); s != "" {
		t.Errorf("expected empty statement for no parts, got %q", s)
	}
}

func TestDerivePosture(t *testing.T) {
	const na = string(relational.ImplementationStatusNotApplicable)
	const planned = string(relational.ImplementationStatusPlanned)
	sat := relational.EvidenceStatusSatisfied
	notSat := relational.EvidenceStatusNotSatisfied

	cases := []struct {
		name      string
		inProfile bool
		evidence  string
		impl      string
		inherited bool
		want      string
	}{
		// Scope wins over everything: an out-of-profile control is never a problem.
		{"out of profile beats all", false, notSat, na, false, PostureOutOfScope},
		// Out-of-scope beats inherited credit too: an un-profiled control is excluded
		// regardless of leverage.
		{"out of profile beats inherited", false, "unknown", "", true, PostureOutOfScope},
		// Decisive evidence beats declared status (the user's "evidence wins" rule):
		// even a not-applicable control with stale failing evidence stays red.
		{"not-satisfied evidence wins over not-applicable", true, notSat, na, false, PostureNotSatisfied},
		{"satisfied evidence wins over declared implemented", true, sat, "implemented", false, PostureSatisfied},
		// Evidence wins over inherited credit in both directions.
		{"not-satisfied evidence wins over inherited", true, notSat, "", true, PostureNotSatisfied},
		{"satisfied evidence wins over inherited", true, sat, "", true, PostureSatisfied},
		// No decisive evidence + inherited credit -> inherited, above not-applicable/planned.
		{"no evidence + inherited credit is inherited", true, "unknown", "", true, PostureInherited},
		{"inherited beats not-applicable", true, "unknown", na, true, PostureInherited},
		{"inherited beats planned", true, "unknown", planned, true, PostureInherited},
		// No decisive evidence, no credit -> declared status decides problem vs expected.
		{"credit=false + not-applicable stays not-applicable", true, "unknown", na, false, PostureNotApplicable},
		{"no evidence + not-applicable is muted", true, "unknown", na, false, PostureNotApplicable},
		{"no evidence + planned is muted", true, "unknown", planned, false, PosturePlanned},
		{"no evidence + implemented is attention", true, "unknown", "implemented", false, PostureAttention},
		{"no evidence + partial is attention", true, "unknown", "partial", false, PostureAttention},
		{"no evidence + alternative is attention", true, "unknown", "alternative", false, PostureAttention},
		{"no evidence + undeclared is attention", true, "unknown", "", false, PostureAttention},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := derivePosture(tc.inProfile, tc.evidence, tc.impl, tc.inherited); got != tc.want {
				t.Errorf("derivePosture(%v, %q, %q, %v) = %q, want %q", tc.inProfile, tc.evidence, tc.impl, tc.inherited, got, tc.want)
			}
		})
	}
}

func TestCollapseUniformStatus(t *testing.T) {
	cases := []struct {
		name   string
		states []string
		want   string
	}{
		{"empty is undeclared", nil, ""},
		{"single state", []string{"not-applicable"}, "not-applicable"},
		{"all agree", []string{"not-applicable", "not-applicable"}, "not-applicable"},
		{"disagreement is undeclared", []string{"not-applicable", "implemented"}, ""},
		{"leading blank is undeclared", []string{"", "not-applicable"}, ""},
		{"trailing blank is undeclared", []string{"not-applicable", ""}, ""},
		{"all blank is undeclared", []string{"", ""}, ""},
		{"case and space folded", []string{"NOT-APPLICABLE", " not-applicable "}, "not-applicable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := collapseUniformStatus(tc.states); got != tc.want {
				t.Errorf("collapseUniformStatus(%v) = %q, want %q", tc.states, got, tc.want)
			}
		})
	}
}

func TestParseNodeKey(t *testing.T) {
	catID := uuid.New()

	kind, gotCat, sub, err := parseNodeKey("catalog:" + catID.String())
	if err != nil || kind != "catalog" || gotCat != catID || sub != "" {
		t.Errorf("catalog key parse failed: kind=%q cat=%v sub=%q err=%v", kind, gotCat, sub, err)
	}

	kind, gotCat, sub, err = parseNodeKey("control:" + catID.String() + "/ac-1")
	if err != nil || kind != "control" || gotCat != catID || sub != "ac-1" {
		t.Errorf("control key parse failed: kind=%q cat=%v sub=%q err=%v", kind, gotCat, sub, err)
	}

	kind, gotCat, sub, err = parseNodeKey("group:" + catID.String() + "/ac")
	if err != nil || kind != "group" || gotCat != catID || sub != "ac" {
		t.Errorf("group key parse failed: kind=%q cat=%v sub=%q err=%v", kind, gotCat, sub, err)
	}

	// linkcat: catalogID is the child (linked) catalog; subID carries
	// "<rel>/<parentCatalogId>/<parentControlId>". The parent control id may itself
	// contain '/', so it must survive as the untouched remainder.
	childCat := uuid.New()
	parentCat := uuid.New()
	linkKey := "linkcat:" + childCat.String() + "/implements/" + parentCat.String() + "/ac-1/sub"
	kind, gotCat, sub, err = parseNodeKey(linkKey)
	if err != nil || kind != "linkcat" || gotCat != childCat ||
		sub != "implements/"+parentCat.String()+"/ac-1/sub" {
		t.Errorf("linkcat key parse failed: kind=%q cat=%v sub=%q err=%v", kind, gotCat, sub, err)
	}

	if _, _, _, err := parseNodeKey("bogus"); err == nil {
		t.Error("malformed key should error")
	}
	if _, _, _, err := parseNodeKey("control:not-a-uuid/ac-1"); err == nil {
		t.Error("bad catalog uuid should error")
	}

	// Echo delivers path params still percent-encoded (the UI sends
	// encodeURIComponent(key)); parseNodeKey must decode %3A/%2F before splitting.
	kind, gotCat, sub, err = parseNodeKey("control%3A" + catID.String() + "%2Fac-1")
	if err != nil || kind != "control" || gotCat != catID || sub != "ac-1" {
		t.Errorf("URL-encoded control key parse failed: kind=%q cat=%v sub=%q err=%v", kind, gotCat, sub, err)
	}
}
