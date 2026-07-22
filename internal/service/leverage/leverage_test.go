package leverage

import (
	"testing"

	"github.com/google/uuid"

	"github.com/compliance-framework/api/internal/service/relational"
)

func statement(s string) *string { return &s }

// summary is a small helper to build a LinkSummary for one control in one SSP.
func summary(sspID, upstream, offering uuid.UUID, controlID string, stmt *string, status relational.SSPLeverageStatus, sat relational.SSPLeverageSatisfaction, outstanding, total int) LinkSummary {
	return LinkSummary{
		LinkID:                uuid.New(),
		DownstreamSSPID:       sspID,
		UpstreamSSPID:         upstream,
		OfferingID:            offering,
		UpstreamSSPTitle:      "Upstream",
		OfferingTitle:         "Offering",
		OfferingVersion:       2,
		ControlID:             controlID,
		StatementID:           stmt,
		Status:                status,
		Satisfaction:          sat,
		OutstandingCount:      outstanding,
		TotalResponsibilities: total,
	}
}

func TestNormalizeControlID(t *testing.T) {
	cases := map[string]string{
		"ac-2":     "AC-2",
		" ac-2 ":   "AC-2",
		"AC-2":     "AC-2",
		"Ac-2_smt": "AC-2_SMT",
	}
	for in, want := range cases {
		if got := NormalizeControlID(in); got != want {
			t.Errorf("NormalizeControlID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDriftDedupeKey(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	want := "leverage-drift:11111111-1111-1111-1111-111111111111"
	if got := DriftDedupeKey(id); got != want {
		t.Errorf("DriftDedupeKey = %q, want %q", got, want)
	}
}

func TestDeriveSatisfactionVacuousFull(t *testing.T) {
	// An empty responsibility set is vacuously full: nothing outstanding.
	sat, outstanding := DeriveSatisfaction(nil, map[uuid.UUID]bool{})
	if sat != relational.SSPLeverageSatisfactionFull {
		t.Errorf("empty set: got %q, want full", sat)
	}
	if len(outstanding) != 0 {
		t.Errorf("empty set: expected no outstanding, got %d", len(outstanding))
	}

	r1, r2 := uuid.New(), uuid.New()
	full := []Responsibility{{ResponsibilityUUID: r1}, {ResponsibilityUUID: r2}}
	// All satisfied -> full.
	sat, outstanding = DeriveSatisfaction(full, map[uuid.UUID]bool{r1: true, r2: true})
	if sat != relational.SSPLeverageSatisfactionFull || len(outstanding) != 0 {
		t.Errorf("all satisfied: got %q / %d outstanding, want full / 0", sat, len(outstanding))
	}
	// One missing -> partial, that one outstanding.
	sat, outstanding = DeriveSatisfaction(full, map[uuid.UUID]bool{r1: true})
	if sat != relational.SSPLeverageSatisfactionPartial || len(outstanding) != 1 || outstanding[0].ResponsibilityUUID != r2 {
		t.Errorf("one missing: got %q / %v, want partial / [r2]", sat, outstanding)
	}
}

func TestAggregateByControl_CreditAllActiveAllFull(t *testing.T) {
	ssp := uuid.New()
	up := uuid.New()
	off := uuid.New()
	summaries := []LinkSummary{
		summary(ssp, up, off, "AC-2", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 3),
	}
	agg := AggregateByControl(summaries)
	got, ok := agg[ControlKey{SSPID: ssp, ControlID: "AC-2"}]
	if !ok {
		t.Fatal("expected an aggregate for AC-2")
	}
	if !got.Credit {
		t.Error("expected credit for a single active+full link")
	}
	if got.Links != 1 || got.TotalResponsibilities != 3 || got.OutstandingCount != 0 {
		t.Errorf("unexpected counts: %+v", got)
	}
	if got.Status != relational.SSPLeverageStatusActive || got.Satisfaction != relational.SSPLeverageSatisfactionFull {
		t.Errorf("unexpected status/satisfaction: %+v", got)
	}
}

func TestAggregateByControl_NoCreditOnPartialOrNonActive(t *testing.T) {
	ssp := uuid.New()
	up := uuid.New()
	off := uuid.New()

	noCredit := []struct {
		name   string
		status relational.SSPLeverageStatus
		sat    relational.SSPLeverageSatisfaction
	}{
		{"drifted", relational.SSPLeverageStatusDrifted, relational.SSPLeverageSatisfactionFull},
		{"revoked", relational.SSPLeverageStatusRevoked, relational.SSPLeverageSatisfactionFull},
		{"superseded", relational.SSPLeverageStatusSuperseded, relational.SSPLeverageSatisfactionFull},
		{"partial", relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionPartial},
	}
	for _, tc := range noCredit {
		t.Run(tc.name, func(t *testing.T) {
			agg := AggregateByControl([]LinkSummary{
				summary(ssp, up, off, "AC-2", nil, tc.status, tc.sat, 1, 3),
			})
			if agg[ControlKey{SSPID: ssp, ControlID: "AC-2"}].Credit {
				t.Errorf("%s must not earn credit", tc.name)
			}
		})
	}
}

func TestAggregateByControl_WorstStatusPrecedence(t *testing.T) {
	ssp := uuid.New()
	up := uuid.New()
	off := uuid.New()
	// active + superseded + revoked + drifted -> worst is drifted.
	summaries := []LinkSummary{
		summary(ssp, up, off, "AC-2", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 1),
		summary(ssp, up, off, "AC-2", nil, relational.SSPLeverageStatusSuperseded, relational.SSPLeverageSatisfactionFull, 0, 1),
		summary(ssp, up, off, "AC-2", nil, relational.SSPLeverageStatusRevoked, relational.SSPLeverageSatisfactionFull, 0, 1),
		summary(ssp, up, off, "AC-2", nil, relational.SSPLeverageStatusDrifted, relational.SSPLeverageSatisfactionFull, 0, 1),
	}
	got := AggregateByControl(summaries)[ControlKey{SSPID: ssp, ControlID: "AC-2"}]
	if got.Status != relational.SSPLeverageStatusDrifted {
		t.Errorf("worst status = %q, want drifted", got.Status)
	}
	if got.Credit {
		t.Error("a non-active link must strip credit")
	}
}

func TestAggregateByControl_StatementScopedCollapseAndCaseFold(t *testing.T) {
	ssp := uuid.New()
	up := uuid.New()
	off := uuid.New()
	// A control-scoped link plus a statement-scoped link with differently-cased id
	// collapse into one control key; counts sum.
	summaries := []LinkSummary{
		summary(ssp, up, off, "ac-2", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 2),
		summary(ssp, up, off, "AC-2", statement("ac-2_smt.a"), relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 3),
	}
	agg := AggregateByControl(summaries)
	if len(agg) != 1 {
		t.Fatalf("expected 1 control key, got %d", len(agg))
	}
	got := agg[ControlKey{SSPID: ssp, ControlID: "AC-2"}]
	if got.Links != 2 || got.TotalResponsibilities != 5 || got.OutstandingCount != 0 {
		t.Errorf("collapse sums wrong: %+v", got)
	}
	if !got.Credit {
		t.Error("both active+full should keep credit")
	}
}

func TestAggregateByControl_OriginDedupeAndSums(t *testing.T) {
	ssp := uuid.New()
	up1 := uuid.New()
	up2 := uuid.New()
	off1 := uuid.New()
	off2 := uuid.New()
	// Two links from the same (upstream, offering) dedupe to one origin; a third from a
	// different pair adds a second. Outstanding/total sum across all links.
	summaries := []LinkSummary{
		summary(ssp, up1, off1, "AC-2", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionPartial, 1, 3),
		summary(ssp, up1, off1, "AC-2", statement("ac-2_smt.a"), relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 2),
		summary(ssp, up2, off2, "AC-2", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 1),
	}
	got := AggregateByControl(summaries)[ControlKey{SSPID: ssp, ControlID: "AC-2"}]
	if len(got.InheritedFrom) != 2 {
		t.Errorf("expected 2 deduped origins, got %d", len(got.InheritedFrom))
	}
	if got.OutstandingCount != 1 || got.TotalResponsibilities != 6 {
		t.Errorf("sums wrong: outstanding=%d total=%d", got.OutstandingCount, got.TotalResponsibilities)
	}
	if got.Satisfaction != relational.SSPLeverageSatisfactionPartial {
		t.Errorf("any partial link -> partial aggregate, got %q", got.Satisfaction)
	}
	if got.Credit {
		t.Error("a partial link strips credit")
	}
}

func TestAggregateByControl_SeparateSSPsAndControls(t *testing.T) {
	sspA := uuid.New()
	sspB := uuid.New()
	up := uuid.New()
	off := uuid.New()
	summaries := []LinkSummary{
		summary(sspA, up, off, "AC-2", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 1),
		summary(sspB, up, off, "AC-2", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 1),
		summary(sspA, up, off, "AC-3", nil, relational.SSPLeverageStatusActive, relational.SSPLeverageSatisfactionFull, 0, 1),
	}
	agg := AggregateByControl(summaries)
	if len(agg) != 3 {
		t.Fatalf("expected 3 distinct (ssp, control) keys, got %d", len(agg))
	}
	for _, key := range []ControlKey{
		{SSPID: sspA, ControlID: "AC-2"},
		{SSPID: sspB, ControlID: "AC-2"},
		{SSPID: sspA, ControlID: "AC-3"},
	} {
		if !agg[key].Credit {
			t.Errorf("expected credit for %+v", key)
		}
	}
}

func TestAggregateByControl_Empty(t *testing.T) {
	if got := AggregateByControl(nil); len(got) != 0 {
		t.Errorf("expected empty map, got %d entries", len(got))
	}
}
