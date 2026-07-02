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

	if _, _, _, err := parseNodeKey("bogus"); err == nil {
		t.Error("malformed key should error")
	}
	if _, _, _, err := parseNodeKey("control:not-a-uuid/ac-1"); err == nil {
		t.Error("bad catalog uuid should error")
	}
}
