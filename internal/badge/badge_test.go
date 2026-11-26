package badge

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestAggregate(t *testing.T) {
	cases := []struct {
		name   string
		counts []Count
		want   State
	}{
		{"empty", nil, StateNoEvidence},
		{"zero counts", []Count{{"satisfied", 0}}, StateNoEvidence},
		{"all satisfied", []Count{{"satisfied", 3}}, StatePassing},
		{"any not-satisfied", []Count{{"satisfied", 9}, {"not-satisfied", 1}}, StateFailing},
		{"failing beats unknown", []Count{{"not-satisfied", 1}, {"other", 1}}, StateFailing},
		{"unfamiliar state", []Count{{"satisfied", 9}, {"pending", 1}}, StateUnknown},
		{"empty state", []Count{{"satisfied", 9}, {"", 1}}, StateUnknown},
		{"case and space folded", []Count{{" Satisfied ", 2}}, StatePassing},
	}
	for _, tc := range cases {
		if got := Aggregate(tc.counts); got != tc.want {
			t.Errorf("%s: Aggregate = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRenderEscapesAndStaysSelfContained(t *testing.T) {
	label := `<script>alert("x")</script> & 'q' ` + "\uFFFE"
	svg := string(Render(label, StateFailing))

	if err := xml.Unmarshal([]byte(svg), new(struct{})); err != nil {
		t.Fatalf("rendered SVG is not well-formed XML: %v\n%s", err, svg)
	}
	for _, forbidden := range []string{"<script", "foreignObject", "href", "<image", "@import", "url(", "on" + "load", "javascript:"} {
		if strings.Contains(svg, forbidden) {
			t.Errorf("SVG contains %q:\n%s", forbidden, svg)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "&amp;", "&#34;x&#34;", `role="img"`, "<title>", "failing", "#e05d44"} {
		if !strings.Contains(svg, want) {
			t.Errorf("SVG lacks %q:\n%s", want, svg)
		}
	}
	// Only the SVG namespace may appear as a URL.
	if strings.Count(svg, "http") != 1 {
		t.Errorf("SVG references URLs other than its namespace:\n%s", svg)
	}
}

func TestRenderIsBoundedAndDeterministic(t *testing.T) {
	long := strings.Repeat("界", 500)
	a, b := Render(long, StatePassing), Render(long, StatePassing)
	if string(a) != string(b) {
		t.Fatal("Render is not deterministic")
	}
	// aria-label, title, and the text and its shadow each carry the label once.
	if got := strings.Count(string(a), "界"); got != 4*MaxLabelRunes {
		t.Errorf("label occurrences = %d runes, want truncation to %d per use", got, MaxLabelRunes)
	}
	if len(a) > 4096 {
		t.Errorf("SVG is %d bytes; want a small bounded document", len(a))
	}
}

func TestRenderStates(t *testing.T) {
	for state, color := range map[State]string{
		StatePassing:    "#4c1",
		StateFailing:    "#e05d44",
		StateNoEvidence: "#9f9f9f",
		StateUnknown:    "#9f9f9f",
		State("bogus"):  "#9f9f9f",
	} {
		svg := string(Render("compliance", state))
		if !strings.Contains(svg, color) {
			t.Errorf("%q: missing color %s", state, color)
		}
		text := string(state)
		if state == "bogus" {
			text = string(StateUnknown)
		}
		if !strings.Contains(svg, "<title>compliance: "+text+"</title>") {
			t.Errorf("%q: missing title text %q:\n%s", state, text, svg)
		}
	}
}
