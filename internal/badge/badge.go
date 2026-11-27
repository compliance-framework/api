// Package badge renders the SVG status badges published for saved evidence filters
// (docs/filter-badges.md). A badge discloses only its label and one aggregate state.
package badge

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"unicode/utf8"
)

// State is the aggregate compliance state a badge displays.
type State string

const (
	StateNoEvidence State = "no evidence"
	StateFailing    State = "failing"
	StatePassing    State = "passing"
	StateUnknown    State = "unknown"
)

// MaxLabelRunes bounds the label, and so the rendered width.
const MaxLabelRunes = 64

const (
	colorLabel   = "#555"
	colorRed     = "#e05d44"
	colorGreen   = "#4c1"
	colorGray    = "#9f9f9f"
	height       = 20
	padding      = 6
	asciiWidth   = 7
	wideWidth    = 12
	minTextWidth = 8
)

// Count is one evidence state and how much latest evidence is in it.
type Count struct {
	State string
	Count int64
}

// Aggregate reduces evidence state counts to the badge state: no evidence, failing when
// any evidence is not-satisfied, passing when all of it is satisfied, otherwise unknown.
// Unfamiliar and empty states are never treated as satisfied.
func Aggregate(counts []Count) State {
	var total int64
	failing := false
	allSatisfied := true
	for _, c := range counts {
		if c.Count <= 0 {
			continue
		}
		total += c.Count
		switch strings.ToLower(strings.TrimSpace(c.State)) {
		case "not-satisfied":
			failing = true
		case "satisfied":
		default:
			allSatisfied = false
		}
	}
	switch {
	case total == 0:
		return StateNoEvidence
	case failing:
		return StateFailing
	case allSatisfied:
		return StatePassing
	default:
		return StateUnknown
	}
}

func (s State) color() string {
	switch s {
	case StateFailing:
		return colorRed
	case StatePassing:
		return colorGreen
	default:
		return colorGray
	}
}

func (s State) text() string {
	switch s {
	case StateNoEvidence, StateFailing, StatePassing:
		return string(s)
	default:
		return string(StateUnknown)
	}
}

// Render returns the badge SVG. It references nothing outside itself: no scripts, links,
// images, fonts or URLs. Every inserted string is XML-escaped, which is safe in both the
// text and attribute contexts it is used in.
func Render(label string, state State) []byte {
	label = truncate(label, MaxLabelRunes)
	value := state.text()

	labelTextWidth := textWidth(label)
	valueTextWidth := textWidth(value)
	labelWidth := labelTextWidth + 2*padding
	valueWidth := valueTextWidth + 2*padding
	width := labelWidth + valueWidth
	title := escape(label + ": " + value)
	color := state.color()

	var b bytes.Buffer
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s">`, width, height, width, height, title)
	fmt.Fprintf(&b, `<title>%s</title>`, title)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" rx="3" fill="%s"/>`, width, height, colorLabel)
	fmt.Fprintf(&b, `<rect x="%d" width="%d" height="%d" rx="3" fill="%s"/>`, labelWidth, valueWidth, height, color)
	fmt.Fprintf(&b, `<rect x="%d" width="4" height="%d" fill="%s"/>`, labelWidth, height, color)
	b.WriteString(`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">`)
	writeText(&b, labelWidth/2, labelTextWidth, escape(label))
	writeText(&b, labelWidth+valueWidth/2, valueTextWidth, escape(value))
	b.WriteString(`</g></svg>`)
	return b.Bytes()
}

func writeText(b *bytes.Buffer, x, length int, escaped string) {
	fmt.Fprintf(b, `<text x="%d" y="15" fill="#010101" fill-opacity=".3" textLength="%d" lengthAdjust="spacingAndGlyphs" aria-hidden="true">%s</text>`, x, length, escaped)
	fmt.Fprintf(b, `<text x="%d" y="14" textLength="%d" lengthAdjust="spacingAndGlyphs">%s</text>`, x, length, escaped)
}

// textWidth estimates the rendered width of s at 11px.
func textWidth(s string) int {
	w := 0
	for _, r := range s {
		if r < utf8.RuneSelf {
			w += asciiWidth
		} else {
			w += wideWidth
		}
	}
	return max(w, minTextWidth)
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func escape(s string) string {
	var b bytes.Buffer
	// xml.EscapeText escapes quotes and replaces characters XML cannot carry; writing to a
	// bytes.Buffer cannot fail.
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
