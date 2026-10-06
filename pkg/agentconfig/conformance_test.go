package agentconfig

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// conformanceGolden is the conformance file for the clients that re-implement some of this
// package's rules (the UI: glob.ts, cron5.ts, field-access.ts, validation.ts). It is
// generated from the same tables the unit tests use, with every expected value computed by
// the real functions, and TestConformanceGolden fails when it is stale.
const conformanceGolden = "testdata/conformance.json"

var updateConformance = flag.Bool("update", false, "rewrite "+conformanceGolden+" (TestConformanceGolden)")

type conformanceDoc struct {
	Comment        string `json:"_comment"`
	Source         string `json:"_source"`
	TrustedSources struct {
		Patterns []string                   `json:"patterns"`
		Cases    [][2]any                   `json:"cases"`
		Extra    []conformanceTrustedSource `json:"extra"`
	} `json:"trustedSources"`
	OverridableConfigFlags []conformanceConfigFlag `json:"overridableConfigFlags"`
	SourceKinds            [][2]string             `json:"sourceKinds"`
	Schedules              conformanceValidity     `json:"schedules"`
	ApplySafe              struct {
		Comment string                 `json:"_comment"`
		Cases   []conformanceApplySafe `json:"cases"`
	} `json:"applySafe"`
	PluginNames conformanceValidity `json:"pluginNames"`
}

type conformanceTrustedSource struct {
	Patterns []string `json:"patterns"`
	Source   string   `json:"source"`
	Want     bool     `json:"want"`
}

type conformanceConfigFlag struct {
	Name   string   `json:"name"`
	Flags  []string `json:"flags"`
	Plugin string   `json:"plugin"`
	Key    string   `json:"key"`
	Want   bool     `json:"want"`
}

type conformanceValidity struct {
	Valid   []string `json:"valid"`
	Invalid []string `json:"invalid"`
}

type conformanceApplySafe struct {
	Name    string             `json:"name"`
	Trusted []string           `json:"trusted"`
	File    map[string]*Plugin `json:"file"`
	Overlay json.RawMessage    `json:"overlay"` // the UI's draft overlay: always null here
	Path    string             `json:"path"`
	State   string             `json:"state"`
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// conformanceDocument builds the golden file from the unit-test tables, computing every
// expected value with the real functions.
func conformanceDocument() ([]byte, error) {
	var doc conformanceDoc
	doc.Comment = "Expected results of the pkg/agentconfig rules that clients re-implement (the UI's glob.ts, cron5.ts, field-access.ts, validation.ts). " +
		"Generated from the API's own test tables (remoteconfig_test.go, sources_test.go incl. TestNamePatterns, cron_test.go, classify_test.go), " +
		"every expected value computed by the real functions. Do not edit: regenerate with go test ./pkg/agentconfig -run TestConformanceGolden -update."
	doc.Source = "compliance-framework/api pkg/agentconfig/testdata/conformance.json"

	doc.TrustedSources.Patterns = trustedSourcePatterns
	rc := RemoteConfig{TrustedSources: trustedSourcePatterns}
	for _, c := range trustedSourceCases {
		doc.TrustedSources.Cases = append(doc.TrustedSources.Cases, [2]any{c.source, MatchTrustedSource(rc, c.source)})
	}
	for _, c := range trustedSourceExtraCases {
		doc.TrustedSources.Extra = append(doc.TrustedSources.Extra, conformanceTrustedSource{
			Patterns: nonNilStrings(c.patterns),
			Source:   c.source,
			Want:     MatchTrustedSource(RemoteConfig{TrustedSources: c.patterns}, c.source),
		})
	}

	for _, c := range overridableConfigFlagCases {
		doc.OverridableConfigFlags = append(doc.OverridableConfigFlags, conformanceConfigFlag{
			Name: c.name, Flags: nonNilStrings(c.flags), Plugin: c.plugin, Key: c.key,
			Want: MatchOverridableConfigFlag(RemoteConfig{OverridableConfigFlags: c.flags}, c.plugin, c.key),
		})
	}

	for _, c := range sourceKindCases {
		doc.SourceKinds = append(doc.SourceKinds, [2]string{c.source, string(KindOf(c.source))})
	}

	doc.Schedules = conformanceValidity{Valid: []string{}, Invalid: []string{}}
	for _, expr := range append(append([]string{}, schedulesValid...), schedulesInvalid...) {
		if _, err := ParseSchedule(expr); err == nil {
			doc.Schedules.Valid = append(doc.Schedules.Valid, expr)
		} else {
			doc.Schedules.Invalid = append(doc.Schedules.Invalid, expr)
		}
	}

	doc.PluginNames = conformanceValidity{Valid: []string{}, Invalid: []string{}}
	for _, name := range append(append([]string{}, pluginNamesValid...), pluginNamesInvalid...) {
		if PluginNamePattern.MatchString(name) {
			doc.PluginNames.Valid = append(doc.PluginNames.Valid, name)
		} else {
			doc.PluginNames.Invalid = append(doc.PluginNames.Invalid, name)
		}
	}

	doc.ApplySafe.Comment = "classify_test.go applySafeCases: whether an apply_safe host applies a change at `path` (Classify + WillApply over the case's probe overlays), for the field-level prediction of field-access.ts. `state` is fieldAccess over that one host: editable (every probe applies), restricted (some do), readonly (none do)."
	for _, c := range applySafeCases {
		state, err := applySafeState(c.trusted, c.file, c.path, c.probes)
		if err != nil {
			return nil, err
		}
		doc.ApplySafe.Cases = append(doc.ApplySafe.Cases, conformanceApplySafe{
			Name: c.name, Trusted: nonNilStrings(c.trusted), File: c.file,
			Overlay: json.RawMessage("null"), Path: c.path, State: state,
		})
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TestConformanceGolden fails when testdata/conformance.json no longer matches the rules.
// Regenerate it with: go test ./pkg/agentconfig -run TestConformanceGolden -update
func TestConformanceGolden(t *testing.T) {
	got, err := conformanceDocument()
	require.NoError(t, err)
	if *updateConformance {
		require.NoError(t, os.MkdirAll(filepath.Dir(conformanceGolden), 0o755))
		require.NoError(t, os.WriteFile(conformanceGolden, got, 0o644))
		return
	}
	want, err := os.ReadFile(conformanceGolden)
	require.NoError(t, err, "run: go test ./pkg/agentconfig -run TestConformanceGolden -update")
	assert.Equal(t, string(want), string(got),
		"%s is stale: a rule or its test table changed. Regenerate it with go test ./pkg/agentconfig -run TestConformanceGolden -update, and update the clients that consume it", conformanceGolden)
}
