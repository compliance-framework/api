package relational

import (
	"encoding/json"
	"os"
	"testing"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/stretchr/testify/assert"
)

func TestImport_MarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Import
	}{
		{
			name: "with include-all set",
			data: oscalTypes_1_1_3.Import{
				Href:       "#/definition/123456",
				IncludeAll: &oscalTypes_1_1_3.IncludeAll{},
			},
		},
		{
			name: "without include-all but include-controls set",
			data: oscalTypes_1_1_3.Import{
				Href: "#/definition/123456",
				IncludeControls: &[]oscalTypes_1_1_3.SelectControlById{
					{
						WithIds: &[]string{
							"ac-1",
							"ac-2",
						},
					},
				},
			},
		},
		{
			name: "include-controls and exclude-controls set",
			data: oscalTypes_1_1_3.Import{
				Href: "#/definition/123456",
				IncludeControls: &[]oscalTypes_1_1_3.SelectControlById{
					{
						WithIds: &[]string{
							"ac-1",
							"ac-2",
						},
						WithChildControls: "controls.json",
						Matching: &[]oscalTypes_1_1_3.Matching{
							{
								Pattern: "ia\\d+.\\d+",
							},
						},
					},
				},
				ExcludeControls: &[]oscalTypes_1_1_3.SelectControlById{
					{
						WithIds: &[]string{
							"ia-1",
						},
						WithChildControls: "controls-exclude.json",
						Matching: &[]oscalTypes_1_1_3.Matching{
							{
								Pattern: "cp-7.\\d+",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize the OSCAL type to JSON
			inputJSON, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			// Round-trip through internal model
			imp := Import{}
			imp.UnmarshalOscal(tt.data)
			output := imp.MarshalOscal()
			outputJSON, err := json.Marshal(output)
			assert.NoError(t, err)

			// Deep-compare JSON
			assert.JSONEq(t, string(inputJSON), string(outputJSON))
		})
	}
}

func TestMerge_MarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Merge
	}{
		{
			name: "with AsIs Set only - true",
			data: oscalTypes_1_1_3.Merge{
				AsIs: true,
			},
		},
		{
			name: "with AsIs Set only - false",
			data: oscalTypes_1_1_3.Merge{
				AsIs: false,
			},
		},
		{
			name: "with nothing set",
			data: oscalTypes_1_1_3.Merge{},
		},
		{
			name: "with flat set",
			data: oscalTypes_1_1_3.Merge{
				Flat: &oscalTypes_1_1_3.FlatWithoutGrouping{},
			},
		},
		{
			name: "combine set",
			data: oscalTypes_1_1_3.Merge{
				Combine: &oscalTypes_1_1_3.CombinationRule{
					Method: "test",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize the OSCAL type to JSON
			inputJSON, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			// Round-trip through internal model
			merge := Merge{}
			merge.UnmarshalOscal(tt.data)
			output := merge.MarshalOscal()
			outputJSON, err := json.Marshal(output)
			assert.NoError(t, err)

			// Deep-compare JSON
			assert.JSONEq(t, string(inputJSON), string(outputJSON))
		})
	}
}

func TestParameterSetting_MarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.ParameterSetting
	}{
		{
			name: "with minimal fields set",
			data: oscalTypes_1_1_3.ParameterSetting{
				ParamId: "minimal-param",
			},
		},
		{
			name: "with full fields set",
			data: oscalTypes_1_1_3.ParameterSetting{
				ParamId:   "full-param",
				Class:     "classification",
				DependsOn: "dependency-id",
				Label:     "Full Parameter Label",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "prop-name", Value: "prop-value"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "https://example.com", Rel: "related"},
				},
				Constraints: &[]oscalTypes_1_1_3.ParameterConstraint{
					{Description: "constraint description"},
				},
				Guidelines: &[]oscalTypes_1_1_3.ParameterGuideline{
					{Prose: "follow this"},
				},
				Values: &[]string{"value1", "value2"},
				Select: &oscalTypes_1_1_3.ParameterSelection{
					HowMany: "one",
					Choice: &[]string{
						"1",
						"2",
					},
				},
			},
		},
		{
			name: "with select but no choices",
			data: oscalTypes_1_1_3.ParameterSetting{
				ParamId: "select-no-choices",
				Select: &oscalTypes_1_1_3.ParameterSelection{
					HowMany: "one",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize the OSCAL type to JSON
			inputJSON, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			// Round-trip through internal model
			ps := ParameterSetting{}
			ps.UnmarshalOscal(tt.data)
			output := ps.MarshalOscal()
			outputJSON, err := json.Marshal(output)
			assert.NoError(t, err)

			// Deep-compare JSON
			assert.JSONEq(t, string(inputJSON), string(outputJSON))
		})
	}
}

func TestProfile_MarshalOscal(t *testing.T) {
	f, err := os.Open("../../../testdata/profile_fedramp_low.json")
	assert.NoError(t, err)

	defer func() {
		err := f.Close()
		assert.NoError(t, err)
	}()

	embed := struct {
		Profile oscalTypes_1_1_3.Profile `json:"profile"`
	}{}
	err = json.NewDecoder(f).Decode(&embed)
	assert.NoError(t, err)

	inputJson, err := json.Marshal(embed.Profile)
	assert.NoError(t, err)

	profile := &Profile{}
	profile.UnmarshalOscal(embed.Profile)

	output := profile.MarshalOscal()
	outputJSON, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJSON))
}

func TestProfileImportHrefResolve(t *testing.T) {
	tests := []struct {
		name     string
		href     string
		expected *HrefMetadata
	}{
		{
			name: "absolute URL with scheme and host",
			href: "https://example.com/resource",
			expected: &HrefMetadata{
				Path:         "https://example.com/resource",
				AbsolutePath: true,
				RelativePath: false,
				Fragment:     false,
			},
		},
		{
			name: "relative URL",
			href: "path/to/resource",
			expected: &HrefMetadata{
				Path:         "path/to/resource",
				AbsolutePath: false,
				RelativePath: true,
				Fragment:     false,
			},
		},
		{
			name: "URI fragment",
			href: "#fragment",
			expected: &HrefMetadata{
				Path:         "fragment",
				AbsolutePath: false,
				RelativePath: false,
				Fragment:     true,
			},
		},
		{
			name: "Filepath URI",
			href: "file:///path/to/resource",
			expected: &HrefMetadata{
				Path:         "file:///path/to/resource",
				AbsolutePath: true,
				RelativePath: false,
				Fragment:     false,
			},
		},
		{
			name: "Shorthand filepath URI",
			href: "/path/to/resource",
			expected: &HrefMetadata{
				Path:         "/path/to/resource",
				AbsolutePath: true,
				RelativePath: false,
				Fragment:     false,
			},
		},
		{
			name: "Relative file path in the same directory",
			href: "resource.txt",
			expected: &HrefMetadata{
				Path:         "resource.txt",
				AbsolutePath: false,
				RelativePath: true,
				Fragment:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imp := Import{Href: tt.href}
			result, err := imp.ResolveHref()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
