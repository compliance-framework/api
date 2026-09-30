package agentconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPointer(t *testing.T) {
	tests := []struct {
		segments []string
		want     string
	}{
		{nil, ""},
		{[]string{""}, "/"},
		{[]string{"plugins", "x", "config", "port"}, "/plugins/x/config/port"},
		{[]string{"plugins", "x", "config", "a/b"}, "/plugins/x/config/a~1b"},
		{[]string{"k~ey"}, "/k~0ey"},
		{[]string{"~/", "/~"}, "/~0~1/~1~0"},
		{[]string{"~1"}, "/~01"},
		{[]string{"policy_bundles", "ssh", "modules", "sub/banner.rego"}, "/policy_bundles/ssh/modules/sub~1banner.rego"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := Pointer(tt.segments...)
			assert.Equal(t, tt.want, got)
			if len(tt.segments) > 0 {
				assert.Equal(t, tt.segments, SplitPointer(got), "round trip")
			} else {
				assert.Nil(t, SplitPointer(got))
			}
		})
	}
}

func TestEscapePointerToken(t *testing.T) {
	for _, s := range []string{"", "a", "a/b", "a~b", "~1", "~0", "/~/~", "~~//"} {
		esc := EscapePointerToken(s)
		assert.NotContains(t, esc, "/", s)
		assert.Equal(t, s, UnescapePointerToken(esc), s)
	}
	assert.Equal(t, "~01", EscapePointerToken("~1"))
	assert.Equal(t, "~1", UnescapePointerToken("~01"), "~01 unescapes to ~1, not /")
}

func TestDiffJSON(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want []DiffEntry
	}{
		{name: "equal", a: `{"a":1,"b":[1,2]}`, b: `{"b":[1,2],"a":1}`, want: nil},
		{name: "equal numbers by text", a: `{"n":12345678901234567890}`, b: `{"n":12345678901234567890}`, want: nil},
		{
			name: "add remove replace",
			a:    `{"a":1,"b":"x","c":true}`,
			b:    `{"a":2,"c":true,"d":null}`,
			want: []DiffEntry{
				{Path: "/a", Op: DiffOpReplace, From: json.RawMessage(`1`), To: json.RawMessage(`2`)},
				{Path: "/b", Op: DiffOpRemove, From: json.RawMessage(`"x"`)},
				{Path: "/d", Op: DiffOpAdd, To: json.RawMessage(`null`)},
			},
		},
		{
			name: "nested objects recurse",
			a:    `{"plugins":{"x":{"config":{"port":"22","host":"h"}}}}`,
			b:    `{"plugins":{"x":{"config":{"port":"2222","host":"h"}},"y":{"source":"s"}}}`,
			want: []DiffEntry{
				{Path: "/plugins/x/config/port", Op: DiffOpReplace, From: json.RawMessage(`"22"`), To: json.RawMessage(`"2222"`)},
				{Path: "/plugins/y", Op: DiffOpAdd, To: json.RawMessage(`{"source":"s"}`)},
			},
		},
		{
			name: "arrays are leaves",
			a:    `{"p":["a","b"]}`,
			b:    `{"p":["a","c"]}`,
			want: []DiffEntry{{Path: "/p", Op: DiffOpReplace, From: json.RawMessage(`["a","b"]`), To: json.RawMessage(`["a","c"]`)}},
		},
		{
			name: "type change object to scalar",
			a:    `{"x":{"y":1}}`,
			b:    `{"x":null}`,
			want: []DiffEntry{{Path: "/x", Op: DiffOpReplace, From: json.RawMessage(`{"y":1}`), To: json.RawMessage(`null`)}},
		},
		{
			name: "keys with / and ~ are escaped",
			a:    `{"m":{"a/b":1,"c~d":1}}`,
			b:    `{"m":{"a/b":2}}`,
			want: []DiffEntry{
				{Path: "/m/a~1b", Op: DiffOpReplace, From: json.RawMessage(`1`), To: json.RawMessage(`2`)},
				{Path: "/m/c~0d", Op: DiffOpRemove, From: json.RawMessage(`1`)},
			},
		},
		{
			name: "root replace",
			a:    `[1]`,
			b:    `{"a":1}`,
			want: []DiffEntry{{Path: "", Op: DiffOpReplace, From: json.RawMessage(`[1]`), To: json.RawMessage(`{"a":1}`)}},
		},
		{
			name: "empty input is null",
			a:    ``,
			b:    `null`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DiffJSON([]byte(tt.a), []byte(tt.b))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDiffJSONSortedByPath(t *testing.T) {
	got, err := DiffJSON([]byte(`{"z":1,"a":{"c":1,"b":1},"m":1}`), []byte(`{"z":2,"a":{"c":2,"b":2},"m":2}`))
	require.NoError(t, err)
	var paths []string
	for _, d := range got {
		paths = append(paths, d.Path)
	}
	assert.Equal(t, []string{"/a/b", "/a/c", "/m", "/z"}, paths)
}

func TestDiffJSONErrors(t *testing.T) {
	_, err := DiffJSON([]byte(`{`), []byte(`{}`))
	assert.Error(t, err)
	_, err = DiffJSON([]byte(`{}`), []byte(`nope`))
	assert.Error(t, err)
}
