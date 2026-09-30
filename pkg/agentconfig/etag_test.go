package agentconfig

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	etagRowID   = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	etagAgentID = uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	etagOtherID = uuid.MustParse("99999999-2222-3333-4444-555555555555")
)

func TestETagForRevision(t *testing.T) {
	assert.Equal(t, `"r0-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"`, ETagForRevision(0, etagRowID, etagAgentID))
	assert.Equal(t, `"r0-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"`, ETagForRevision(0, uuid.Nil, etagAgentID))
	assert.Equal(t, `"r7-11111111-2222-3333-4444-555555555555"`, ETagForRevision(7, etagRowID, etagAgentID))
	assert.Equal(t, `"r1-11111111-2222-3333-4444-555555555555"`, ETagForRevision(1, etagRowID, etagAgentID))
}

func TestParseETagRevision(t *testing.T) {
	tests := []struct {
		tag     string
		wantRev int64
		wantID  uuid.UUID
		wantOK  bool
	}{
		{tag: `"r7-11111111-2222-3333-4444-555555555555"`, wantRev: 7, wantID: etagRowID, wantOK: true},
		{tag: `W/"r7-11111111-2222-3333-4444-555555555555"`, wantRev: 7, wantID: etagRowID, wantOK: true},
		{tag: `r7-11111111-2222-3333-4444-555555555555`, wantRev: 7, wantID: etagRowID, wantOK: true},
		{tag: ` "r0-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `, wantRev: 0, wantID: etagAgentID, wantOK: true},
		{tag: ETagForRevision(42, etagRowID, etagAgentID), wantRev: 42, wantID: etagRowID, wantOK: true},
		{tag: ``},
		{tag: `"7"`},
		{tag: `"x7-11111111-2222-3333-4444-555555555555"`},
		{tag: `"r-11111111-2222-3333-4444-555555555555"`},
		{tag: `"r-1-11111111-2222-3333-4444-555555555555"`},
		{tag: `"r7"`},
		{tag: `"r7-not-a-uuid"`},
		{tag: `"rX-11111111-2222-3333-4444-555555555555"`},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			rev, id, ok := ParseETagRevision(tt.tag)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantRev, rev)
			if tt.wantOK {
				assert.Equal(t, tt.wantID, id)
			} else {
				assert.Equal(t, uuid.Nil, id)
			}
		})
	}
}

func TestMatchIfNoneMatch(t *testing.T) {
	current := ETagForRevision(7, etagRowID, etagAgentID)
	other := ETagForRevision(7, etagOtherID, etagAgentID)
	older := ETagForRevision(6, etagRowID, etagAgentID)
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "strong", header: current, want: true},
		{name: "weak", header: "W/" + current, want: true},
		{name: "bare", header: "r7-11111111-2222-3333-4444-555555555555", want: true},
		{name: "list containing", header: older + ", " + "W/" + current, want: true},
		{name: "list without spaces", header: older + "," + current, want: true},
		{name: "star", header: "*", want: true},
		{name: "star in list", header: older + ", *", want: true},
		{name: "mismatching row uuid", header: other, want: false},
		{name: "older revision", header: older, want: false},
		{name: "list not containing", header: older + ", " + other, want: false},
		{name: "empty", header: "", want: false},
		{name: "whitespace", header: "  ", want: false},
		{name: "empty list entries", header: " , ,", want: false},
		{name: "case sensitive", header: `"R7-11111111-2222-3333-4444-555555555555"`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchIfNoneMatch(tt.header, current))
		})
	}
	assert.False(t, MatchIfNoneMatch("*", ""), "no current tag never matches")
	assert.False(t, MatchIfNoneMatch(`""`, `""`))
}

func TestAdminETag(t *testing.T) {
	assert.Equal(t, `"7"`, AdminETag(7))
	rev, ok := ParseRevisionIfMatch(AdminETag(7))
	assert.True(t, ok)
	assert.Equal(t, int64(7), rev)
}

func TestParseRevisionIfMatch(t *testing.T) {
	tests := []struct {
		header  string
		wantRev int64
		wantOK  bool
	}{
		{header: `"7"`, wantRev: 7, wantOK: true},
		{header: `W/"7"`, wantRev: 7, wantOK: true},
		{header: `7`, wantRev: 7, wantOK: true},
		{header: ` "0" `, wantRev: 0, wantOK: true},
		{header: `"123456789012"`, wantRev: 123456789012, wantOK: true},
		{header: ``},
		{header: `  `},
		{header: `*`},
		{header: `"*"`},
		{header: `"7", "8"`},
		{header: `7,8`},
		{header: `"-1"`},
		{header: `-1`},
		{header: `"abc"`},
		{header: `"7`},
		{header: `""`},
		{header: `"""7"""`},
		{header: `"r7-11111111-2222-3333-4444-555555555555"`},
		{header: `"7.0"`},
		{header: `"+7"`},
		{header: `+7`},
		{header: `W/"+7"`},
		{header: `"07"`},
		{header: `"00"`},
		{header: `" 7"`},
		{header: `"7 "`},
		{header: `"0x7"`},
		{header: `"1e3"`},
		{header: `"99999999999999999999"`},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			rev, ok := ParseRevisionIfMatch(tt.header)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantRev, rev)
		})
	}
}
