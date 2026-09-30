package agentconfig

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ETagForRevision returns the agent-facing opaque ETag (R7), including the quotes:
// `"r<rev>-<revisionRowID>"` for rev >= 1 and `"r0-<agentID>"` for rev 0, so a DB reset,
// re-registration or agent re-creation never yields a false 304. Server-side only: clients
// store the raw ETag they received and send it back verbatim.
func ETagForRevision(rev int64, revisionRowID uuid.UUID, agentID uuid.UUID) string {
	if rev <= 0 {
		return fmt.Sprintf(`"r0-%s"`, agentID)
	}
	return fmt.Sprintf(`"r%d-%s"`, rev, revisionRowID)
}

// normalizeETag strips a weak prefix, surrounding whitespace and quotes.
func normalizeETag(tag string) string {
	t := strings.TrimSpace(tag)
	t = strings.TrimPrefix(t, "W/")
	t = strings.TrimSpace(t)
	if len(t) >= 2 && strings.HasPrefix(t, `"`) && strings.HasSuffix(t, `"`) {
		t = t[1 : len(t)-1]
	}
	return t
}

// ParseETagRevision parses an opaque agent ETag (strong, W/ or bare) back into its revision
// and uuid (the revision row id, or the agent id for rev 0). For diagnostics and logging only.
func ParseETagRevision(tag string) (rev int64, id uuid.UUID, ok bool) {
	t := normalizeETag(tag)
	if !strings.HasPrefix(t, "r") {
		return 0, uuid.Nil, false
	}
	revPart, idPart, found := strings.Cut(t[1:], "-")
	if !found {
		return 0, uuid.Nil, false
	}
	r, err := strconv.ParseInt(revPart, 10, 64)
	if err != nil || r < 0 {
		return 0, uuid.Nil, false
	}
	u, err := uuid.Parse(idPart)
	if err != nil {
		return 0, uuid.Nil, false
	}
	return r, u, true
}

// MatchIfNoneMatch reports whether any entry of an If-None-Match header (strong, W/, bare,
// a comma-separated list, or "*") equals the CURRENT opaque tag. Entries are compared as text
// after stripping W/ and quotes. An empty header never matches.
func MatchIfNoneMatch(header, current string) bool {
	want := normalizeETag(current)
	if want == "" {
		return false
	}
	for _, entry := range strings.Split(header, ",") {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if e == "*" || normalizeETag(e) == want {
			return true
		}
	}
	return false
}

// AdminETag returns the admin-facing ETag for a revision: the plain revision number, quoted
// (`"7"`) (R7).
func AdminETag(rev int64) string {
	return fmt.Sprintf(`"%d"`, rev)
}

// ParseRevisionIfMatch parses an admin If-Match header holding a plain revision number:
// `"7"`, `W/"7"` or `7`. Exactly one non-negative value in canonical decimal form is
// accepted; anything else (a list, "*", a sign such as "+7", leading zeros such as "07")
// yields ok=false.
func ParseRevisionIfMatch(header string) (rev int64, ok bool) {
	h := strings.TrimSpace(header)
	if h == "" || strings.Contains(h, ",") {
		return 0, false
	}
	t := normalizeETag(h)
	if !isCanonicalDecimal(t) {
		return 0, false
	}
	r, err := strconv.ParseInt(t, 10, 64)
	if err != nil || r < 0 {
		return 0, false
	}
	return r, true
}

// isCanonicalDecimal reports whether s is "0" or a digit string without a leading zero.
func isCanonicalDecimal(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
