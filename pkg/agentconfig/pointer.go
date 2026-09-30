package agentconfig

import "strings"

var (
	pointerEscaper   = strings.NewReplacer("~", "~0", "/", "~1")
	pointerUnescaper = strings.NewReplacer("~1", "/", "~0", "~")
)

// EscapePointerToken escapes one reference token for an RFC 6901 JSON Pointer
// ("~" -> "~0", "/" -> "~1").
func EscapePointerToken(token string) string {
	return pointerEscaper.Replace(token)
}

// UnescapePointerToken reverses EscapePointerToken.
func UnescapePointerToken(token string) string {
	return pointerUnescaper.Replace(token)
}

// Pointer builds an RFC 6901 JSON Pointer from unescaped segments, e.g.
// Pointer("policy_bundles", "ssh", "modules", "banner.rego") ==
// "/policy_bundles/ssh/modules/banner.rego" and Pointer("plugins", "x", "config", "a/b") ==
// "/plugins/x/config/a~1b". No segments yields "" (the whole document).
func Pointer(segments ...string) string {
	if len(segments) == 0 {
		return ""
	}
	var b strings.Builder
	for _, s := range segments {
		b.WriteByte('/')
		b.WriteString(EscapePointerToken(s))
	}
	return b.String()
}

// SplitPointer splits an RFC 6901 JSON Pointer into unescaped segments. "" yields nil.
func SplitPointer(ptr string) []string {
	if ptr == "" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(ptr, "/"), "/")
	for i, p := range parts {
		parts[i] = UnescapePointerToken(p)
	}
	return parts
}

// appendPointer appends one unescaped segment to an existing pointer.
func appendPointer(ptr string, segment string) string {
	return ptr + "/" + EscapePointerToken(segment)
}
