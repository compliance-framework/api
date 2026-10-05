package agentconfig

import (
	"crypto/sha256"
	"encoding/hex"
)

// DigestPrefix prefixes config digests.
const DigestPrefix = "sha256:"

// Digest returns "sha256:" + hex(sha256(canonical(Redact(c, opts...) with API = nil))).
// Callers pass the SAME options they used to redact the reported effective config, so the
// digest matches the reported document (R55). Canonical JSON is described on CanonicalJSON.
func Digest(c Config, opts ...RedactOption) string {
	r := Redact(c, opts...)
	r.API = nil
	raw, err := CanonicalJSON(r)
	if err != nil {
		// Redact normalizes every free-form value, so the redacted config always encodes.
		raw = nil
	}
	sum := sha256.Sum256(raw)
	return DigestPrefix + hex.EncodeToString(sum[:])
}
