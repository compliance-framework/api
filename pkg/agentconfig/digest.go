package agentconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// DigestPrefix prefixes config digests.
const DigestPrefix = "sha256:"

// TreeDigestPrefix prefixes bundle tree digests.
const TreeDigestPrefix = "tree:sha256:"

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

// BundleTreeDigest is the single digest of a materialized policy tree (paths relative to the
// policy root). It is:
//
//	"tree:sha256:" + hex(sha256( for each path in sort.Strings(keys(files)):
//	                               path + "\x00" + hex(sha256(files[path])) + "\n" ))
//
// Golden vector: BundleTreeDigest(map[string][]byte{"a.rego": []byte("package a\n"),
// "data.json": []byte("{}")}) ==
// "tree:sha256:7e0808049205b3cce8b6f1bbedbef302d261072214504dd6add0d5674d2e5c2c" (see
// TestBundleTreeDigestGolden). It is the "digest" of a PolicyBundleReport, and
// GET /api/artifacts/{digest}/files reports it as treeDigest for a stored bundle, so a
// reported tree and its artifact can be matched. It is not the artifact digest, which
// addresses the canonical tar (internal/artifact).
func BundleTreeDigest(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var b strings.Builder
	for _, p := range paths {
		sum := sha256.Sum256(files[p])
		b.WriteString(p)
		b.WriteByte(0)
		b.WriteString(hex.EncodeToString(sum[:]))
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return TreeDigestPrefix + hex.EncodeToString(sum[:])
}
