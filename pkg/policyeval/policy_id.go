package policyeval

import "strings"

// A policy module may declare its evidence identity with `policy_id := "<string>"` (R74).
// Plugins seed each evidence UUID with the policy's file path and the policy path the agent
// passed them, so moving, renaming or overriding a policy file starts a new evidence stream.
// A policy_id replaces those two seed values (see SeedPath), so the stream follows the
// policy instead of its location. Without a policy_id nothing changes.

// MaxPolicyIDLength is the most characters (runes) a policy_id may have.
const MaxPolicyIDLength = 512

// keyPolicyID is the contract key that declares a policy's evidence identity.
const keyPolicyID = "policy_id"

// ValidPolicyID reports whether id can be a policy_id: a non-empty, valid UTF-8 string of at
// most MaxPolicyIDLength characters.
func ValidPolicyID(id string) bool {
	return policyIDProblem(id) == ""
}

// policyIDFrom returns the module output's policy_id when it is a valid one, and "" when it
// is absent or invalid. An invalid one never fails evaluation; ValidateResult reports it.
func policyIDFrom(outputs map[string]any) string {
	id, ok := outputs[keyPolicyID].(string)
	if !ok || !ValidPolicyID(id) {
		return ""
	}
	return id
}

// SeedPath returns the two values a plugin seeds a policy's evidence UUID with, as
// `policy_file` and as the `_policy_path` label (R74). policyFile is Result.Policy.File and
// policyPath is the path string the agent passed to the plugin for the policy's bundle.
//
// Without a policy ID, they are policyFile and policyPath unchanged, so every existing
// evidence stream keeps its UUIDs.
//
// With a policy ID, the file seed is the ID. The path seed is the ID minus the policy's
// bundle-relative path when the ID ends in "/" + that path, and the ID itself otherwise.
// The bundle-relative path rel is the literal relationship policyFile == policyPath + "/" +
// rel (or policyPath + rel when policyPath already ends in "/", in which case the trailing
// "/" is kept in the path seed); nothing is cleaned or made absolute, since plugins seed
// with the literal strings. So an ID equal to the legacy
// policyFile reproduces the legacy pair exactly, which lets an override continue the stream
// of the policy it replaces, and an opaque ID (for example "ssh-deny-password-auth") gives a
// stream that does not depend on where the bundle lives.
//
// The agent's policy-manager calls this when it seeds evidence, so the API, the agent and
// the UI agree on the identity a policy_id produces.
func SeedPath(policyID, policyFile, policyPath string) (seedFile, seedPolicyPath string) {
	if policyID == "" {
		return policyFile, policyPath
	}
	rel, sep := bundleRelative(policyFile, policyPath)
	if rel != "" && strings.HasSuffix(policyID, "/"+rel) {
		return policyID, policyID[:len(policyID)-len(rel)-len(sep)]
	}
	return policyID, policyID
}

// bundleRelative splits policyFile into policyPath, a separator and the bundle-relative path
// rel, by their literal strings. sep is "/", or "" when policyPath already ends in "/". rel
// is "" when policyFile is not under policyPath.
func bundleRelative(policyFile, policyPath string) (rel, sep string) {
	if policyPath == "" {
		return "", ""
	}
	if rest, ok := strings.CutPrefix(policyFile, policyPath+"/"); ok {
		return rest, "/"
	}
	if strings.HasSuffix(policyPath, "/") {
		if rest, ok := strings.CutPrefix(policyFile, policyPath); ok {
			return rest, ""
		}
	}
	return "", ""
}
