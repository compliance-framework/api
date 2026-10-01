package policyeval

import (
	"path"
	"strings"
)

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
// policyFile comes from OPA's loader, which joins the bundle directory and the file, so it
// is clean even when policyPath is not (for example "./x" or "x/"); the `_policy_path` seed
// is policyPath as passed.
//
// Without a policy ID, they are policyFile and policyPath unchanged, so every existing
// evidence stream keeps its UUIDs. An ID that ValidPolicyID rejects counts as none, as
// Execute does when it sets Policy.ID.
//
// An ID equal to policyFile, or that cleans to it, also gives that legacy pair exactly, so a
// policy_id naming the policy's own location never changes its own stream, whatever the
// shape of the policy path.
//
// For any other ID the file seed is the cleaned ID, matching OPA's clean policy_file. The
// path seed is the raw (un-cleaned) ID minus "/" + the policy's bundle-relative path when
// the raw ID ends in that, and the raw ID itself otherwise. The bundle-relative path is
// policyFile relative to the cleaned policyPath. So an ID built as the literal
// plugin-path + "/" + file of another location (for example a vendor module that an inline
// bundle overrides) continues that file's stream even when that plugin path is un-cleaned:
// "./policies" + "/" + "a.rego" seeds ("policies/a.rego", "./policies"), as the vendor
// plugin did. An opaque ID (for example "ssh-deny-password-auth") gives a stream that does
// not depend on where the bundle lives; its file seed is also cleaned, which leaves a plain
// slug as it is.
//
// The agent's policy-manager calls this when it seeds evidence, so the API, the agent and
// the UI agree on the identity a policy_id produces.
func SeedPath(policyID, policyFile, policyPath string) (seedFile, seedPolicyPath string) {
	if !ValidPolicyID(policyID) || policyID == policyFile || path.Clean(policyID) == policyFile {
		return policyFile, policyPath
	}
	seedFile = path.Clean(policyID)
	rel := bundleRelative(policyFile, policyPath)
	if rel != "" && strings.HasSuffix(policyID, "/"+rel) {
		// Trim the raw ID so a literal plugin path such as "./x" or "x/" survives as is.
		return seedFile, strings.TrimSuffix(policyID, "/"+rel)
	}
	return seedFile, policyID
}

// bundleRelative returns policyFile's path relative to the cleaned policyPath, or "" when
// policyPath is empty or policyFile is not under it.
func bundleRelative(policyFile, policyPath string) string {
	if policyPath == "" {
		return ""
	}
	dir := path.Clean(policyPath)
	if dir == "." {
		// OPA joins "." away: a relative file is under it unless it climbs out.
		if path.IsAbs(policyFile) || policyFile == ".." || strings.HasPrefix(policyFile, "../") {
			return ""
		}
		return policyFile
	}
	rest, ok := strings.CutPrefix(policyFile, strings.TrimSuffix(dir, "/")+"/")
	if !ok {
		return ""
	}
	return rest
}
