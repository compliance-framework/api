# Policy identity

Plugins give each piece of evidence a UUID seeded from the policy's location:

```
SeededUUID({type: evidence, policy: <package>, policy_file: <policy path>/<file>}
           + plugin labels {type, hostname, _policy_path: <policy path>})
```

`<policy path>` is the literal string the agent passes to the plugin for the policy's
bundle. For example:

- vendor OCI bundle: `.compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies`
- inline bundle: `.compliance-framework/policies/_inline/<bundle>/policies`

Agent and config labels (`_agent`, `_plugin`, `plugins.<p>.labels`) are added after the UUID
is computed, so they are not part of the seed.

## Path shadowing keeps vendor streams

When an inline bundle `extends` an OCI source, the agent gives it to plugins **at the
source's own path string** and changes only what that path resolves to. Inherited and
overridden modules therefore keep the vendor's evidence streams, on any plugin build. New
modules start path-based streams under the vendor path. The agent documentation describes
the mechanism and its limits.

A bundle that can't be shadowed starts path-based streams under its inline path, and the
agent warns with `policy-stream-forked`. This happens when its `extends` source is an
absolute (local) path, or when a plugin also loads the source or a second bundle on the same
path.

## Authored `policy_id` (optional)

A module can choose its stream explicitly:

```rego
package compliance_framework.ssh_deny_password_auth

import rego.v1

policy_id := "ssh-deny-password-auth"
title := "SSH denies password authentication"
```

- `policy_id` must be a single, unconditional rule whose value is a non-empty string
  literal of at most 512 characters. No two policies a plugin loads may share one.
- The API checks it statically when an agent configuration is saved and on playback
  (`policyeval.CheckContract`), and checks evaluated results too
  (`policyeval.ValidateResult`). The agent checks it again across all of a plugin's policy
  paths before it applies a configuration.
- `policyeval.SeedPath(policyID, policyFile, policyPath)` returns the seed values the
  plugin uses. Without a `policy_id`, or with one equal to the module's own `policy_file`,
  the seed is unchanged, byte for byte. Any other ID gives a stream that does not depend on
  where the bundle lives.
- Only the seed changes. Evidence keeps the real `_policy_path` label and gains a
  `_policy_id` label.
- **Plugin support.** Only plugins built against agent ≥ v0.9.0 honour it. Older plugins
  ignore it and keep path-based seeds, and the agent warns with
  `plugin-lib-policy-id-unsupported`.

## Plugin compatibility

The agent reads each plugin's agent-library version from its Go build info and reports it
as `plugins[].lib-version` in config reports. The value is empty when the version is
unknown: no build info, or a `replace` or devel build.

Plugins built against an agent library older than v0.7.1 crash on `violation contains
{...}`. The agent rejects such a module for those plugins with
`plugin-lib-violation-set-unsupported`, or only warns when the version is unknown.
`violation[{...}] if { ... }` works with every library.

## Codes

`PolicyError.code` values (constants in `pkg/agentconfig`):

| Code | Produced by | Severity | Meaning |
| --- | --- | --- | --- |
| `invalid-policy-id` | API, agent | error | `policy_id` is not a constant, non-empty string literal of at most 512 characters. |
| `duplicate-policy-id` | API, agent | error | Two modules checked together declare the same `policy_id`. |
| `duplicate-policy-identity` | agent | error, or warning from the config file | One plugin loads the same evidence identity from two policy paths. |
| `policy-package-changed` | agent | warning | An override changes the package of the module it replaces, which starts a new stream. |
| `plugin-lib-violation-set-unsupported` | agent | error, or warning when the version is unknown | A set-form `violation` for a plugin whose agent library is older than v0.7.1. |
| `plugin-lib-policy-id-unsupported` | agent | warning | A `policy_id` for a plugin whose agent library ignores it. |
