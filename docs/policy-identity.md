# Policy identity (`policy_id`)

A policy module can declare which evidence stream it writes to with an optional
`policy_id`. Without one, nothing changes.

## Why

Plugins give each piece of evidence a UUID seeded from the policy's location:

```
SeededUUID({type: evidence, policy: <package>, policy_file: <policy path>/<file>}
           + plugin labels {type, hostname, _policy_path: <policy path>})
```

`<policy path>` is the literal string the agent passes to the plugin for the policy's
bundle. Relative paths stay relative and absolute paths stay absolute. For example:

- vendor OCI bundle: `.compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies`
- inline bundle: `/app/.compliance-framework/state/local-dev/inline/<bundle>/current/bundle`

So overriding a vendor policy in an inline bundle, bumping an OCI tag, renaming a bundle
or moving the agent's state directory each start a new evidence stream, and the history of
the old one stops. Agent and config labels (`_agent`, `_plugin`, `plugins.<p>.labels`) are
added after the UUID is computed, so they are not part of the seed.

## Declaring it

```rego
package compliance_framework.ssh_deny_password_auth

import rego.v1

policy_id := "ssh/ssh_deny_password_auth.rego"
title := "SSH denies password authentication"
```

`policy_id` must be a single, unconditional rule whose value is a non-empty string literal
of at most 512 characters, and no two policies a plugin loads may share one. The API
checks this statically (`policyeval.CheckContract`, run by playback and on inline bundles
when an agent configuration is saved) and on evaluated results (`policyeval.ValidateResult`).
The agent checks it again, across all of a plugin's policy paths, before it applies a
configuration.

## How plugins seed with it

`policyeval.SeedPath(policyID, policyFile, policyPath)` returns the two seed values. The
agent's `policy-manager` calls it, so the API, the agent and the UI agree:

- No `policy_id`: `policy_file` and `_policy_path` stay as they are, byte for byte. Every
  existing stream keeps its UUIDs.
- With a `policy_id`: `policy_file` is the `policy_id`. `_policy_path` is the `policy_id`
  without the module's bundle-relative path when the `policy_id` ends in `/<that path>`,
  and the `policy_id` itself otherwise. The bundle-relative path is taken literally: the
  file path is `<policy path>/<relative path>`. Nothing is cleaned or made absolute.

So there are two ways to use it:

- **Continue a stream.** A `policy_id` equal to the policy's old `policy_file` (the policy
  path the plugin used, a `/`, and the file) reproduces the old seed exactly. An override
  of a vendor policy can therefore keep writing to the vendor policy's stream. Config
  reports carry each policy path as `policy-bundles[].plugin-path`, and the UI pre-fills
  `policy_id := "<plugin-path>/<file>"` when it overrides a vendor module that has none.
- **A stable stream.** Any other `policy_id`, for example `ssh-deny-password-auth` or
  `<bundle>/<file>`, gives a stream that does not depend on where the bundle lives.

Evidence keeps the real `_policy_path` label, and the agent adds a `_policy_id` label. With
the bundle artifact digest and the config revision already on each record, it stays
auditable which rule version produced it.

## Lifecycle

| Change | Stream |
| --- | --- |
| Override a policy and keep its `policy_id` | Same stream; the results may change. |
| `delete` the policy | The stream stops receiving evidence. |
| Revert the override | Same stream. |
| Add a new policy | A new stream, from its own `policy_id`. |
| Publish it into a real bundle with the same `policy_id` | Same stream. |
| Change the `package` line of an overridden module | A new stream (the package is in the seed); the agent warns with `policy-package-changed`. |

## Compatibility

- **Plugins must be rebuilt.** Plugins seed evidence with the `policy-manager` they embed
  from `github.com/compliance-framework/agent`. Only plugins built against an agent library
  that includes `policy_id` support use it. Older plugins ignore it and keep path-based
  seeds, and the agent warns with `plugin-lib-policy-id-unsupported`.
- **Set-form violations.** Plugins built against an agent library older than v0.7.1 crash
  on `violation contains {...}`. The agent rejects such a module for those plugins with
  `plugin-lib-violation-set-unsupported`; `violation[{...}] if { ... }` works with every
  library.
- The agent reads each plugin's library version from its Go build info and reports it as
  `plugins[].lib-version` in config reports, so the UI can show compatibility before a save.
  It is empty when unknown (no build info, or a `replace` or devel build); then both checks
  are warnings.
- Agents and APIs without this feature still interoperate: the new report fields are
  optional, and evidence without `_policy_id` is unchanged.

## Codes

`PolicyError.code` values (constants in `pkg/agentconfig`, the first two also in
`pkg/policyeval`):

| Code | Produced by | Severity | Meaning |
| --- | --- | --- | --- |
| `invalid-policy-id` | API, agent | error | `policy_id` is not a constant, non-empty string literal of at most 512 characters. A `policy_id` written as a function or with `contains` is reported as `contract-key-function` or `contract-key-multi-value`. |
| `duplicate-policy-id` | API, agent | error | Two modules checked together (one inline bundle in the API; all of a plugin's policy paths in the agent) declare the same `policy_id`. |
| `duplicate-policy-identity` | agent | error, or warning when it comes from the config file | One plugin loads the same evidence identity (a `policy_id`, or a package and bundle-relative file) from two policy paths, so it would report it twice. |
| `policy-package-changed` | agent | warning | An override changes the package of the module it replaces, which starts a new stream. |
| `plugin-lib-violation-set-unsupported` | agent | error, or warning when the library version is unknown | A set-form `violation` for a plugin whose agent library is older than v0.7.1. |
| `plugin-lib-policy-id-unsupported` | agent | warning | A `policy_id` for a plugin whose agent library ignores it. |

## Reference

- `policyeval.Policy.ID` (JSON `id`): the evaluated `policy_id`, set only when valid.
- `policyeval.SeedPath`, `policyeval.ValidPolicyID`, `policyeval.MaxPolicyIDLength`.
- Playback results carry `policyId` ([playback.md](./playback.md)).
- Config reports: `policy-bundles[].plugin-path` and `plugins[]` (`name`, `source`,
  `lib-version`), returned on agent instances ([artifacts.md](./artifacts.md)).
