# Policy identity

Plugins give each piece of evidence a UUID seeded from the policy's location:

```
SeededUUID({type: evidence, policy: <package>, policy_file: clean(<policy path>/<file>)}
           + plugin labels {type, hostname, _policy_path: <policy path>})
```

`<policy path>` is the literal string the agent passes to the plugin for the policy's
bundle. `policy_file` is OPA's cleaned join of that path and the file, while `_policy_path`
is the literal string. For example:

- vendor OCI bundle: `.compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies`
- inline bundle that is not shadowed: `.compliance-framework/policies/_inline/<bundle>/policies`

Agent and config labels (`_agent`, `_plugin`, `plugins.<p>.labels`) are added after the UUID
is computed, so they are not part of the seed.

## Path shadowing keeps vendor streams

When an inline bundle `extends` an OCI source, the agent gives it to plugins **at the
source's own path string** and changes only what that path resolves to. Inherited modules,
and overrides that keep the vendor module's package, therefore keep the vendor's evidence
streams, on any plugin build. New modules start path-based streams under the vendor path.
The agent documentation describes the mechanism and its limits.

The agent warns when streams fork:

- **The bundle can't be shadowed for a plugin.** The plugin receives it at its inline path,
  so its modules start new streams. The agent emits one `policy-stream-forked` warning per
  bundle and plugin (`bundle` set, no `path`) that gives the reason and lists the modules
  that fork. Reasons:
  - the `extends` path is absolute, or not a relative `policies/` tree (a local source);
  - the plugin also loads the source, or another bundle that extends the same source;
  - there is no writable state directory, or the file system has no symlinks;
  - another relative policy path of the plugin can't be placed in its view.
- **An authored override that changes the package forks even at the source's path.** The
  agent warns per module with `policy-package-changed`.

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
| `duplicate-policy-identity` | agent | error, or warning from the config file | One plugin loads the same evidence identity from two policy paths. |
| `policy-package-changed` | agent | warning | An override changes the package of the module it replaces, which starts a new stream. |
| `policy-stream-forked` | agent | warning | A bundle can't be shadowed for a plugin, so its listed modules start new streams. Defined by the agent, not in `pkg/agentconfig`. |
| `plugin-lib-violation-set-unsupported` | agent | error, or warning when the version is unknown | A set-form `violation` for a plugin whose agent library is older than v0.7.1. |
