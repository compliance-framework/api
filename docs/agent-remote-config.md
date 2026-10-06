# Agent remote configuration

An admin can change a running agent's configuration from the API instead of editing the
file on its host. The API stores an **overlay** per agent: an RFC 7396 JSON merge patch
(snake_case, the agent's config file format) that the agent merges over its own file:
`effective = MergePatch(file, overlay)`. Omitting a key keeps the file's value; `null`
deletes it so the agent's default applies. An empty overlay (`{}`, revision 0) means the
agent runs from its file.

Every save appends a numbered **revision**; revisions are never edited or deleted, except
when the agent itself is deleted. Agents poll for the current revision, decide on their
own whether to apply it, and report what they run. The host keeps the last word: its
`remote_config` block decides what an overlay may change, and that block can never be set
remotely.

The shared model (merge, validation, classification, redaction, digests, ETags) is
`pkg/agentconfig`, which the agent imports too. Design IDs cited in the code (`D3`, `R48`,
`O11`, ...) are defined in `compliance-framework/local-dev`:
`docs/agent-remote-config-design.md` and `docs/agent-remote-config-lld-api.md`.

## Routes

Agent-facing routes accept agent JWTs only, never a user token or an anonymous caller (even
with public agent endpoints on), and need `agent:sync`. An agent only reads and reports on
its own configuration.

| Route | Status codes |
| --- | --- |
| `GET /api/agent/config` | `200` the current overlay `{revision, overlay, created-at}` with an `ETag`; `304` when `If-None-Match` matches; `401`, `403`, `500`. A `404` means the API predates remote configuration. |
| `PUT /api/agent/instances/{instanceId}/config-report` | `204` stored; `400` invalid instance ID or report (for example an unknown mode or status, a malformed digest, a base or effective that is not an object, or a NUL character anywhere); `401`, `403`; `409` instance cap reached (back off); `413` body over 4 MiB; `415` not JSON; `500`. |
| `POST /api/agent/heartbeat` | An authenticated heartbeat with a well-formed `config_digest` (sent when the mode is not `off`) also records `config_revision`/`config_digest` and registers the instance. This is authorized by `heartbeat:ingest`, not `agent:sync`. |

Admin routes take a user token. Reads need `agent:read`; saving, reverting and preview need
`agent:configure`. With the default `builtin` authz driver both require the admin check.
Every admin route returns `400` for a malformed agent ID, `403` without the permission and
`404` for an unknown agent.

| Route | Status codes |
| --- | --- |
| `GET /api/admin/agents/{id}/config` | `200` current revision with `ETag: "<revision>"`. |
| `PUT /api/admin/agents/{id}/config` | `201` new revision; `200` the overlay is semantically unchanged (nothing is created); `400` malformed body (including data after the JSON object), missing `overlay`, or a comment over 2000 characters or containing a NUL; `409` stale `If-Match`, body has `current-revision`; `413` body over 1 MiB; `415` not JSON; `422` validation errors; `428` `If-Match` missing or not a plain revision number. |
| `POST /api/admin/agents/{id}/config/preview` | `200` validation and a per-instance preview, problems included (it never saves); `400`, `413`, `415`. |
| `GET /api/admin/agents/{id}/config/revisions` | `200` revisions newest first, without overlays; `page` (default 1) and `limit` (default 50, max 100). |
| `GET /api/admin/agents/{id}/config/revisions/{rev}` | `200` one revision; `404` unknown revision. |
| `POST /api/admin/agents/{id}/config/revisions/{rev}/revert` | Saves revision `rev`'s overlay as the next revision (`revert-of` records it). Same `If-Match`, validation and status codes as `PUT`; the body (`{"comment": ...}`) is optional. |
| `GET /api/admin/agents/{id}/instances` | `200` one page of instance summaries, most recently seen first; `page` (default 1) and `limit` (default 25, max 25; a larger limit is capped). `meta.desired-revision` and `meta.counts` cover all of the agent's instances; `meta.page`, `meta.limit`, `meta.total` and `meta.total-pages` describe the page. `400` invalid `page` or `limit`. |
| `GET /api/admin/agents/{id}/instances/{instanceId}` | `200` the summary plus the redacted `base` and `effective` configs; `404` unknown instance. |

The CORS configuration allows the `If-Match` and `If-None-Match` request headers and exposes
`ETag`, so a browser client can run both flows below.

## Saving: ETag and If-Match

1. `GET …/config` returns the current revision and `ETag: "7"` (the plain revision number,
   `"0"` before the first save).
2. `PUT …/config` with `If-Match: "7"` (`W/"7"` and `7` are accepted too) and
   `{"overlay": {...}, "comment": "..."}`.
3. If another save happened meanwhile, the answer is `409` with `current-revision`: reload,
   reapply the change and retry. Without `If-Match` the answer is `428`.

A save validates the overlay on its own first (unknown keys, types, locked keys, plugin
names, schedules, `${env:}` placement, at most 256 KiB compact, no NUL). It then merges the
overlay over the reported base of every instance in the **validation set** and validates
the result:

- every fresh instance (seen within `CCF_AGENT_INSTANCE_STALE_AFTER`) in `apply_safe` or
  `apply_all` mode that reported a base;
- if there is none, the single most recently reported apply-mode instance, however old;
- if there is none either, only the overlay-level checks run (`standalone`).

Report-mode instances are never validated against. Instances that report the same base are
validated once and share the result. Only errors the overlay introduces block a save: an
error already present in `Merge(base, {})` comes from the host's own file and is returned as
a warning. A `422` body lists `overlay` errors and, per instance, `errors` and `warnings`.

Preview runs the same checks without saving, and shows per instance (fresh and stale) the
redacted effective config, its diff against what the instance runs now, the classified
changes and whether the agent would apply them (`will-apply`, `will-apply-reason`).
`validated` marks the instances a save validates against. Preview covers at most 50
instances and 16 MiB of reported config (validated instances first, then newest first);
`omitted-instances` counts the rest. A save still validates against the whole set.

## Polling: ETag and If-None-Match

The agent sends the `ETag` of the overlay it has as `If-None-Match`. When it still matches
the current revision the answer is `304`, and the API answers it without loading the
overlay. The agent ETag is opaque: send it back verbatim, never build one. It names the
stored revision row, not just its number, so a database reset or a re-created agent never
yields a false `304`.

## Apply modes and classification

An agent compares each new revision with its own file and classifies every changed path as
`safe`, `unsafe` or `forbidden`. Its mode (`remote_config.mode` in its file) decides what it
applies:

| Mode | Applies |
| --- | --- |
| `off` | Nothing (`mode-off`). The default without API credentials. |
| `report` | Nothing (`mode-report`), but reports what it runs. The default with credentials. |
| `apply_safe` | A revision whose changes are all safe; otherwise `unsafe-changes`. |
| `apply_all` | A revision with safe and unsafe changes. |

In both apply modes a revision with any forbidden change is refused (`forbidden-changes`),
and so is an invalid merged config (`invalid-config`). The classification, with its reason
codes:

| Change | Class |
| --- | --- |
| `api`, `daemon` or `remote_config` (locked keys; a save rejects them anyway) | forbidden, `locked-key` |
| `verbosity`, `agent_evidence.*` | safe, `logging` |
| A plugin's `schedule`, `labels`, `policy_behavior`, `protocol_version`, `policy_data`, or disabling it | safe, `data-only` |
| Removing a plugin or some of its `policies` | safe, `reduces-scope` |
| A plugin `source` or added `policies` entry already used by an enabled plugin of the file | safe, `already-used` |
| …that is a local path (not an OCI reference) | forbidden, `local-source-not-allowed`; unsafe, `new-local-source` in `apply_all` with `allow_local_sources` |
| …that matches `trusted_sources` | safe, `trusted-source` |
| …any other source | unsafe, `untrusted-source` |
| `plugins.<p>.config.<key>` matching `overridable_config_flags` | safe, `overridable-config-flag` |
| any other config value | unsafe, `config-not-overridable` |
| A config value with a new `${env:NAME}` reference | unsafe, `new-env-reference`; forbidden for `CCF_API_AUTH_*`, `forbidden-env-reference` |
| Re-enabling a plugin the file disables | unsafe, `reenables-plugin`, or safe when its source is trusted. Its sources and env references are classified as new ones, so a local source is forbidden unless `apply_all` allows local sources. |

A new plugin takes the class of its parts. So by design `apply_safe` lets an admin change
the policy inputs that decide pass/fail (`policy_data`) or stop a plugin, with no host
opt-in.

The host's `remote_config` block holds these settings. It is set locally only (file, host
environment or CLI flags), never by an overlay:

| Setting | Default | Meaning |
| --- | --- | --- |
| `mode` | `report` with credentials, `off` without | See above. |
| `poll_interval` | `60s` | How often the agent polls; at least `15s`. |
| `trusted_sources` | `[]` | `path.Match` globs of plugin and policy sources an overlay may introduce safely, for example `ghcr.io/compliance-framework/*`. Case-sensitive; `*` does not cross `/`. A local path is never trusted. |
| `overridable_config_flags` | `[]` | Plugin config keys an overlay may change safely: `<plugin-glob>:<key-glob>`, or `<key-glob>` for any plugin, for example `ssh:port`. |
| `allow_local_sources` | `false` | Lets `apply_all` run local-path plugin and policy sources an overlay introduces. |

Preview classifies with each instance's reported `remote_config` block and its reported
mode, so it shows what each agent would do.

## Instances

An instance is one running agent process (agents send an instance UUID). It is registered
by its first config report, or by an authenticated heartbeat that carries a config digest.
The list shows, per instance, the derived `status` (`applied`, `rejected`, `failed` and
`not-applicable` as reported; `pending` when an apply-mode instance has not attempted the
current revision yet; `unknown` before its first report), the `sync-status` (`in-sync`,
`out-of-sync`, `not-applicable` in report or off mode, `unknown`), `stale` (not seen within
`CCF_AGENT_INSTANCE_STALE_AFTER`) and `report-stale` (its heartbeat digest no longer matches
its last report).

**Cap.** An agent has at most `CCF_AGENT_MAX_INSTANCES` instances that are not yet eligible
for pruning. A new instance at the cap replaces the oldest stale one, since a restarted
agent gets a new instance ID. When every counted instance is fresh, a report from a new
instance gets `409` and its heartbeats are not recorded (logged at most once a minute per
agent). Existing instances keep reporting.

**Pruning.** A periodic worker job deletes one-shot instances (`daemon: false`) not seen for
`CCF_AGENT_INSTANCE_ONESHOT_RETENTION` and every other instance not seen for
`CCF_AGENT_INSTANCE_RETENTION`. It needs the worker service and runs at most hourly.
Deleting an agent deletes its instances and revisions.

**Report bounds.** The API caps what a report stores and marks the instance `truncated`:
plugins, warnings and unsafe changes by count, every one of their strings (warning codes and
change safety and reason included, cut to 64 bytes rather than rejected, so a newer agent's
values still fit), the error text, hostname and version by length, and the reported
`remote_config` (at most 100 `trusted_sources` and 100 `overridable_config_flags`, each at
most 256 bytes encoded, dropped rather than cut; about 64 KiB in all). On top of these caps,
the summary fields as a whole (hostname, version, error, warnings, unsafe changes, plugins and
`remote_config`) are kept within 3 MiB as the instance list encodes them, JSON escaping
included (`<`, `&` and control characters take six bytes each): over that, the API drops the
last entries of the largest list and cuts the error text until the report fits. A plain-text
report at every cap is about 2.9 MB and is stored unchanged. The instance list returns these
summary columns, without the base and effective configs, so with pages of 25 instances a page
is about 75 MiB at most, whatever the reports contain. Its counts are computed from the
instances' status columns alone.

## Who sees secrets

- **The agent** receives its own overlay verbatim: it has to apply it.
- **Overlays on the admin routes** (`GET …/config`, `GET …/config/revisions/{rev}`) are
  verbatim only for callers that also hold `agent:configure`, so they can edit them. Every
  other `agent:read` holder gets them redacted (secret-like keys and values become `••••`),
  and so does every caller when the `agent:configure` check cannot be evaluated. The
  revision list never includes overlays.
- **Reported configs** (`base` and `effective` on the instance detail, and the effective
  config in preview) are always redacted. The agent redacts them and the API redacts them
  again as a best effort. Report free text that contains a secret (the error, warning
  messages, plugin sources, unsafe change values, `remote_config` strings) is replaced with
  `••••`.

Editors and every stored revision keep literal values, so put `${env:NAME}` placeholders in
`plugins.<p>.config` values instead of secrets: the agent resolves them from its host
environment, and `CCF_API_AUTH_*` can never be referenced.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CCF_AGENT_INSTANCE_STALE_AFTER` | `10m` | An instance seen (report or heartbeat) within this window is fresh: saves validate against it, and a full cap cannot replace it. |
| `CCF_AGENT_INSTANCE_RETENTION` | `720h` | Daemon (or unknown) instances not seen for this long are pruned. |
| `CCF_AGENT_INSTANCE_ONESHOT_RETENTION` | `24h` | One-shot (`daemon: false`) instances not seen for this long are pruned. |
| `CCF_AGENT_INSTANCE_PRUNE_ENABLED` | `true` | Schedules the prune job (needs the worker service). |
| `CCF_AGENT_INSTANCE_PRUNE_SCHEDULE` | `0 17 * * * *` | River cron (6 fields, seconds first) of the prune job. It runs at most hourly; a more frequent schedule is not honored. |
| `CCF_AGENT_MAX_INSTANCES` | `500` | Non-prunable instances per agent; see the cap above. |

A value that is unset or not positive takes the default.
