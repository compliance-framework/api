# Saved evidence filter badges: API specification

Status: implemented. The model, the `filter:publish` action, the preview route
(`GET /api/filters/{id}/badge.svg`) and the public route
(`GET /api/public/badges/{slug}.svg`) are in place; the renderer lives in
`internal/badge`.

## Purpose and scope

Let an administrator explicitly publish a saved evidence filter's aggregate
compliance state as an API-rendered SVG that can be embedded in a README.
Publishing is an opt-in setting on the saved filter, not an anonymous endpoint
that accepts arbitrary evidence labels or filter expressions.

With this feature, the public badge route is the only supported anonymous view
of a filter's aggregate. The JSON `compliance-by-filter` endpoint is not intended
for anonymous use; its current anonymous access under builtin with public agent
endpoints enabled is expected to go away. Do not build integrations on it.

Saved filters are inexpensive and already support SSP scope, scope-following,
and control/component associations. Reuse those objects rather than introducing
a parallel badge-query model.

The API owns lookup, aggregation, SVG rendering, and cache headers. No
shields.io integration, external badge service, worker, or additional runtime is
required. Neither badge endpoint returns individual evidence.

## Existing implementation to reuse

- [Filter routes and request handling](../internal/api/handler/filter.go):
  `POST /api/filters`, `PUT /api/filters/:id`, and authenticated filter reads.
- [Filter model](../internal/service/relational/filters.go): the persisted
  predicate, SSP binding, scope-following base, and associations.
- [ComplianceByFilter](../internal/api/handler/evidence.go):
  `GET /api/evidence/compliance-by-filter/:id` loads a saved filter and calls
  `GetStatusCountsByFilters(filter.Filter.Data())`.
- [Evidence service](../internal/service/relational/evidence/service.go):
  `GetStatusCountsByFilters` uses the latest-evidence query, applies the saved
  predicate, and groups counts by `status->>'state'`.
- [Authorization manifest](../internal/authz/manifest.yaml) and
  [builtin driver](../internal/authz/builtin.go): contributors have filter
  create/update rights under Cedar; builtin currently permits ordinary filter
  actions for every authenticated caller. Neither is sufficient authority to
  publish data.

## Filter settings and persistence

Add a nested `badge` object to filter create/update requests and authenticated
filter responses. For example, these are the new fields within an otherwise
valid filter request:

```json
{
  "badge": {
    "enabled": true,
    "label": "compliance",
    "slug": "payments-service"
  }
}
```

| Field | Contract |
| --- | --- |
| `enabled` | Boolean; defaults to `false` on creation and for existing filters. |
| `label` | Plain-text left-hand badge label; defaults to `compliance`. Trim surrounding whitespace; require 1–64 Unicode code points and reject control characters. |
| `slug` | Nullable public identifier. Required when enabled; `null` clears it and disables publication. |

Slug rules:

- Require 1–63 ASCII characters matching
  `^[a-z0-9]+(?:-[a-z0-9]+)*$`: lowercase words separated by single hyphens.
  Reject invalid input rather than silently lowercasing or rewriting it.
- Slugs are human-readable, not secrets or authorization credentials. They
  must not contain confidential identifiers.
- Enforce uniqueness across all filters, including disabled ones, with a
  partial unique index on non-null `badge_slug`.
- Store absent slugs as SQL `NULL`, never an empty string. Reject `""`.
- Changing or clearing a slug removes the old public mapping in the same
  transaction. There are no aliases or redirects.

Suggested columns on `filters` are `badge_enabled` (non-null, default false),
`badge_label` (non-null, default `compliance`), and nullable `badge_slug`.
Keep storage columns out of the flat JSON shape; expose only `badge`.
Add a database check that an enabled badge has a non-null slug.

### Write semantics and compatibility

- `POST /api/filters` without `badge` creates an unpublished filter.
- `PUT /api/filters/:id` without `badge` preserves all existing badge settings,
  so older clients do not accidentally publish or unpublish.
- Within a supplied `badge` object, omitted fields retain their current values
  on update and use their defaults on creation.
- An explicit `badge: null` resets settings to disabled, label `compliance`,
  and no slug. An explicit `slug: null` disables publication while retaining
  the label. Reject `enabled: true` combined with `slug: null`.
- `enabled: false` alone disables publication but retains the slug reservation
  and label. Re-enabling the same retained slug intentionally restores its
  existing embeds.
- A new slug can be reserved while disabled, allowing preview and review before
  publication. Never enable implicitly just because a slug is present.
- Settings, any affected filter fields, and slug reservations are committed
  atomically after validation and authorization. A rejected request must not
  partially change associations or publication state.
- Imports, clones, and automatically generated filters start unpublished with
  no slug; they must not copy publication settings from another filter.

Return the existing JSON response envelopes and create/update success codes.
Use `400` for invalid settings, `403` for missing publish authority, and `409`
for a conflicting slug. Map database uniqueness violations to the same `409`
as pre-validation, including concurrent requests.

### Revocation and slug reuse

Disabling, clearing/changing the slug, or deleting the filter makes subsequent
origin requests to the old public URL return `404`. Changing a slug never
redirects an existing embed to its replacement.

A slug is reserved only while a filter holds it, published or not. Changing or
clearing the slug, or deleting its filter, frees it; a later claim by any filter
is allowed. Disabling without clearing retains the slug. The partial unique
index on `filters.badge_slug` protects these reservations; no tombstone table
is needed.

Revocation removes the current mapping, not the URL forever. If a freed slug is
later claimed and enabled, existing embeds of that URL display the new holder's
aggregate. There are still no redirects or aliases.

This is origin revocation, not erasure: the API cannot retract previously
downloaded SVGs, screenshots, or copies cached by external image proxies.

## Publishing permission

Introduce action `publish` on resource `filter` (`filter:publish`):

- Add its action constant to [pdp.go](../internal/authz/pdp.go), declare it on
  `filter` in the manifest, and keep manifest/export/permission-discovery
  contracts consistent.
- Cedar's default admin role receives it through its existing wildcard grant.
  Do not add it to contributor, auditor, viewer, or agent roles.
- Add an explicit builtin rule delegating `filter:publish` to the existing
  user-admin check. Do not let it fall through to builtin's ordinary
  authenticated-request allow. Keep single and batch evaluation consistent.
- AuthZEN/custom policy operators must explicitly grant the new action.

The existing create/update permission remains required. Additionally require
`filter:publish` whenever a request changes badge settings, including reserving
or changing a slug, enabling, disabling, clearing, or changing the label.
An identical settings round trip is not a publication change.

Because changing a published filter's selection changes what is disclosed,
also require publish authority for changes made through the filter routes to
its effective predicate, SSP binding, or scope-following configuration while it
is enabled. This prevents a caller with only filter update rights from
broadening a published filter through those routes. Reject the entire
unauthorized write before any mutation.
Unrelated metadata/association edits retain existing authorization unless they
change the evidence selection.

A published badge is a live view: new evidence and SSP scope updates affect it
without another publication request. Editing an SSP's scope never requires
`filter:publish`; it retains its existing SSP authorization, and a scope-following
badge reflects scope changes as part of its live view. This behavior must be
made clear at publication time. Filter deletion retains its existing delete
permission and revokes the badge.

Enforce conditional publish checks through the existing PDP/PEP mechanisms,
not hard-coded role names in handlers. For every publication-sensitive write
through the filter routes, the publication-state read, authorization decision,
and write must form one atomic decision. Serialize competing writes (for
example, lock the filter row before checking and hold the lock until commit),
or use a versioned conditional write and roll back the entire transaction on
conflict (`409`). All competing filter-route writers, including enabling a
badge, must follow the same concurrency protocol.

A predicate write authorized only while disabled must not commit after another
transaction enables the badge: it must fail without mutation. Evaluate
authorization before side effects against the state protected by that protocol,
not an earlier unlocked read. Slug claims/releases and affected associations
belong to the same transaction, with the unique index arbitrating concurrent
slug claims. This atomicity requirement does not add publish checks to SSP
scope edits. Publication checks must fail closed if the PDP is unavailable,
even if ordinary authorization is configured fail-open.

## SVG endpoints

| Route | Authentication and authorization | Behavior |
| --- | --- | --- |
| `GET /api/filters/:id/badge.svg` | User JWT, `filter:read`, and the same `evidence:read` authorization as `GET /api/evidence/compliance-by-filter/:id` | Preview by filter UUID, whether published or not and without requiring a slug. |
| `GET /api/public/badges/{slug}.svg` | Anonymous; no user or agent token required | Render only when the slug resolves to an existing filter with `badge.enabled = true`. |

The public URL shape is `/api/public/badges/{slug}.svg`. In Echo, register
`/api/public/badges/:file`, require the captured `file` to end in the literal
`.svg` suffix, strip that suffix, and validate the remaining slug. Return the
generic public `404` for a missing suffix or invalid slug. Do not register
`:slug.svg`: Echo treats the entire `slug.svg` as the parameter name and does
not enforce that suffix.

Register preview in the existing authenticated filter group with both the
filter-read and evidence-read guards. Use the same evidence authorization
semantics as the JSON compliance endpoint; `filter:read` alone must not disclose
evidence-derived state, even for an enabled badge.

Register public badges in a separate, deliberately anonymous group in
[RegisterHandlers](../internal/api/handler/api.go). Do not attach optional agent
authentication, an evidence-read guard, or an anonymous `filter:read` grant.
The narrowly scoped publication lookup is the public access gate.

Public badges are available regardless of
`StrictDisablePublicAgentEndpoints`. This flag controls existing agent-facing
exposure, not explicitly published filter badges. Do not broaden access to
filter JSON, evidence, artifacts, or other routes.

No query parameter may override the predicate, SSP scope, label, slug, or
aggregation. Reject unsupported query parameters with `400`.

### Responses and errors

- Success: `200`, `Content-Type: image/svg+xml; charset=utf-8`, raw SVG bytes,
  not a JSON response envelope.
- Preview: `400` for a malformed UUID; existing JWT behavior for unauthenticated
  requests; `403` if either read permission is denied; `404` for an unknown filter.
- Public: `404` for a missing `.svg` suffix, invalid/unknown slug, or a slug with
  no enabled holder (including after clearing, disabling, or deletion), with
  the same generic response shape for each case. A freed slug may be reclaimed
  and published as described above.
- Database/aggregation/rendering failures: log internally and return a generic
  `500` using the API error helper. Never render a green badge or pretend that
  a failure means no evidence.
- Error responses use standard API JSON errors, not SVG, and are not cached.

## Aggregation and rendering

Both endpoints share one lookup/aggregate/render path after their different
access checks. Reuse `GetStatusCountsByFilters` directly; do not make an HTTP
request to the JSON compliance endpoint or duplicate its query logic.

Per render, perform the necessary saved-filter/publication lookup and one
grouped evidence query. Do not load individual evidence, iterate over evidence
in application code, or add one query per status. Preserve existing
latest-stream, deduplication, and effective-filter semantics, including saved
scope-following predicates. Do not infer additional evidence constraints from
control/component associations or SSP metadata that the existing endpoint
does not apply.

The SVG shows the configured label and one aggregate state:

| Aggregate counts | Display text | Color |
| --- | --- | --- |
| No matching evidence | `no evidence` | Gray |
| Any `not-satisfied` evidence | `failing` | Red |
| Nonempty result, all evidence `satisfied` | `passing` | Green |
| Otherwise, including unknown/empty states | `unknown` | Gray |

Failure takes precedence over unknown states. Do not silently drop unfamiliar
states or treat them as satisfied. This is a rollup of recorded evidence, not
an attestation, certification, or guarantee of freshness. Do not introduce a
different expiry rule from the existing compliance aggregation.

V1 publishes only the label and aggregate state, not counts, percentages,
evidence IDs, titles, labels, props, timestamps, filter UUIDs/predicates, SSP
details, control/component identifiers, or links to authenticated resources.
Keep SVG metadata and accessible text limited to the same disclosure.

Use a small deterministic SVG template with bounded dimensions and escaped
text in every insertion context. Include readable text and an accessible
label/title so color is not the sole signal. No scripts, event handlers,
`foreignObject`, external images/fonts, remote URLs, or embedded credentials.
Set `X-Content-Type-Options: nosniff` and a restrictive SVG-compatible CSP
(`default-src 'none'; style-src 'unsafe-inline'; sandbox`).

## Caching and revocation boundary

Set cache policy in the API, not in an external badge service:

- Authenticated preview: `Cache-Control: private, no-store`.
- Public SVG: `Cache-Control: public, no-cache, max-age=0, must-revalidate`.
  This permits storage but requires origin revalidation before reuse; do not
  add `stale-while-revalidate` or `stale-if-error`.
- All error responses: `Cache-Control: no-store`.

V1 need not implement ETags. If conditional responses are added, check the
current publication mapping before considering `304`, and compute validators
from the current rendered representation. An old validator must never bypass
revocation.

Origin requests begun after a revocation transaction commits must observe it.
Already in-flight responses and external caches are outside that guarantee.
Do not add an in-process publication/result cache: independent caches across API
replicas could continue serving a revoked mapping after commit. Each origin
request must check the current mapping.
GitHub's image proxy may cache independently; document that no cache header can
guarantee immediate removal from an already-rendered GitHub README.

## Embedding and deployment

```markdown
![Compliance](https://api.example.com/api/public/badges/payments-service.svg)
```

Only the public slug URL is suitable for anonymous embeds; never embed an
access token or the authenticated preview URL.

Badges render only where the API is reachable. On github.com, GitHub's image
fetcher must be able to reach the public route over the internet, normally
over HTTPS. A private-network-only API will not render there. Operators may
expose only this path through their ingress without exposing authenticated
API data. Publishing a badge does not configure DNS, TLS, firewall, or ingress.

No CORS change is needed for an ordinary Markdown/image embed. The API currently
has no HTTP rate limiting. Operators must rate-limit `/api/public/badges/` at
the ingress before exposing it: each render performs an aggregate query, and
the revalidation policy can send every proxy hit back to the origin. Do not
assume an existing API limiter or add an in-process result cache as a substitute.

## Implementation and verification checklist

1. Add model fields, defaults, validation, the partial unique index, and
   migrations in the production and test migrators.
   Existing filters must all migrate unpublished.
2. Extend filter requests/responses and conditional publish authorization;
   preserve existing clients and ensure imports/automatic filters stay private.
3. Add `filter:publish` to the vocabulary and enforce the builtin/Cedar/remote
   policy behavior described above.
4. Add the authenticated preview and independent public route, shared aggregate
   renderer, safe SVG template, and response headers.
5. Add handler annotations and run `make swag`; do not hand-edit generated
   Swagger files.
6. Add focused tests covering:
   - Defaults, omitted/null settings, label/slug validation, duplicate slugs,
     concurrent claims, and transactional rollback.
   - Publish allowed for admin, denied for ordinary contributors, and not
     implied by builtin filter update; single/batch permission parity and
     fail-closed publication during PDP failure.
   - Unauthorized changes to a published predicate/scope, unchanged settings
     round trips, and compatibility with older request bodies; an SSP scope
     edit without `filter:publish` still updates a scope-following badge.
   - Concurrent predicate changes and badge enablement: an update authorized
     only while disabled must not commit after publication. Include slug
     claims/releases and verify conflicts leave no partial mutations.
   - Preview before publication and after disabling; user JWT enforcement,
     success with both read permissions, and `403` when either one is missing;
     public success with no token under both values of the strict-agent flag.
   - `404` after disable, rename, clear, or deletion until a freed slug is
     reclaimed and enabled; reuse by the same or another filter succeeds,
     while disabled filters retain their slugs. No redirect, alias, or
     conditional-cache bypass.
   - Public filename routing: valid `.svg` URLs work; missing suffixes,
     invalid slugs, and unsupported query parameters are rejected as specified.
   - Parity with the existing compliance query for latest evidence, overlapping
     matches, and effective SSP-following filters; one grouped evidence query.
   - Passing, failing, mixed, empty, and unknown states; database failures;
     XML escaping, bounded SVG output, forbidden-content absence, and headers.
   - No individual evidence or filter details in SVG text, metadata, or errors;
     no regressions in existing filter/evidence access.
7. Run targeted unit/integration tests and lint. Integration tests require
   Docker; compile integration-tagged code when shared helpers change.
   Before deployment, verify ingress rate limiting on the public badge path
   and revocation visibility across API replicas.

UI controls and permission hints can consume this contract in a separate UI
change. They must explain that enabling a badge publishes a live aggregate and
that the label/slug are public. API authorization must remain sufficient even
without those UI controls.
