# Policy evaluation artifacts

An evaluation depends on three things: the policy bundle, the input data the plugin
collected, and the policy data configured on the agent. The agent uploads each as it has
them. The API converts each to a canonical form, stores it once under its SHA-256 digest,
and records the digests on the evidence the evaluation produced:

| Evidence prop | Artifact |
| --- | --- |
| `_policy_bundle_digest` | The policy bundle, as a canonical tar |
| `_policy_input_digest` | The input data, as canonical JSON |
| `_policy_data_digest` | The policy data, as canonical JSON (absent when none is configured) |

The API writes these props before signing the evidence, so the link from a result to what
produced it is covered by the evidence signature. Clients may not set them. With the three
artifacts, the evaluation can be replayed through
[`POST /api/playback/evaluate`](./playback.md).

Evidence without `policy-artifacts` is accepted as before, so agents that do not upload
artifacts keep working.

## Flow

1. The agent uploads each artifact to `POST /api/agent/artifacts` and gets back its digest.
   Content already stored is not stored again.
2. The agent creates the evidence with the digests:

   ```json
   {
     "uuid": "…",
     "title": "…",
     "policy-artifacts": {
       "bundle-digest": "sha256:…",
       "input-digest": "sha256:…",
       "policy-data-digest": "sha256:…"
     }
   }
   ```

   The API checks each digest names a stored artifact of the right kind, and rejects the
   evidence with `400` otherwise. `policy-data-digest` is optional.

## Canonical forms

`internal/artifact` defines them. Only the API computes digests, so uploaders never need
to match them:

- **Digest:** `sha256:` and 64 lowercase hex characters.
- **JSON** (`application/json`): any JSON value is accepted. It is stored with object keys
  sorted, no insignificant whitespace, no HTML escaping, and numbers kept exactly as
  written.
- **Policy bundle** (`application/vnd.ccf.policy-bundle.v1+tar`): a tar or gzipped tar is
  accepted. It is stored as an uncompressed tar of its regular files, sorted by path, with
  mode 0644, owner 0/0 and zero modification time. Links, paths that leave the bundle,
  duplicate paths and bundles OPA cannot read are rejected.

Stored digests must stay reproducible, so these forms are permanent. Golden tests in
`internal/artifact` fail if either changes.

## API

| Route | Auth | Behaviour |
| --- | --- | --- |
| `POST /api/agent/artifacts` | Agent token, or none while public agent endpoints are allowed | Canonicalises and stores the body. Returns `201` when stored, `200` when already present, with `{digest, mediaType, sizeBytes}`. |
| `GET /api/artifacts/{digest}` | Any user or agent token | Returns the canonical bytes with their media type. |
| `GET /api/artifacts/{digest}/files` | Any user or agent token | Lists the files of a policy bundle artifact (see below). |
| `GET /api/artifacts/{digest}/files/{path}` | Any user or agent token | Returns one file of a policy bundle artifact as source text (see below). |

Uploads take the same auth as the other agent ingest routes: an agent token, or none while
public agent endpoints are allowed (`CCF_STRICT_DISABLE_PUBLIC_AGENT_ENDPOINTS=false`), so
agents running without credentials can store the artifacts their evidence refers to.
Invalid content gets `400`. Bodies, and bundles once decompressed, over
`CCF_ARTIFACT_MAX_BYTES` (default 16 MiB) are rejected.

At most `CCF_ARTIFACT_MAX_CONCURRENT` uploads (default 8) are canonicalised and stored at
once, across all callers. The body is read before a slot is taken, so a slow uploader
cannot hold one. An upload waits up to 10 seconds for a slot, since agents upload in bursts
at the start of each scheduled run, and then gets `429`; the agent retries `429`.

The SDK wraps these as `client.Artifact.Upload` and `Get`; `Get` checks the content against
the digest. `types.Evidence.PolicyArtifacts` carries the digests on evidence create.

### Policy bundle files

The file routes read a stored policy bundle without downloading and unpacking the tar.
Both answer `400` for a malformed digest, `404` for an unknown digest (or, for a single
file, an unknown path), and `415` when the artifact is not a policy bundle.

`GET /api/artifacts/{digest}/files` lists every file, sorted by path:

```json
{
  "digest": "sha256:…",
  "treeDigest": "tree:sha256:…",
  "files": [
    { "path": "config/data.json", "sha256": "…", "size": 52 },
    { "path": "policy.rego", "sha256": "…", "size": 214, "package": "compliance_framework.ports" }
  ]
}
```

- `sha256` is the lowercase hex SHA-256 of the file, as in agent config reports.
- `package` is set for `.rego` files that parse (as Rego v1, or else v0), without the
  leading `data.`.
- `treeDigest` is `agentconfig.BundleTreeDigest` over the files: the digest an agent config
  report gives the same tree. The two digests stay separate. `digest` addresses the
  canonical tar; `treeDigest` the file map.

`GET /api/artifacts/{digest}/files/{path}` returns one file. `path` is the file's path as
listed; a `/` inside it may be sent as is or escaped as `%2F`:

```json
{ "path": "policy.rego", "package": "compliance_framework.ports", "sha256": "…", "source": "package compliance_framework.ports\n…" }
```

Files over 1 MiB, or that are not UTF-8 text, get `422`; download the artifact instead.

An artifact never changes, so both routes answer with `Cache-Control: private,
max-age=31536000, immutable` and an `ETag` (the digest of the response body), and answer
`If-None-Match` with `304`.

### Agent config reports

Agents that report artifact digests also upload the policy trees they load when they
apply a configuration, not only when they evaluate. A config report (`PUT /api/agent/instances/{id}/config-report`) names
each tree's artifact in `policy-bundles[].artifact-digest` and, for an inline bundle that
extends a source, the vendor tree's artifact in `policy-bundles[].extends.artifact-digest`.
The UI reads vendor sources through the file routes, for example to pre-fill an override.

The field is best effort: it is empty when the agent could not upload, and it is kept when
the agent drops `files` to fit the report size. The API checks its format only, not that
the artifact is stored, so a reader must handle `404`.

## Who can read artifacts

Every bundled authz role holds `artifact:read`, including `ssp-subscriber`, which has no
`agent:read`. Artifacts include the inline Rego agents upload (at evaluation since #464,
and with config reports, which add the vendor trees inline bundles extend). So a role
without `agent:read` can read an agent's inline policies through the artifact routes if
it knows their digests. Config reports, which hold the digests, need `agent:read`. This is
documented rather than changed (R72); operators who need to narrow it can add a Cedar
`forbid` on `artifact:read`.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CCF_ARTIFACT_MAX_BYTES` | `16777216` | Largest artifact accepted, in bytes. |
| `CCF_ARTIFACT_MAX_CONCURRENT` | `8` | Uploads canonicalised and stored at once, across all callers. |
