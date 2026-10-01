# Rego playback

`POST /api/playback/evaluate` evaluates a Rego policy against JSON input and returns the
outcome, exactly as an agent's policy-manager would produce it. Use it to replay a past
result, or to see how a change to a policy or its input moves the outcome, without
deploying a bundle or running an agent.

Evaluation uses `pkg/policyeval`, the same code the agent uses, so a result here means the
same as a result there. Nothing from the request is stored.

## Who can call it

Any caller: a user token, an agent token, or no token at all when public agent endpoints
are allowed. It uses the same authentication as `POST /api/evidence`, so setting
`CCF_STRICT_DISABLE_PUBLIC_AGENT_ENDPOINTS=true` refuses anonymous calls. Every bundled
authz role, including `agent`, holds `playback:execute`.

Agents can use the SDK:

```go
resp, err := client.Playback.Evaluate(ctx, sdk.PlaybackRequest{
	Policy: policySource,
	Input:  collectedData,
})
```

A policy that fails to parse, compile or evaluate returns `*sdk.PlaybackPolicyError`.

## Example

```shell
curl -s -X POST http://localhost:8080/api/playback/evaluate \
  -H 'Content-Type: application/json' \
  -d @- <<'JSON'
{
  "policy": "package compliance_framework.ssh_root_login\n\ntitle := \"Root login is disabled\"\n\nviolation contains {\"id\": \"root-login-enabled\"} if {\n\tprint(\"PermitRootLogin =\", input.sshd_config.PermitRootLogin)\n\tinput.sshd_config.PermitRootLogin == \"yes\"\n}\n",
  "input": { "sshd_config": { "PermitRootLogin": "yes" } }
}
JSON
```

```json
{
  "results": [
    {
      "package": "compliance_framework.ssh_root_login",
      "file": "policy.rego",
      "status": "not-satisfied",
      "title": "Root login is disabled",
      "description": null,
      "remarks": null,
      "skipReason": null,
      "labels": {},
      "violations": [{ "id": "root-login-enabled" }],
      "additionalVariables": { "title": "Root login is disabled" },
      "raw": { "title": "Root login is disabled", "violation": [{ "id": "root-login-enabled" }] }
    }
  ],
  "prints": ["policy.rego:6: PermitRootLogin = yes"],
  "durationMs": 4
}
```

## Request

| Field | Required | Meaning |
| --- | --- | --- |
| `policy` | yes | Rego source for the policy under test, stored as module `policy.rego`. |
| `modules` | no | Extra modules the policy imports, keyed by file name, for example `{"ccf_libs/helpers.rego": "package ccf_libs.helpers ..."}`. Packages outside `compliance_framework` are loaded for import only, never evaluated. |
| `input` | yes | Any JSON value, bound to `input`. |
| `data` | no | Policy data, merged into `data.*` as the agent merges its configured policy data. |
| `evaluatedAt` | no | RFC 3339 time that `time.now_ns()` returns, so time-based rules replay as they ran. Defaults to now. |

## Response

Each package under `compliance_framework` gives one result:

- `status` is `satisfied` (no violations), `not-satisfied` (any violation) or `skipped`
  (a non-empty `skip_reason`), the same rule the agent uses.
- `raw` is the package's full value from OPA, before interpretation.
- `error` is set when the agent would not record the result as evidence, for example
  `evidence title is required`.

`prints` holds `print()` output as `file:row: message`, capped at 1000 lines.

## Errors

| Status | When |
| --- | --- |
| `400` | Malformed JSON, or `policy` or `input` missing. |
| `413` | Body larger than `CCF_PLAYBACK_MAX_BYTES`. |
| `422` | The policy does not parse, compile or evaluate (`rego_parse_error`, `rego_type_error`, `eval_conflict_error`, ...), runs past the time limit (`eval_timeout`), or has no `compliance_framework` package (`no_policies`). The body is `{"errors": [{"code", "message", "file", "row", "col"}]}`. |
| `429` | `CCF_PLAYBACK_MAX_CONCURRENT` evaluations are already running. Retry shortly. |

## Sandbox

The policy runs inside the API process, so it is restricted:

- `http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed. A policy that calls
  one fails to compile with a `rego_type_error`.
- Modules come only from the request. Nothing is read from disk.
- Evaluation stops after `CCF_PLAYBACK_TIMEOUT`.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CCF_PLAYBACK_ENABLED` | `true` | Set `false` to remove the route. |
| `CCF_PLAYBACK_TIMEOUT` | `5s` | Time limit for one evaluation. |
| `CCF_PLAYBACK_MAX_BYTES` | `2097152` | Request body limit, in bytes. |
| `CCF_PLAYBACK_MAX_CONCURRENT` | `4` | Evaluations allowed at once, across all callers. |

## Playing back stored evidence

`GET /api/evidence/{id}/playback` replays the evaluation that produced a piece of evidence,
from the artifacts the agent stored for it (see [artifacts.md](./artifacts.md)), and
compares the result with what the evidence recorded. The UI shows it in the Overview tab of
evidence detail.

The API:

1. reads the evidence's `_policy_bundle_digest`, `_policy_input_digest` and
   `_policy_data_digest` props and its `_policy` label (the policy package);
2. loads the artifacts, unpacks the bundle, and layers the policy data over the bundle's own
   data documents, as the agent does;
3. replays every file of the bundle in the same sandbox as `/api/playback/evaluate`, with
   `time.now_ns()` pinned to the evidence's end time;
4. compares the replayed package's status and violation IDs with the evidence's recorded
   status and `_violation_id` props;
5. locates the `violation` rule behind each replayed violation (`policyeval.LocateViolations`).
   OPA merges all of a package's `violation` rules into one set, so each rule is copied under
   its own name, appended after the original source, and evaluated with the same input, data
   and time. Each copy's output is what its rule produced. Each replayed violation carries
   `rules`: `[{file, startLine, endLine}]`, 1-based lines in the stored file. Locating is
   best effort: if it fails, `rules` is empty and the violations are still returned.

The response carries the bundle files, the input, policy data and bundle data as
pretty-printed JSON strings (the input is cut at 1 MiB, with `inputTruncated`; the full
input is the input artifact), the recorded and replayed results, and the comparison:
`statusMatches`, `missingViolationIds` (recorded, not replayed), `newViolationIds` (replayed,
not recorded) and `unidentifiedViolations` (replayed without an ID).

- Evidence recorded without artifacts, or whose artifacts are not stored, returns `200`
  with `available: false` and a `reason`.
- A policy that cannot run in the sandbox (for example one calling `http.send`) returns the
  artifacts with `errors` and no `replay`.
- It needs any user or agent token, since the response contains the raw input, and shares
  the playback endpoint's time limit and concurrency limit (`429` when busy).
