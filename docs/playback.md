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
      "raw": { "title": "Root login is disabled", "violation": [{ "id": "root-login-enabled" }] },
      "issues": []
    }
  ],
  "issues": [],
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

- `issues` lists the policy contract problems in this result (see below).

`prints` holds `print()` output as `file:row: message`, capped at 1000 lines.

### Contract issues

The policy contract is what a `compliance_framework` package must produce for the agent to
record evidence and submit risk templates: a string `title` (unless `skip_reason` is set),
string `description`, `remarks` and `skip_reason`, `labels` as an object of strings,
`violation` as a set of objects with string `id`, `title`, `description` and `remarks`, and
`risk_templates` as an array of objects the API accepts. `pkg/policyeval` checks it in two
layers, and the response carries both. Issues never fail the request:

- `issues` at the top level comes from `CheckContract`, a static check of the request's
  modules. It finds literal type and shape mistakes, a package without a `title`, a
  `violation` written as an object rule (`violation[k] := v`), risk templates the API
  would reject, `violation_ids` no literal violation produces, and packages defined by
  more than one module (each module produces its own evidence).
- `results[].issues` comes from `ValidateResult`, a check of the evaluated values: a
  missing or empty title, violations without an `id`, and computed risk templates the API
  would reject.

Each issue is `{"file", "row", "col", "package", "severity", "code", "message"}`, with
`severity` `error` or `warning` and `code` one of `missing-title`, `empty-title`,
`conditional-title`, `missing-violation`, `contract-key-function`,
`contract-key-multi-value`, `invalid-type`, `invalid-violation-rule`, `invalid-violation`,
`violation-missing-id`, `invalid-risk-template`, `unknown-violation-id`,
`duplicate-package-module` or `no-output`. The same check runs on inline policy bundles
when an agent configuration is saved, where error-severity issues block the save.

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
