# Cascade Chat Conversation

  Note: _This is purely the output of the chat conversation and does not contain any raw data, codebase snippets, etc. used to generate the output._

### User Input

I want you to look at `plugin-dependabot` and `plugin-dependabot-policies` . today, they create evidence + risks based on the collection of vulnerabilities associated with no remediation (which is fine) - but I want to try extend this to cover all existing vulnerabilities individually (the existence of a vulnerability to be an alert itself). Can you see if that's possible? My main concern is how to mark that a specific vulnerability evidence is now passing - as we don't have enough info IIRC from the API to know when a vulnerability was resolved

*Updated todo list*

*Viewed [main.go](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go) *

*Viewed [main_test.go](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main_test.go) *

*Viewed [main_integration_test.go](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main_integration_test.go) *

*Viewed [full.json](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/examples/input/full.json) *

### Planner Response

Now let me look at the policies and the rest of the example data, plus check what fields the `DependabotAlert` struct provides.

*Viewed [full.json](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/examples/input/full.json) *

*Viewed [redacted.json](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/examples/input/redacted.json) *

*Viewed [critical_vulnerabilities.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/examples/policies/critical_vulnerabilities.rego) *

*Viewed [critical_vulnerabilities_test.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/examples/policies/critical_vulnerabilities_test.rego) *

*Listed directory [policies](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies) *

*Viewed [critical_vulnerabilities_count.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies/critical_vulnerabilities_count/critical_vulnerabilities_count.rego) *

*Viewed [critical_vulnerabilities_dismissal.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies/critical_vulnerabilities_dismissal/critical_vulnerabilities_dismissal.rego) *

*Viewed [vulnerability_patch_available.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies/vulnerability_patch_available/vulnerability_patch_available.rego) *

*Viewed [vulnerability_dismissal_count.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies/vulnerability_dismissal_count/vulnerability_dismissal_count.rego) *

*Viewed [vulnerability_dismissal_date.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies/vulnerability_dismissal_date/vulnerability_dismissal_date.rego) *

*Viewed [vulnerabilities_dismissed_by_security_team.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies/vulnerabilities_dismissed_by_security_team/vulnerabilities_dismissed_by_security_team.rego) *

*Viewed [medium_vulnerabilities_count.rego](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/policies/medium_vulnerabilities_count/medium_vulnerabilities_count.rego) *

### Planner Response

Let me check the go-github `DependabotAlert` struct to understand what fields are available from the API.

*Grep searched codebase*

*User accepted the command `grep -r "DependabotAlert" /Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/go.sum | head -1`*

*User accepted the command `find $(go env GOMODCACHE)/github.com/google/go-github -path "*/github/dependabot_alerts.go" 2>/dev/null | head -3`*

*Viewed [dependabot_alerts.go](file:///Users/gusfcarvalho/go/1.25.7/pkg/mod/github.com/google/go-github/v71@v71.0.0/github/dependabot_alerts.go) *

*Updated todo list*

### Planner Response

Now let me also quickly check the `examples/dismissed.json` in the policies repo to see what a dismissed alert looks like with the API data:

*Viewed [dismissed.json](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot-policies/examples/dismissed.json) *

### Planner Response

Now I have a complete picture. Here's my analysis:

---

# Feasibility Analysis: Per-Vulnerability Evidence in Dependabot Plugin

## Current Architecture

**`plugin-dependabot`** collects all alerts for a repo and passes the entire array as [DependabotData](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go:40:0-43:1) to OPA policies. Each policy evaluates the *aggregate* list:
- "Are there ≥2 open critical vulns?" → violation
- "Are there ≥5 open medium vulns?" → violation
- "Any critical open >5 working days?" → violation
- etc.

This produces **one evidence per policy per repo** — a repo-level compliance statement.

**`plugin-dependabot-policies`** has 10 policies, all operating on `input.alerts` as an aggregate.

## What the API Gives Us

The [DependabotAlert](file:///Users/gusfcarvalho/go/1.25.7/pkg/mod/github.com/google/go-github/v71@v71.0.0/github/dependabot_alerts.go:49:0-67:1) struct from `go-github/v71` has excellent state information:

| Field | Type | Description |
|---|---|---|
| `State` | `*string` | **`"open"`, `"fixed"`, `"dismissed"`** |
| `FixedAt` | `*Timestamp` | When the vuln was fixed (null if still open) |
| `DismissedAt` | `*Timestamp` | When dismissed |
| `AutoDismissedAt` | `*Timestamp` | When auto-dismissed |
| `Number` | `*int` | Stable per-repo alert ID |
| `SecurityAdvisory.GHSAID` | `*string` | e.g. `GHSA-265r-hfxg-fhmg` |
| `SecurityAdvisory.CVEID` | `*string` | e.g. `CVE-2024-40635` |
| `CreatedAt` | `*Timestamp` | When alert was created |

Your example data confirms this — fixed alerts have `"state": "fixed"` and a populated `fixed_at` field.

## Your Concern: Knowing When a Vuln is "Passing"

**Good news: you actually DO have enough data.** The API returns:

1. **`state: "open"`** → vulnerability exists and is unresolved → **failing**
2. **`state: "fixed"`** with `fixed_at` timestamp → vulnerability was remediated → **passing**
3. **`state: "dismissed"`** with `dismissed_at` timestamp → someone dismissed it → **passing** (or a different kind of policy question)

The key insight: **the current [FetchRepositoryDependabotAlerts](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go:185:0-197:1) call doesn't filter by state**. The `ListAlertsOptions.State` field is `nil`, so the GitHub API returns **all alerts** — open, fixed, and dismissed. The example data already shows this (alerts #7 through #1 in [full.json](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/examples/input/full.json:0:0-0:0) are all `"state": "fixed"` with `fixed_at` populated).

So the resolution lifecycle is:
- Alert appears → `state: "open"`, `fixed_at: null`
- Developer bumps dep → `state: "fixed"`, `fixed_at: "2024-12-17T14:45:16Z"`
- Alert never comes back as "open" for that same `number`

## Approaches for Per-Vulnerability Evidence

### Option A: New per-vuln policies (alongside existing aggregate ones)

Create new policies in `plugin-dependabot-policies` that iterate each alert individually and produce a violation per alert. The Rego `violation` rule already supports this pattern — each `some alert in input.alerts` match creates a separate violation entry.

Example new policy `open_vulnerability_alert.rego`:
```rego
violation[{"id": sprintf("vuln_open_%d", [alert.number])}] if {
    some alert in input.alerts
    alert.state == "open"
}
```

**Pro:** No changes needed to the plugin Go code. Policies just iterate individually.
**Con:** Evidence is still per-repo. The violation IDs would be dynamic (per-alert), but the evidence envelope (subjects, components, etc.) is per-repo. You'd get "repo X has violations for alert #9, #10" but it's still one evidence record.

### Option B: Restructure the plugin to emit per-vulnerability evidence

Change `plugin-dependabot` to loop over each alert individually and call [EvaluatePolicies](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go:272:0-402:1) with a single-alert input. Each evidence would have its own subject identity incorporating the alert number/GHSA ID.

**Requires:**
- New subject template like `dependabot-vulnerability` with identity keys `{repository, organization, ghsa_id}` or `{repository, organization, alert_number}`
- Loop in [Eval()](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go:91:0-172:1) to call [EvaluatePolicies](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go:272:0-402:1) per-alert instead of per-repo
- New policies that evaluate a single `input.alert` (singular) rather than `input.alerts` (array)

**Pro:** Each vulnerability gets its own evidence trail, risk, and lifecycle.
**Con:** More API/CCF evidence volume. Breaking change for existing policies. Needs both plugin and policy changes.

### Option C: Hybrid — keep aggregate + add per-vuln

Keep existing aggregate evidence (repo-level) but **also** emit individual per-vulnerability evidence records. The plugin would:
1. Run existing policies with full [DependabotData](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go:40:0-43:1) (aggregate) → repo-level evidence
2. For each alert, run per-vuln policies with single-alert data → per-vuln evidence

**This is the most flexible approach** and is non-breaking.

## The "Passing" Question — Solved

For per-vulnerability evidence:
- **Each run** the plugin fetches all alerts (open + fixed + dismissed)
- A per-vuln policy like "this vulnerability is open" would:
  - **Violate** when `alert.state == "open"`
  - **Not violate** (= passing) when `alert.state == "fixed"` or `alert.state == "dismissed"`
- The CCF evidence for that specific vulnerability (keyed by `alert.number` or `GHSA ID`) flips from failing → passing naturally

**The only caveat:** once a vulnerability is fixed, it stays in the API response as `state: "fixed"` indefinitely. So each run you'd re-confirm it as "passing." If GitHub ever removes old fixed alerts from the listing, you'd stop producing evidence for it — but it wouldn't flip back to "failing" either; it would just have no new evidence. That's arguably correct behavior (the vuln no longer exists to evaluate).

## Recommendation

**Option C (Hybrid)** is the cleanest path. Specifically:

1. **In `plugin-dependabot`:** Add a second loop in [Eval()](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-dependabot/main.go:91:0-172:1) that, after the repo-level policy eval, iterates each alert and runs per-vuln policy paths against a `SingleAlertData` struct. Add a new subject template for individual vulnerabilities.

2. **In `plugin-dependabot-policies`:** Add a new set of per-vuln policies (e.g., `open_vulnerability/`, `vulnerability_sla/`) that operate on `input.alert` (singular). These produce a violation when the alert is open, and pass when it's fixed/dismissed.

3. **Stable identity key:** Use `{repository, organization, alert_number}` — the `number` is stable and unique per repo. Optionally include `ghsa_id` for human readability.

---

Want me to start implementing this (Option C hybrid), or would you prefer a different approach? Also — should I start with the plugin changes, the policies, or both in parallel?

### User Input

1- I want per vuln policies to be even a different repo - so this way this is an optional package users can adhere to or not.

2 - I'd rather go with option B where this behavior is configured. i.e. if `collection_granularity=repo` or something like that it keeps the current behavior; if `collection_Granularity=alert` it changes the behavior to trigger policy per alert. 

3 - on the per vuln policies, what I would like the most is to have one risk template that _maps_ to the correct CVE. For that you can leverage labels to create templated fields, like `impact_hint: {{ .alert_severity }}` where the plugin emits a `alert_severity=<CVE_severity>` as a label to this evidence. LMK if you have questions in this one because this is the coolest thing I wanted to do with it :)

### Planner Response

Let me understand the policy-manager's risk template mechanism before planning.

*Found code context*

### Planner Response

Let me dig deeper into the proto definitions and understand how risk templates connect to evidence in the API.

*Updated todo list*

*Viewed [result.go](file:///Users/gusfcarvalho/repos/cs/ccf/agent/policy-manager/result.go) *

*Grep searched codebase*

*Grep searched codebase*

*Grep searched codebase*

*Viewed [types.proto](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/proto/types.proto) *

### Planner Response

Let me check how the API consumes risk templates and matches them with evidence to understand the full pipeline.

*Found code context*

### Planner Response

Now I have the full picture of the pipeline. Let me share my findings and the key question on point 3.

## Understanding the Full Pipeline

The flow is:
1. **Init** → policy `risk_templates` are extracted and upserted to the API DB (static, no evidence context yet)
2. **Eval** → plugin runs policies against data, produces evidence with labels + violation props
3. **API Worker** → `RiskEvidenceWorker` matches evidence to risk templates via `_policy` label + `_violation_id` props, then creates/updates risks

Key detail in `@/Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:488-506`:
```go
newRisk := risks.Risk{
    Title:       riskTemplate.Title,
    Description: riskTemplate.Statement,
    // ...
}
if riskTemplate.LikelihoodHint != nil {
    newRisk.Likelihood = riskTemplate.LikelihoodHint
}
if riskTemplate.ImpactHint != nil {
    newRisk.Impact = riskTemplate.ImpactHint
}
```

**Currently no template resolution exists** — fields are copied verbatim from the risk template to the risk.

## The Dedupe Problem (Important!)

The risk dedupe key is computed as `ssp_id:risk_template_id` (`@/Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:414-416`). With your vision of **one risk template** for all vulnerabilities, every per-alert evidence would match the **same** risk template, producing the **same** dedupe key, and all alerts would collapse into **one risk per SSP**.

For one-risk-per-CVE, the dedupe key needs to incorporate something from the evidence — like the GHSA ID or alert number. This means the API worker needs a way to know "for this template, include these evidence labels in the dedupe key."

## What's Needed Across the Stack

| Layer | Change |
|---|---|
| **`plugin-dependabot`** | Config toggle `collection_granularity`, per-alert loop, rich labels (`alert_severity`, `cve_id`, `ghsa_id`, `alert_number`, `package_name`, `alert_state`) |
| **New policy repo** | Single risk template with templated fields, simple policy that triggers on `alert.state == "open"` |
| **`agent/policy-manager`** | No changes needed — labels already flow from plugin → evidence |
| **API `RiskEvidenceWorker`** | (1) Template resolution: resolve `{{ .label_name }}` in risk template fields using evidence labels. (2) Dedupe key enhancement: risk templates need a way to declare "include these evidence label keys in my dedupe key" |

## Question on Point 3

The template resolution (`impact_hint: "{{ .alert_severity }}"`) and the per-CVE dedupe both need **API-side changes**. Two options:

1. **Risk template declares dedupe labels** — e.g. a new field `dedupe_label_keys: ["ghsa_id", "repository"]` in the Rego `risk_templates`. The API worker would append those evidence label values to the dedupe key: `ssp_id:template_id:GHSA-xxx:org/repo`. This keeps it generic and reusable.

2. **Evidence-scoped risk identity** — the plugin itself emits a "risk scope" label that the worker always includes in the dedupe key.

I think option 1 is cleaner — the policy declares its own deduplication semantics. The risk template in the per-vuln policy would look something like:

```rego
risk_templates := [{
    "name": "open_vulnerability_alert",
    "title": "Open Dependabot Vulnerability: {{ .ghsa_id }}",
    "statement": "Vulnerability {{ .cve_id }} ({{ .alert_severity }}) ...",
    "likelihood_hint": "{{ .alert_severity }}",
    "impact_hint": "{{ .alert_severity }}",
    "violation_ids": ["vulnerability_open"],
    "dedupe_label_keys": ["ghsa_id", "repository", "organization"],
    "threat_refs": [...]
}]
```

**Does this align with your vision?** Specifically:
- Is `dedupe_label_keys` (or similar) the right approach for per-CVE risk creation?
- Should I start with the plugin-dependabot changes + new policy repo now, and tackle the API template resolution separately?

### User Input

look at the subject template resolver code. I think we need to start with these API changes first. We should make them similar i.e. also add a label schema to the risk_templates in order to validate the template itself, etc.

### Planner Response

Let me look at the subject template resolver code to understand the existing pattern for template resolution and label schemas.

*Updated todo list*

*Found code context*

### Planner Response

Now let me look at the API side — how subject templates are stored, resolved, and how the label schema + template fields work there.

*Found code context*

### Planner Response

Now let me also check the agent-side policy-manager code for how subject templates are extracted from Rego and how `GetSubjectTemplates` works, to understand the full pattern.

*Grep searched codebase*

*Grep searched codebase*

*Viewed [grpc.go](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/grpc.go) *

### Planner Response

Now let me look at the existing risk template validation and upsert code in the API to understand the current pattern:

*Viewed [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go) *

### Planner Response

Let me check the remaining part of that file and also the agent-side [UpsertRiskTemplates](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/grpc.go:16:1-16:74) to see how risk templates flow from agent to API:

*Viewed [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go) *

*Viewed [result.go](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/result.go) *

### Planner Response

Let me check the SDK types and proto conversion for risk templates:

*Grep searched codebase*

*Grep searched codebase*

*Viewed [types.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/sdk/types/types.go) *

*Viewed [util.go](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/util.go) *

### Planner Response

Now I have a complete picture of the subject template pattern and how risk templates need to evolve to match. Let me update the plan and present the design.

*Updated todo list*

### Planner Response

# Design: Templated Risk Templates (Mirroring Subject Template Pattern)

Here's the full design based on studying both patterns. Let me confirm alignment before implementing.

## Subject Template Pattern (the reference)

The existing subject template has:

| Concept | Subject Template Field | Purpose |
|---|---|---|
| **Static identity** | `Name` | Fallback if no template |
| **Template fields** | `TitleTemplate`, `DescriptionTemplate`, `PurposeTemplate`, `RemarksTemplate` | Go `text/template` strings rendered with evidence labels |
| **Identity keys** | `IdentityLabelKeys` | Which label keys form the entity's unique identity (used for deduplication) |
| **Label schema** | `LabelSchema []{ Key, Description }` | Declares valid label keys; templates are validated against this |
| **Selector** | `SelectorLabels` | Which evidence this template applies to (label matching) |

**Validation**: `validateTemplateAgainstSchema()` parses `{{ .fieldName }}` references and verifies each exists in `LabelSchema`. Identity keys must be a subset of label schema keys.

**Resolution**: `renderTemplate()` uses Go `text/template` with `missingkey=zero`, passing evidence labels as `map[string]string`.

## Proposed Risk Template Changes

Following the same pattern:

| Concept | New Risk Template Field | Purpose |
|---|---|---|
| **Static fields (keep)** | `Title`, `Statement`, `LikelihoodHint`, `ImpactHint` | Backward-compatible defaults; existing risk templates unchanged |
| **Template fields (new)** | `TitleTemplate`, `StatementTemplate`, `LikelihoodHintTemplate`, `ImpactHintTemplate` | Optional Go template strings; when present, override static fields at risk creation |
| **Dedupe keys (new)** | `DedupeLabelKeys` | Analog of `IdentityLabelKeys` — which evidence label keys to include in the risk dedupe key |
| **Label schema (new)** | `LabelSchema []{ Key, Description }` | Declares valid label keys; templates + dedupe keys validated against this |

### Key behaviors

1. **Backward compatible**: existing risk templates have no `LabelSchema`, no template fields, no `DedupeLabelKeys` → everything works exactly as today
2. **Template resolution** happens in `RiskEvidenceWorker.createNewRiskForSSP()`:
   - Build `labelMap` from evidence labels (reuse `buildEvidenceLabelMap`)
   - If `TitleTemplate` is set → `renderTemplate(titleTemplate, labelMap)` → use as risk `Title`
   - Otherwise → use static `Title` (current behavior)
   - Same for `Statement`, `LikelihoodHint`, `ImpactHint`
3. **Enhanced dedupe key**: when `DedupeLabelKeys` is present:
   - `ssp_id:risk_template_id:key1=val1:key2=val2` (sorted, deterministic)
   - When absent → current `ssp_id:risk_template_id`
4. **Validation** (on upsert):
   - `DedupeLabelKeys` must be subset of `LabelSchema` keys
   - Template fields validated against `LabelSchema` using existing `validateTemplateAgainstSchema()`
   - Static `LikelihoodHint`/`ImpactHint` still validated as risk levels
   - `LikelihoodHintTemplate`/`ImpactHintTemplate` validated as templates (NOT as risk levels — resolved value depends on runtime data)

### Example: per-vulnerability risk template in Rego

```rego
risk_templates := [{
    "name": "open_vulnerability_alert",
    "title": "Open Dependabot Vulnerability",
    "title_template": "Open Vulnerability: {{.ghsa_id}}",
    "statement": "A dependency vulnerability exists",
    "statement_template": "Vulnerability {{.ghsa_id}} ({{.alert_severity}}) in {{.package_name}} — {{.advisory_summary}}",
    "likelihood_hint_template": "{{.alert_severity}}",
    "impact_hint_template": "{{.alert_severity}}",
    "violation_ids": ["vulnerability_open"],
    "dedupe_label_keys": ["ghsa_id", "repository", "organization"],
    "label_schema": [
        {"key": "ghsa_id", "description": "GitHub Security Advisory ID"},
        {"key": "cve_id", "description": "CVE identifier"},
        {"key": "alert_severity", "description": "Vulnerability severity (critical/high/medium/low)"},
        {"key": "package_name", "description": "Vulnerable package name"},
        {"key": "advisory_summary", "description": "Security advisory summary"},
        {"key": "repository", "description": "GitHub repository name"},
        {"key": "organization", "description": "GitHub organization"},
    ],
}]
```

### Change set across repos

| Repo | Changes |
|---|---|
| **API** (start here) | Model: new columns + `RiskTemplateLabelSchemaField` child table. Validation: template fields against schema, dedupe keys subset. Worker: `renderTemplate` + enhanced dedupe key. Migration. |
| **API SDK** | [types.RiskTemplate](file:///Users/gusfcarvalho/repos/cs/ccf/api/sdk/types/types.go:180:0-193:1): add template fields + dedupe keys + label schema |
| **Agent proto** | [types.proto](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/proto/types.proto:0:0-0:0): add `RiskTemplateLabelSchema` message + new fields on [RiskTemplate](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/proto/types.proto:216:0-227:1) |
| **Agent policy-manager** | [result.go](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/result.go:0:0-0:0): add fields to [RiskTemplate](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/proto/types.proto:216:0-227:1) struct. `policy-manager.go`: map new fields in `newProtoRiskTemplate` |
| **Agent runner** | [util.go](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/util.go:0:0-0:0): update [RiskTemplateProtoToSdk](file:///Users/gusfcarvalho/repos/cs/ccf/agent/runner/util.go:254:0-273:1) |

Does this design look right? Anything you'd change before I start implementing in the API?

*Viewed [collector.go](file:///Users/gusfcarvalho/repos/cs/ccf/plugin-k8s/collector.go) *

*User accepted the command `git pull origin main`*

*User accepted the command `rm eks-readonly-*`*

*User accepted the command `git status`*

*User accepted the command `git checkout -b gc-feat-templeatable-risk-templates`*

*User accepted the command `git status`*

### User Input

you can start.

### Planner Response

I see you've created the branch `gc-feat-templeatable-risk-templates` on the API repo. Let me start implementing.

*Updated todo list*

### Planner Response

Let me first read the full models.go to understand the current DB model structure, then check how the SDK risk template upsert client works:

*Viewed [models.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/models.go) *

*Grep searched codebase*

*Grep searched codebase*

*Viewed [risk_template.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/sdk/risk_template.go) *

*Viewed [types.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/sdk/types/types.go) *

### Planner Response

Now let me check the API handler for the batch upsert endpoint and the migration setup:

*Grep searched codebase*

*Grep searched codebase*

*Viewed [migrator.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/migrator.go) *

*Viewed [risk_template.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/api/handler/templates/risk_template.go) *

*Viewed [migrate.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/tests/migrate.go) *

### Planner Response

Good, I have the full picture. Let me start implementing layer by layer.

## Step 1: Model changes

*Edited relevant file*

### Planner Response

Now add the `RiskTemplateLabelSchemaField` model definition, following the same pattern as [SubjectTemplateLabelSchemaField](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/models.go:126:0-132:1):

*Edited relevant file*

### Planner Response

Now register the new model in migrations:

*Edited relevant file*

*Edited relevant file*

### Planner Response

Now update the test migrator:

*Edited relevant file*

### Planner Response

Now update the test migrator [Down()](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/tests/migrate.go:200:0-370:1) as well:

*Edited relevant file*

*Updated todo list*

### Planner Response

## Step 2: Service layer — payloads, validation, batch items, fingerprinting

Now I need to update [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:0:0-0:0) with the new fields across all the relevant structs and add validation logic. This is a large file so I'll make targeted edits.

*Edited relevant file*

### Planner Response

Now update the [Create](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/api/handler/templates/risk_template.go:171:0-198:1), [List](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:108:0-145:1) (preloading), [fetchRiskTemplateByID](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:666:0-676:1), validation, normalization, [batchItemToPayload](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:868:0-884:1)/[batchItemFromPayload](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:886:0-899:1), fingerprinting, and create/update functions. Let me do these systematically.

First, update [List](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:108:0-145:1) and [fetchRiskTemplateByID](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:666:0-676:1) to preload `LabelSchema`:

*Grep searched codebase*

*Grep searched codebase*

### Planner Response

Now update [List](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:108:0-145:1) to preload LabelSchema, and [fetchRiskTemplateByID](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:666:0-676:1):

*Edited relevant file*

### Planner Response

Now update the [Create](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:152:0-234:1) method to persist the new fields, and update normalization + validation:

*Edited relevant file*

### Planner Response

Now I need to find and update the [Create](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:152:0-244:1) method's label schema persistence (after threat refs), and the [Update](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/api/handler/templates/risk_template.go:227:0-261:1) method similarly. Let me find where threat refs are created after the main row:

*Viewed [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go) *

### Planner Response

Now add label schema persistence in [Create](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:152:0-244:1) (after [replaceThreatRefs](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:362:0-383:1)), and update [Update](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:236:0-302:1) to handle new fields:

*Edited relevant file*

### Planner Response

Now add the `replaceRiskTemplateLabelSchema` helper function and the validation logic. Let me find where [replaceThreatRefs](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:377:0-398:1) is defined to add the new function nearby:

*Viewed [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go) *

### Planner Response

Now add `replaceRiskTemplateLabelSchema` right after [replaceThreatRefs](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:362:0-383:1), and update validation + normalization:

*Edited relevant file*

### Planner Response

Now update the validation function to handle the new fields:

*Edited relevant file*

### Planner Response

Now update the normalization function and fingerprinting. Let me find the normalize function:

*Viewed [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go) *

*Edited relevant file*

### Planner Response

Now update the fingerprinting functions to include the new fields. Let me read them:

*Viewed [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go) *

*Viewed [risk_template_service.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go) *

### Planner Response

Now I need to update [batchItemToPayload](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:868:0-884:1), [batchItemFromPayload](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:902:0-915:1), [createRiskTemplateInTx](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:1061:0-1113:1), [updateRiskTemplateInTx](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/risk_template_service.go:1115:0-1157:1), the fingerprint struct, and both FP functions. Let me do these in batches:

*Edited relevant file*

*Edited relevant file*

### Planner Response

Now update the fingerprint struct and both FP functions to include the new fields:

*Edited relevant file*

*Updated todo list*

### Planner Response

Now let me fix the Delete method to clean up label schema, and update BatchUpsert to preload LabelSchema and clean up on delete:

*Edited relevant file*

### Planner Response

Now update BatchUpsert to preload LabelSchema and clean up on delete:

*Edited relevant file*

### Planner Response

Now update the BatchUpsert delete path to also clean up label schema:

*Edited relevant file*

### Planner Response

Now let me update the handler layer. Let me read the full handler file:

*Viewed [risk_template.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/api/handler/templates/risk_template.go) *

*Viewed [risk_template.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/api/handler/templates/risk_template.go) *

*Viewed [risk_template.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/api/handler/templates/risk_template.go) *

### Planner Response

Now update the handler layer with the new fields across all request/response types and mapping functions:

*Edited relevant file*

### Planner Response

Now update the BatchUpsert handler to map the new fields:

*Edited relevant file*

### Planner Response

Now update [mapRiskTemplateToResponse](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/api/handler/templates/risk_template.go:504:0-551:1) to include the new fields:

*Edited relevant file*

### User Input

Continue

### Planner Response

Now update the SDK types and then do a compile check:

*Updated todo list*

*Viewed [types.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/sdk/types/types.go) *

*Edited relevant file*

### Planner Response

Now let me compile check the API:

*User accepted the command `cd /Users/gusfcarvalho/repos/cs/ccf/api && go build ./...`*

### Planner Response

Clean compile. Now let me move to the RiskEvidenceWorker to add template resolution and enhanced dedupe key.

*Viewed [risk_evidence_worker.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go) *

*Viewed [risk_evidence_worker.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go) *

*Viewed [risk_evidence_worker.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go) *

*Viewed [risk_evidence_worker.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go) *

### Planner Response

Now I have the full picture of the worker. The key changes needed are:

1. **[computeDedupeKeyForSSP](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:411:0-415:1)** — include evidence labels from `DedupeLabelKeys`
2. **[createNewRiskForSSP](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:481:0-541:1)** — resolve template fields before creating the risk
3. **[loadRiskTemplates](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:257:0-306:1)** — also preload `LabelSchema`

Let me implement these:

*Edited relevant file*

### Planner Response

Now update the [computeDedupeKeyForSSP](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:412:0-416:1) to include evidence labels from `DedupeLabelKeys`, and update [createNewRiskForSSP](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:482:0-542:1) to resolve template fields:

*Edited relevant file*

### Planner Response

Now update the [computeDedupeKeyForSSP](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:412:0-416:1) function signature and implementation to include evidence labels:

*Edited relevant file*

### Planner Response

Now add template field resolution to [createNewRiskForSSP](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:508:0-568:1). I need to look at how subject templates resolve their templates to mirror that pattern:

*Found code context*

### Planner Response

Now update [createNewRiskForSSP](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go:482:0-542:1) to resolve template fields before creating the risk:

*Edited relevant file*

### Planner Response

Now add the `resolveRiskTemplateFields` method:

*Viewed [risk_evidence_worker.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go) *

*Viewed [risk_evidence_worker.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/worker/risk_evidence_worker.go) *

*Edited relevant file*

### Planner Response

The `renderTemplate` function in `template_renderer.go` is unexported. I need to add a public wrapper:

*Viewed [template_renderer.go](file:///Users/gusfcarvalho/repos/cs/ccf/api/internal/service/relational/templates/template_renderer.go) *

*Edited relevant file*