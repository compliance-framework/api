# Authorization — OSS embedded Cedar engine

CCF's open-source authorization is **global RBAC on an embedded [Cedar](https://www.cedarpolicy.com/)
engine** (cedar-go, in-process). It enforces the **full** API surface (every resource in the
authorization manifest); what the OSS engine gates is policy *expressiveness*, not coverage —
the bundled policies decide on `subject.role × action × resource.type` (the "C0" attribute
class). Attribute-rich (ABAC/ReBAC) policy is an Enterprise / bring-your-own-PDP concern.

> Design: *Per-Resource Evaluation Attribute Surface* (BCH-1319, §11) and *Pluggable
> Authorization — Design Plan*. Ticket: BCH-1316.

## Engines (the `authz.driver` config)

| Driver    | What it is                                                              |
| --------- | ---------------------------------------------------------------------- |
| `builtin` | **Default.** Pre-authz rules: authenticated = allowed, admin via SSO groups. The `agent` resource (agent reads and remote configuration) also requires the admin check for users; agent service accounts are allowed. |
| `cedar`   | Embedded Cedar RBAC against the bundled role policies (this document).  |
| `authzen` | Delegate every decision to a remote AuthZen-compliant PDP (bring your own). |

Select the engine with `CCF_AUTHZ_DRIVER`. Cedar is **opt-in**; making it the default is a
separate migration (BCH-1330), so enabling it is an explicit, reversible choice.

```bash
CCF_AUTHZ_DRIVER=cedar
CCF_AUTHZ_ROLE_ASSIGNMENTS=authz-roles.yaml   # default; optional file
CCF_AUTHZ_CEDAR_POLICY_DIR=/etc/ccf/policies  # optional operator .cedar files
```

## Bundled roles

Four fixed global roles, `policy-author` and the agent service role (the manifest lists every role, e.g. `ssp-subscriber`), defined in the manifest's `roles:` block
(`internal/authz/manifest.yaml`) and compiled to Cedar policies at startup:

| Role          | Grants                                                                       |
| ------------- | ---------------------------------------------------------------------------- |
| `admin`       | Everything (all resources, all actions).                                     |
| `contributor` | Author content (OSCAL docs, risk/poam register, workflows, dashboards, evidence); read everything; no admin. |
| `auditor`     | Read everything; record evidence; maintain the risk/poam register.           |
| `viewer`      | Read everything; no writes.                                                  |
| `policy-author` | Viewer plus `agent:configure-policy`: edit inline policy bundles and plugin policy lists in agent configuration overlays, nothing else. |
| `agent`       | Service accounts: ingest evidence/heartbeats, register, sync their remote configuration. |

viewer, auditor, contributor and policy-author read agent configurations (including inline
Rego) through `"*": [read]`. This is intended; narrow it with an operator `forbid` policy if
needed. The instance reports (`base`/`effective`) are redacted, but the **overlay** is not:
`GET …/config` and `GET …/config/revisions/{rev}` return it verbatim so it can be edited, so a
literal secret typed into an overlay's `plugins.*.config` is readable by every `agent:read`
holder. Put secrets on the host and reference them with `${env:NAME}` placeholders instead
(R57).

Every bundled role, including `ssp-subscriber` (which has no `agent:read`), holds
`artifact:read`. Agents upload the policy trees they load, inline Rego included, as
artifacts and name them in their config reports, so `artifact:read` also exposes inline
Rego to anyone who knows a digest. This is documented rather than narrowed (R72); see
[artifacts](./artifacts.md#who-can-read-artifacts).

Cedar is **deny-by-default**: a subject with no assigned role is denied every request.

## Assigning roles (`authz-roles.yaml`)

Static, GitOps-friendly configuration mapping principals to one role. A subject's effective
roles are the **union** of its direct user grant and a grant for each group it belongs to.

```yaml
users:                 # by email (subject.id), case-insensitive
  alice@example.com: admin
  bob@example.com: auditor
groups:                # by group name (see note below)
  sec-team: admin
agents: agent          # role for all authenticated agents (default: agent)
```

A typo'd or unknown role name fails fast at startup. A missing file is tolerated (only agents
are then authorized); an empty assignment set logs a warning (all users denied).

> **Group-based assignment requires native groups (BCH-1328).** Until subjects carry a
> `groups` attribute (native CCF groups ∪ SSO groups), the `groups:` section is inert and
> direct `users:` assignment covers everyone. The wiring is already in place, so it goes live
> additively when BCH-1328 lands — no change to this engine.

## Extending beyond the four roles

Three escape hatches, all OSS, in increasing power:

1. **Author your own Cedar** — drop `.cedar` files in `CCF_AUTHZ_CEDAR_POLICY_DIR`. They are
   appended to the bundled role policies. Because Cedar is deny-by-default with `forbid`
   overriding `permit`, an operator file can both grant beyond the roles and carve `forbid`
   exceptions out of them — without editing CCF. Entities live in the `CCF::` namespace
   (`CCF::User`, `CCF::Role`, `CCF::Evidence`, `CCF::Action::"read"`, …); run
   `ccf authz export --format=cedar` for the schema.
2. **Bring your own PDP** — set `CCF_AUTHZ_DRIVER=authzen` and point CCF at any
   AuthZen-compliant PDP. CCF becomes the PEP only; you own the policies.
3. **Write your own driver** — implement `authz.PDP` and `authz.Register` it.
