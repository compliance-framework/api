# CCF Authorization Design

## Overview

This document describes the authorization (AuthZ) model for the Compliance Framework (CCF) API. The goal is to introduce a simple, opinionated Role-Based Access Control (RBAC) system that covers the common use cases out of the box, while exposing a standard [OpenID AuthZen](https://openid.net/wg/authzen/) interface so that organizations with more granular requirements can plug in their own Policy Decision Point (PDP).

---

## Motivation

The current API enforces authentication (JWT) on most routes but applies authorization only at the coarsest level: a user is either an admin (via `RequireAdminGroups` middleware) or they are not. There is no concept of per-resource scoping, least-privilege roles, or a path to delegating authorization decisions to an external system.

As CCF matures, the following gaps need to be addressed:

- Users should only be able to see and modify the SSPs they are assigned to.
- Automated agents should be able to submit evidence without any broader system access.
- Organizations with compliance or enterprise requirements need a clear upgrade path to fine-grained authorization (OPA, OpenFGA, Cerbos, etc.) without forking the API.

---

## Roles

### Design Principles

1. **Simple by default.** The built-in role set covers the vast majority of deployments. Roles are intentionally coarse — if an organization needs attribute-level or action-level granularity, they buy or build an AuthZen-compatible PDP.
2. **Least privilege for the common case.** A user gets the minimum access they need to do their job. The `admin` role is not a default.
3. **Agents are first-class principals.** Any valid agent JWT implicitly holds the `evidence:creator` capability. Agent identity and user identity are separate principal types.

### Role Catalogue

| Role | Scope | Capabilities |
|---|---|---|
| `admin` | Global | Full access to all resources, all operations, user and role management |
| `global:reader` | Global | Read all SSPs, evidence, risks, catalogs, POAM items |
| `global:writer` | Global | Create and modify content across all SSPs; create evidence |
| `global:risk-assessor` | Global | Create, update, and close risks across all SSPs; implies `global:reader` |
| `ssp:reader` | Per-SSP | Read one SSP and its associated evidence, risks, controls, POAM items |
| `ssp:writer` | Per-SSP | Create and modify content within one SSP; implies `ssp:reader` on that SSP |
| `ssp:risk-assessor` | Per-SSP | Create, update, and close risks within one SSP; implies `ssp:reader` on that SSP |
| `evidence:creator` | Global | Submit evidence via `POST /evidence`; no read access to any SSP implied |

> **Note on `ssp:writer` granularity:** The `ssp:writer` role grants write access to everything within an SSP — controls, implementation statements, tasks, POAM items. This is intentionally coarse. Organizations that need field-level or action-level granularity (e.g., separate approver vs. editor roles within an SSP) should implement or procure an AuthZen-compatible PDP and configure the external PDP URL (see [External PDP](#external-pdp)).

### Agent Identity

Agents authenticate via `AgentJWTMiddleware`. Any request carrying a valid agent JWT is implicitly authorized to create evidence (`POST /evidence`) and to read agent-specific endpoints (`/agent/heartbeat`, `/agent/risk-templates`, `/agent/subject-templates`). Agents do not hold user roles and are not stored in `user_role_bindings`.

---

## Data Model

A new table `user_role_bindings` captures role assignments:

```sql
CREATE TABLE user_role_bindings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role          TEXT        NOT NULL,
    resource_type TEXT        NULL,  -- e.g. "ssp"; NULL for global roles
    resource_id   UUID        NULL,  -- FK to the scoped resource; NULL for global roles
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ NULL,

    UNIQUE (user_id, role, resource_type, resource_id)
);
```

**Examples:**

| user_id | role | resource_type | resource_id |
|---|---|---|---|
| `alice-uuid` | `admin` | `NULL` | `NULL` |
| `bob-uuid` | `global:reader` | `NULL` | `NULL` |
| `carol-uuid` | `ssp:writer` | `ssp` | `ssp-uuid-1` |
| `carol-uuid` | `ssp:reader` | `ssp` | `ssp-uuid-2` |
| `dave-uuid` | `evidence:creator` | `NULL` | `NULL` |

Global roles have `NULL` in both `resource_type` and `resource_id`. SSP-scoped roles have `resource_type = 'ssp'` and a specific SSP UUID.

---

## AuthZen Interface

### What is AuthZen?

[OpenID AuthZen](https://openid.net/wg/authzen/) is a draft standard that defines a simple HTTP interface between a Policy Enforcement Point (PEP) — the API middleware — and a Policy Decision Point (PDP) — the component that evaluates whether access is permitted.

The evaluation request is:

```
POST /access/v1/evaluation
```

```json
{
  "subject":  { "type": "user",   "id": "alice@example.com" },
  "action":   { "name": "write" },
  "resource": { "type": "ssp",    "id": "550e8400-e29b-41d4-a716-446655440000" }
}
```

The response is:

```json
{ "decision": true }
```

### Internal PDP (Built-in)

CCF ships with a simple internal PDP that evaluates the `user_role_bindings` table. It is not exposed as an HTTP endpoint — it is called in-process by the authorization middleware.

**The `user_role_bindings` table is exclusively owned by the built-in PDP.** When an external PDP is configured, CCF never reads or writes this table for authorization decisions — it becomes unused for AuthZ purposes. Role bindings are only relevant in the built-in mode.

The built-in PDP evaluates using **prefix matching**: a role grants access to any action whose string starts with the role's resource prefix. For example, `ssp:writer` grants any action beginning with `ssp:` (e.g. `ssp:read`, `ssp:control-implementation:write`), but does **not** match `ssp:delete` — delete operations require an explicit grant.

The PDP checks:

1. Does the user have a global role whose prefix matches the requested action?
2. Does the user have a scoped role on this exact resource UUID whose prefix matches the requested action?
3. Is this an agent token? If so, the action is implicitly permitted on agent-accessible endpoints.

| Action prefix | Roles that grant it (global) | Roles that grant it (scoped) |
|---|---|---|
| `ssp:` (read/write, not delete) | `admin`, `global:reader`\*, `global:writer` | `ssp:reader`\*, `ssp:writer` (on matching SSP) |
| `risk:` (read/write, not delete) | `admin`, `global:reader`\*, `global:writer`, `global:risk-assessor` | `ssp:reader`\*, `ssp:writer`, `ssp:risk-assessor` (on matching SSP) |
| `risk:assess` (exact) | `admin`, `global:risk-assessor` | `ssp:risk-assessor` (on matching SSP) |
| `evidence:read` (exact) | `admin`, `global:reader`, `global:writer`, `global:risk-assessor` | — |
| `evidence:create` (exact) | `admin`, `global:writer`, `evidence:creator` | — |
| `user:` | `admin` | — |
| `template:` | `admin` | — |
| `ssp:delete`, `risk:delete`, `catalog:delete`, etc. | `admin`, `global:writer` | — |

\* read-prefixed roles only match `*:read` actions, not `*:write`.

### External PDP

When the environment variable `AUTHZEN_PDP_URL` is set, the authorization middleware forwards the evaluation request to that URL instead of running the internal PDP. The external PDP must implement the AuthZen `POST /access/v1/evaluation` contract.

**When an external PDP is active, the `user_role_bindings` table is not used.** CCF emits the AuthZen evaluation request — `(subject, action, resource{type, id})` — and the external PDP is solely responsible for the decision. The PDP may:

- Connect directly to CCF's database to inspect resource metadata.
- Maintain its own policy and relationship graph (e.g. OpenFGA tuples, SpiceDB relationships).
- Resolve SSP hierarchies, team memberships, attribute conditions, or any other model it needs.
- Combine data from multiple sources (IdP groups, CMDB, asset inventory).

CCF makes no assumptions about how the external PDP stores or resolves policy. It only guarantees it will send the leaf resource UUID and the most specific action string from the catalogue. **Hierarchy, inheritance, and relationship traversal are entirely the external PDP's concern.**

For example, if an operator models SSP inheritance (SSP-1 → SSP-2 → SSP-3) in OpenFGA, a role grant on SSP-1 can automatically propagate to SSP-2 and SSP-3 without any change to the CCF API. CCF sends the leaf UUID (`ssp-3-uuid`) and OpenFGA resolves the hierarchy internally.

This allows operators to plug in:

- **[OPA](https://www.openpolicyagent.org/)** (with an AuthZen shim) — policy-as-code, attribute-based rules
- **[OpenFGA](https://openfga.dev/)** — relationship-based access control (ReBAC), hierarchy traversal
- **[Cerbos](https://cerbos.dev/)** — policy-as-code with native AuthZen support
- **[SpiceDB](https://authzed.com/spicedb)** — Google Zanzibar-style ReBAC
- A CCF-provided commercial PDP for organisations that want a managed fine-grained AuthZ layer

The API does not change regardless of which PDP is in use. The enforcement logic stays in the middleware; only the decision-making is delegated.

```
┌──────────────────────────────────────────────────────────┐
│                        CCF API                           │
│                                                          │
│  HTTP Request                                            │
│      │                                                   │
│      ▼                                                   │
│  ┌─────────────┐    AuthZen evaluation request           │
│  │ AuthZ       │─────────────────────────────────────►  │
│  │ Middleware  │                                         │
│  │ (PEP)      │◄─────────────────────────────────────  │
│  └─────────────┘    { "decision": true/false }           │
│      │                                                   │
│      │  AUTHZEN_PDP_URL unset?                           │
│      ├── yes ──► Internal PDP (user_role_bindings table) │
│      └── no  ──► External PDP (OPA / OpenFGA / Cerbos)  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Middleware Design

The existing `JWTMiddleware` handles authentication and remains unchanged. A new `RequirePermission` middleware handles authorization and is applied per-route group.

### Action resolution

The middleware receives a **specific action name** and a **resource type** at registration time (see the Action Catalogue). The action name is always the most specific one from the catalogue — e.g. `ssp:control-implementation:write`, not the coarser `ssp:write`. This is what gets forwarded to the PDP, whether internal or external.

The resource ID cannot always be determined at middleware registration time — it lives in the request path (e.g. `:id`, `:sspId`). The middleware resolves it at request time from the Echo context using a configurable path parameter name.

```go
// Conceptual signature — not final code
//
// action:       the specific action string from the catalogue
// resourceType: the resource type string ("ssp", "risk", "evidence", ...)
// resourceParam: the Echo path param name holding the resource UUID, or "" for global resources
middleware.RequirePermission(db, cfg, logger,
    "ssp:control-implementation:write",  // action
    "ssp",                               // resource type
    "id",                                // resolved from c.Param("id") at request time
)

middleware.RequirePermission(db, cfg, logger,
    "evidence:create",
    "evidence",
    "",  // no resource scoping
)

middleware.RequirePermission(db, cfg, logger,
    "user:write",
    "user",
    "",
)
```

At request time, the middleware:

1. Reads `claims.Subject` (email) from the JWT stored in the Echo context by `JWTMiddleware`.
2. If `resourceParam` is non-empty, calls `c.Param(resourceParam)` to extract the resource UUID.
3. Constructs an AuthZen evaluation request with `(subject, action, resource{type, id})`.
4. Dispatches to the internal PDP or, if `AUTHZEN_PDP_URL` is set, to the external PDP.
5. Returns `403 Forbidden` if `decision: false`.

### Why the most specific action?

The action name the API sends is the **ceiling of granularity** for any PDP. If CCF sends `ssp:write` for all SSP mutations, an external PDP can never distinguish "write to control implementations" from "write to system characteristics" — it only sees `ssp:write`. By always sending the specific action (e.g. `ssp:control-implementation:write`), the API leaves the door open for external PDP policies to be as granular as needed.

The **built-in PDP** handles this by doing prefix matching on the role-to-action map: the `ssp:writer` role grants any action whose prefix is `ssp:`. This keeps built-in behaviour coarse while still sending the full action downstream.

```
Incoming action:  ssp:control-implementation:write
Built-in PDP:
  Does user have ssp:writer on this SSP?  → match on prefix "ssp:" → permit
  Does user have global:writer?           → match on prefix "ssp:" → permit

External PDP:
  Receives full action string → can apply policy at whatever grain it chooses
```

---

## Route Authorization Map

The table below shows the specific action sent to the PDP for key route groups. The built-in PDP resolves these via prefix matching against the user's role bindings. An external PDP receives the full action string and can apply whatever policy granularity it chooses.

`resourceParam` is the Echo path parameter name the middleware reads at request time to obtain the resource UUID. Empty means the action is global (no resource scoping).

| Route Group | Action sent to PDP | Resource type | `resourceParam` |
|---|---|---|---|
| `GET /evidence/:id` | `evidence:read` | `evidence` | `` |
| `POST /evidence/search` | `evidence:read` | `evidence` | `` |
| `POST /evidence` | `evidence:create` | `evidence` | `` |
| `GET /oscal/system-security-plans` | `ssp:read` | `ssp` | `` |
| `GET /oscal/system-security-plans/:id` | `ssp:read` | `ssp` | `id` |
| `POST /oscal/system-security-plans` | `ssp:write` | `ssp` | `` |
| `PUT /oscal/system-security-plans/:id` | `ssp:write` | `ssp` | `id` |
| `GET .../system-characteristics` | `ssp:system-characteristics:read` | `ssp` | `id` |
| `PUT .../system-characteristics` | `ssp:system-characteristics:write` | `ssp` | `id` |
| `GET .../control-implementation` | `ssp:control-implementation:read` | `ssp` | `id` |
| `PUT .../control-implementation/implemented-requirements/:reqId` | `ssp:control-implementation:write` | `ssp` | `id` |
| `DELETE /oscal/system-security-plans/:id` | `ssp:delete` | `ssp` | `id` |
| `GET /risks` | `risk:read` | `risk` | `` |
| `POST /risks` | `risk:write` | `risk` | `` |
| `POST /risks/:id/accept` | `risk:assess` | `risk` | `id` |
| `POST /risks/:id/review` | `risk:assess` | `risk` | `id` |
| `GET /poam-items` | `poam:read` | `poam` | `` |
| `POST /poam-items` | `poam:write` | `poam` | `` |
| `GET /admin/users` | `user:read` | `user` | `` |
| `POST /admin/users` | `user:write` | `user` | `` |
| `DELETE /admin/users/:id` | `user:delete` | `user` | `id` |
| `GET /agent/*` | implicit `evidence:create` | — | — |
| `POST /agent/heartbeat` | implicit `evidence:create` | — | — |
| `GET /workflows/definitions` | `workflow:read` | `workflow` | `` |
| `POST /workflows/definitions` | `workflow:write` | `workflow` | `` |
| `PUT /workflows/step-executions/:id/transition` | `workflow:action` | `workflow` | `id` |

---

## Action Catalogue

This section enumerates every action that the built-in PDP understands, derived directly from the current API handler surface. Actions map HTTP methods to semantic operation names. When new handlers are added to the API, a corresponding action **must** be registered in this catalogue and wired into the PDP's role-to-action table (see [Extending Actions](#extending-actions)).

### Action Naming Convention

```
<resource-type>:<verb>
<resource-type>:<sub-resource>:<verb>
```

- `read`   — safe, non-mutating retrieval (HTTP GET)
- `write`  — creation or update (HTTP POST / PUT / PATCH)
- `delete` — removal (HTTP DELETE)
- `action` — a named state-change that is neither pure write nor delete (e.g. `risk:assess`, `workflow:action`)

Resource types mirror the route group names (e.g. `ssp`, `risk`, `evidence`). The sub-resource segment is used when the route operates on a distinct nested resource within the parent — for example, `ssp:control-implementation:write` targets the control implementation sub-tree of an SSP rather than the SSP root.

**The action sent to the PDP is always the most specific string the API can compute from the route.** This is what allows an external PDP to apply fine-grained policies. The built-in PDP evaluates actions using prefix matching, so `ssp:writer` grants any action beginning with `ssp:` — the sub-resource segment is simply ignored by the built-in rules.

**Example:**

| Route | Action sent to PDP | Built-in PDP match | External PDP can distinguish |
|---|---|---|---|
| `PUT .../system-characteristics` | `ssp:system-characteristics:write` | `ssp:writer` (prefix `ssp:`) | yes — separate from control-implementation writes |
| `PUT .../control-implementation/implemented-requirements/:id` | `ssp:control-implementation:write` | `ssp:writer` (prefix `ssp:`) | yes — can allow one but deny the other |
| `DELETE /oscal/system-security-plans/:id` | `ssp:delete` | `ssp:writer` does **not** match `ssp:delete` (explicit mapping required) | yes |

Note that `delete` is **not** covered by the `ssp:write` prefix rule in the built-in PDP. Delete operations require an explicit role grant (only `admin` and `global:writer` carry `ssp:delete`). This is intentional — it prevents a coarse `ssp:writer` scoped role from being able to delete the entire SSP.

---

### Evidence

| Action | HTTP | Route |
|---|---|---|
| `evidence:read` | GET | `/evidence/:id` |
| `evidence:read` | GET | `/evidence/history/:id` |
| `evidence:read` | GET | `/evidence/latest/:id` |
| `evidence:read` | POST | `/evidence/search` |
| `evidence:read` | GET | `/evidence/for-control/:id` |
| `evidence:read` | GET | `/evidence/status-over-time/:id` |
| `evidence:read` | POST | `/evidence/status-over-time` |
| `evidence:read` | GET | `/evidence/compliance-by-control/:id` |
| `evidence:read` | GET | `/evidence/compliance-by-filter/:id` |
| `evidence:create` | POST | `/evidence` |

---

### System Security Plans (SSP)

All routes under `/oscal/system-security-plans`. SSP-scoped roles are evaluated against the `:id` path parameter.

| Action | HTTP | Route |
|---|---|---|
| `ssp:read` | GET | `/oscal/system-security-plans` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/full` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/metadata` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/profile` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/import-profile` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-characteristics` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-characteristics/network-architecture` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-characteristics/data-flow` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-characteristics/authorization-boundary` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-implementation` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-implementation/users` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-implementation/components` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-implementation/components/:componentId` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-implementation/inventory-items` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/system-implementation/leveraged-authorizations` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/control-implementation` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/control-implementation/implemented-requirements` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/back-matter` |
| `ssp:read` | GET | `/oscal/system-security-plans/:id/back-matter/resources` |
| `ssp:write` | POST | `/oscal/system-security-plans` |
| `ssp:write` | PUT | `/oscal/system-security-plans/:id` |
| `ssp:write` | PUT | `/oscal/system-security-plans/:id/metadata` |
| `ssp:write` | PUT | `/oscal/system-security-plans/:id/profile` |
| `ssp:write` | PUT | `/oscal/system-security-plans/:id/import-profile` |
| `ssp:write` | PUT | `/oscal/system-security-plans/:id/system-characteristics` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/system-characteristics/network-architecture/diagrams` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/system-characteristics/data-flow/diagrams` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/system-characteristics/authorization-boundary/diagrams` |
| `ssp:write` | PUT | `/oscal/system-security-plans/:id/system-implementation` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/system-implementation/users` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/system-implementation/components` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/system-implementation/inventory-items` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/system-implementation/leveraged-authorizations` |
| `ssp:write` | PUT | `/oscal/system-security-plans/:id/control-implementation` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/control-implementation/implemented-requirements` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/statements` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components` |
| `ssp:write` | POST | `/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/suggest-components` |
| `ssp:write` | POST | `/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/apply-suggestion` |
| `ssp:write` | POST | `/oscal/system-security-plans/:id/bulk-apply-component-suggestions` |
| `ssp:write` | PUT/POST/DELETE | `/oscal/system-security-plans/:id/back-matter` |
| `ssp:write` | POST/PUT/DELETE | `/oscal/system-security-plans/:id/back-matter/resources` |
| `ssp:delete` | DELETE | `/oscal/system-security-plans/:id` |

---

### Risks

Risks exist both as a global resource and as SSP-scoped sub-resources. The SSP-scoped routes under `/oscal/system-security-plans/:sspId/risks` evaluate against the SSP ID.

| Action | HTTP | Route |
|---|---|---|
| `risk:read` | GET | `/risks` |
| `risk:read` | GET | `/risks/:id` |
| `risk:read` | GET | `/risks/:id/events` |
| `risk:read` | GET | `/risks/:id/reviews` |
| `risk:read` | GET | `/risks/:id/evidence` |
| `risk:read` | GET | `/risks/:id/controls` |
| `risk:read` | GET | `/risks/:id/components` |
| `risk:read` | GET | `/risks/:id/subjects` |
| `risk:read` | GET | `/risks/:id/threat-ids` |
| `risk:read` | GET | `/risks/:id/threat-ids/:threatRefId` |
| `risk:read` | GET | `/risks/:id/remediation-template` |
| `risk:write` | POST | `/risks` |
| `risk:write` | PUT | `/risks/:id` |
| `risk:write` | POST/PUT/DELETE | `/risks/:id/evidence` |
| `risk:write` | POST/DELETE | `/risks/:id/controls` |
| `risk:write` | POST/DELETE | `/risks/:id/components` |
| `risk:write` | POST | `/risks/:id/subjects` |
| `risk:write` | POST/PUT/DELETE | `/risks/:id/threat-ids` |
| `risk:write` | POST/PUT/DELETE | `/risks/:id/remediation-template` |
| `risk:assess` | POST | `/risks/:id/accept` |
| `risk:assess` | POST | `/risks/:id/review` |
| `risk:delete` | DELETE | `/risks/:id` |

The SSP-scoped variants (`/oscal/system-security-plans/:sspId/risks/*`) map to the same action names but are evaluated with the SSP UUID as the resource ID.

---

### POAM Items

| Action | HTTP | Route |
|---|---|---|
| `poam:read` | GET | `/poam-items` |
| `poam:read` | GET | `/poam-items/:id` |
| `poam:write` | POST | `/poam-items` |
| `poam:write` | PUT | `/poam-items/:id` |
| `poam:delete` | DELETE | `/poam-items/:id` |

SSP-scoped variant: `/system-security-plans/:sspId/poam-items` — same actions, resource ID is the SSP UUID.

---

### Catalogs

| Action | HTTP | Route |
|---|---|---|
| `catalog:read` | GET | `/oscal/catalogs` |
| `catalog:read` | GET | `/oscal/catalogs/:id` |
| `catalog:read` | GET | `/oscal/catalogs/:id/full` |
| `catalog:read` | GET | `/oscal/catalogs/:id/back-matter` |
| `catalog:read` | GET | `/oscal/catalogs/:id/groups` |
| `catalog:read` | GET | `/oscal/catalogs/:id/groups/:group` |
| `catalog:read` | GET | `/oscal/catalogs/:id/groups/:group/groups` |
| `catalog:read` | GET | `/oscal/catalogs/:id/groups/:group/controls` |
| `catalog:read` | GET | `/oscal/catalogs/:id/controls` |
| `catalog:read` | GET | `/oscal/catalogs/:id/all-controls` |
| `catalog:read` | GET | `/oscal/catalogs/:id/controls/:control` |
| `catalog:read` | GET | `/oscal/catalogs/:id/controls/:control/controls` |
| `catalog:write` | POST | `/oscal/catalogs` |
| `catalog:write` | PUT | `/oscal/catalogs/:id` |
| `catalog:write` | POST/PUT/DELETE | `/oscal/catalogs/:id/groups` |
| `catalog:write` | POST | `/oscal/catalogs/:id/groups/:group/groups` |
| `catalog:write` | POST | `/oscal/catalogs/:id/groups/:group/controls` |
| `catalog:write` | POST | `/oscal/catalogs/:id/controls` |
| `catalog:write` | PUT/DELETE | `/oscal/catalogs/:id/controls/:control` |
| `catalog:write` | POST | `/oscal/catalogs/:id/controls/:control/controls` |
| `catalog:delete` | DELETE | `/oscal/catalogs/:id` |

---

### Profiles

| Action | HTTP | Route |
|---|---|---|
| `profile:read` | GET | `/oscal/profiles` |
| `profile:read` | GET | `/oscal/profiles/:id` |
| `profile:read` | GET | `/oscal/profiles/:id/full` |
| `profile:read` | GET | `/oscal/profiles/:id/resolved` |
| `profile:read` | GET | `/oscal/profiles/:id/resolved-with-catalogs` |
| `profile:read` | GET | `/oscal/profiles/:id/compliance-progress` |
| `profile:read` | GET | `/oscal/profiles/:id/modify` |
| `profile:read` | GET | `/oscal/profiles/:id/back-matter` |
| `profile:read` | GET | `/oscal/profiles/:id/imports` |
| `profile:read` | GET | `/oscal/profiles/:id/imports/:href` |
| `profile:read` | GET | `/oscal/profiles/:id/merge` |
| `profile:write` | POST | `/oscal/profiles` |
| `profile:write` | POST | `/oscal/profiles/build-props` |
| `profile:write` | POST | `/oscal/profiles/:id/resolve` |
| `profile:write` | POST | `/oscal/profiles/:id/imports/add` |
| `profile:write` | PUT/DELETE | `/oscal/profiles/:id/imports/:href` |
| `profile:write` | PUT | `/oscal/profiles/:id/merge` |

---

### Component Definitions

| Action | HTTP | Route |
|---|---|---|
| `component-definition:read` | GET | `/oscal/component-definitions` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/full` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/import-component-definitions` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/components` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/components/:defined-component` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/components/:defined-component/control-implementations` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/components/:defined-component/control-implementations/implemented-requirements` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/components/:defined-component/control-implementations/implemented-requirements/statements` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/capabilities` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/capabilities/incorporates-components` |
| `component-definition:read` | GET | `/oscal/component-definitions/:id/back-matter` |
| `component-definition:write` | POST | `/oscal/component-definitions` |
| `component-definition:write` | PUT | `/highlight/component-definitions/:id` |
| `component-definition:write` | POST/PUT | `/oscal/component-definitions/:id/import-component-definitions` |
| `component-definition:write` | POST/PUT | `/oscal/component-definitions/:id/components` |
| `component-definition:write` | POST/PUT | `/oscal/component-definitions/:id/components/:defined-component` |
| `component-definition:write` | POST/PUT | `/oscal/component-definitions/:id/components/:defined-component/control-implementations` |
| `component-definition:write` | POST/PUT | `/oscal/component-definitions/:id/capabilities` |
| `component-definition:write` | POST/PUT | `/oscal/component-definitions/:id/capabilities/incorporates-components` |
| `component-definition:write` | POST | `/oscal/component-definitions/:id/back-matter` |

---

### Assessment Plans

| Action | HTTP | Route |
|---|---|---|
| `assessment-plan:read` | GET | `/oscal/assessment-plans` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/full` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/metadata` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/import-ssp` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/local-definitions` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/terms-and-conditions` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/back-matter` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/tasks` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/tasks/:taskId/associated-activities` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/assessment-subjects` |
| `assessment-plan:read` | GET | `/oscal/assessment-plans/:id/assessment-assets` |
| `assessment-plan:write` | POST | `/oscal/assessment-plans` |
| `assessment-plan:write` | PUT | `/oscal/assessment-plans/:id` |
| `assessment-plan:write` | POST/PUT/DELETE | `/oscal/assessment-plans/:id/tasks` |
| `assessment-plan:write` | POST/DELETE | `/oscal/assessment-plans/:id/tasks/:taskId/associated-activities` |
| `assessment-plan:write` | POST/PUT/DELETE | `/oscal/assessment-plans/:id/assessment-subjects` |
| `assessment-plan:write` | POST/PUT/DELETE | `/oscal/assessment-plans/:id/assessment-assets` |
| `assessment-plan:delete` | DELETE | `/oscal/assessment-plans/:id` |

---

### Assessment Results

| Action | HTTP | Route |
|---|---|---|
| `assessment-result:read` | GET | `/oscal/assessment-results` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/full` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/metadata` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/import-ap` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/local-definitions` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId/observations` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId/risks` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId/findings` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId/attestations` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/observations` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/risks` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/findings` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/available-controls` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/control/:controlId` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId/associated-observations` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId/associated-risks` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/results/:resultId/associated-findings` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/back-matter` |
| `assessment-result:read` | GET | `/oscal/assessment-results/:id/back-matter/resources` |
| `assessment-result:write` | POST | `/oscal/assessment-results` |
| `assessment-result:write` | PUT | `/oscal/assessment-results/:id` |
| `assessment-result:write` | PUT | `/oscal/assessment-results/:id/metadata` |
| `assessment-result:write` | PUT | `/oscal/assessment-results/:id/import-ap` |
| `assessment-result:write` | PUT | `/oscal/assessment-results/:id/local-definitions` |
| `assessment-result:write` | POST/PUT/DELETE | `/oscal/assessment-results/:id/results` |
| `assessment-result:write` | POST/PUT/DELETE | `/oscal/assessment-results/:id/results/:resultId/observations` |
| `assessment-result:write` | POST/PUT/DELETE | `/oscal/assessment-results/:id/results/:resultId/risks` |
| `assessment-result:write` | POST/PUT/DELETE | `/oscal/assessment-results/:id/results/:resultId/findings` |
| `assessment-result:write` | POST/PUT/DELETE | `/oscal/assessment-results/:id/results/:resultId/attestations` |
| `assessment-result:write` | POST/DELETE | `/oscal/assessment-results/:id/results/:resultId/associated-observations` |
| `assessment-result:write` | POST/DELETE | `/oscal/assessment-results/:id/results/:resultId/associated-risks` |
| `assessment-result:write` | POST/DELETE | `/oscal/assessment-results/:id/results/:resultId/associated-findings` |
| `assessment-result:write` | POST/PUT/DELETE | `/oscal/assessment-results/:id/back-matter` |
| `assessment-result:write` | POST/PUT/DELETE | `/oscal/assessment-results/:id/back-matter/resources` |
| `assessment-result:delete` | DELETE | `/oscal/assessment-results/:id` |

---

### Plan of Action & Milestones (POA&M)

| Action | HTTP | Route |
|---|---|---|
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/full` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/metadata` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/import-ssp` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/system-id` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/local-definitions` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/back-matter` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/back-matter/resources` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/observations` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/risks` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/findings` |
| `poam-document:read` | GET | `/oscal/plan-of-action-and-milestones/:id/poam-items` |
| `poam-document:write` | POST | `/oscal/plan-of-action-and-milestones` |
| `poam-document:write` | PUT | `/oscal/plan-of-action-and-milestones/:id` |
| `poam-document:write` | PUT | `/oscal/plan-of-action-and-milestones/:id/metadata` |
| `poam-document:write` | POST/PUT | `/oscal/plan-of-action-and-milestones/:id/import-ssp` |
| `poam-document:write` | POST/PUT | `/oscal/plan-of-action-and-milestones/:id/system-id` |
| `poam-document:write` | PUT | `/oscal/plan-of-action-and-milestones/:id/local-definitions` |
| `poam-document:write` | POST/PUT/DELETE | `/oscal/plan-of-action-and-milestones/:id/back-matter` |
| `poam-document:write` | POST/PUT/DELETE | `/oscal/plan-of-action-and-milestones/:id/back-matter/resources` |
| `poam-document:write` | POST/PUT/DELETE | `/oscal/plan-of-action-and-milestones/:id/observations` |
| `poam-document:write` | POST/PUT/DELETE | `/oscal/plan-of-action-and-milestones/:id/risks` |
| `poam-document:write` | POST/PUT/DELETE | `/oscal/plan-of-action-and-milestones/:id/findings` |
| `poam-document:write` | POST/PUT/DELETE | `/oscal/plan-of-action-and-milestones/:id/poam-items` |
| `poam-document:delete` | DELETE | `/oscal/plan-of-action-and-milestones/:id` |

---

### Filters

Filters are saved label-filter configurations, global to the system.

| Action | HTTP | Route |
|---|---|---|
| `filter:read` | GET | `/filters` |
| `filter:read` | GET | `/filters/:id` |
| `filter:write` | POST | `/filters` |
| `filter:write` | PUT | `/filters/:id` |
| `filter:write` | POST | `/filters/import` |
| `filter:delete` | DELETE | `/filters/:id` |

---

### Workflows

Workflow resources operate at the system level (not scoped to an SSP). Workflow role assignments (who can transition a step) are separate from API-level AuthZ.

| Action | HTTP | Route |
|---|---|---|
| `workflow:read` | GET | `/workflows/definitions` |
| `workflow:read` | GET | `/workflows/definitions/:id` |
| `workflow:read` | GET | `/workflows/steps` |
| `workflow:read` | GET | `/workflows/steps/:id` |
| `workflow:read` | GET | `/workflows/steps/:id/dependencies` |
| `workflow:read` | GET | `/workflows/instances` |
| `workflow:read` | GET | `/workflows/instances/:id` |
| `workflow:read` | GET | `/workflows/executions` |
| `workflow:read` | GET | `/workflows/executions/:id` |
| `workflow:read` | GET | `/workflows/executions/:id/status` |
| `workflow:read` | GET | `/workflows/executions/:id/metrics` |
| `workflow:read` | GET | `/workflows/step-executions` |
| `workflow:read` | GET | `/workflows/step-executions/my` |
| `workflow:read` | GET | `/workflows/step-executions/:id` |
| `workflow:read` | GET | `/workflows/step-executions/:id/evidence-requirements` |
| `workflow:read` | GET | `/workflows/step-executions/:id/can-transition` |
| `workflow:read` | GET | `/workflows/control-relationships` |
| `workflow:read` | GET | `/workflows/control-relationships/:id` |
| `workflow:read` | GET | `/workflows/role-assignments` |
| `workflow:read` | GET | `/workflows/role-assignments/:id` |
| `workflow:write` | POST | `/workflows/definitions` |
| `workflow:write` | PUT | `/workflows/definitions/:id` |
| `workflow:write` | DELETE | `/workflows/definitions/:id` |
| `workflow:write` | POST | `/workflows/steps` |
| `workflow:write` | PUT | `/workflows/steps/:id` |
| `workflow:write` | DELETE | `/workflows/steps/:id` |
| `workflow:write` | POST | `/workflows/instances` |
| `workflow:write` | PUT | `/workflows/instances/:id` |
| `workflow:write` | PUT | `/workflows/instances/:id/activate` |
| `workflow:write` | PUT | `/workflows/instances/:id/deactivate` |
| `workflow:write` | DELETE | `/workflows/instances/:id` |
| `workflow:write` | POST | `/workflows/executions` |
| `workflow:write` | PUT | `/workflows/executions/:id/cancel` |
| `workflow:write` | POST | `/workflows/executions/:id/retry` |
| `workflow:write` | PUT | `/workflows/executions/:id/reassign-role` |
| `workflow:write` | POST | `/workflows/role-assignments` |
| `workflow:write` | PUT | `/workflows/role-assignments/:id` |
| `workflow:write` | PUT | `/workflows/role-assignments/:id/activate` |
| `workflow:write` | PUT | `/workflows/role-assignments/:id/deactivate` |
| `workflow:write` | DELETE | `/workflows/role-assignments/:id` |
| `workflow:write` | POST | `/workflows/control-relationships` |
| `workflow:write` | PUT | `/workflows/control-relationships/:id` |
| `workflow:write` | PUT | `/workflows/control-relationships/:id/activate` |
| `workflow:write` | PUT | `/workflows/control-relationships/:id/deactivate` |
| `workflow:write` | DELETE | `/workflows/control-relationships/:id` |
| `workflow:action` | PUT | `/workflows/step-executions/:id/transition` |
| `workflow:action` | PUT | `/workflows/step-executions/:id/fail` |
| `workflow:action` | PUT | `/workflows/step-executions/:id/reassign` |

---

### Users & Admin

| Action | HTTP | Route |
|---|---|---|
| `user:read` | GET | `/admin/users` |
| `user:read` | GET | `/admin/users/:id` |
| `user:read` | GET | `/users/select` |
| `user:read` | GET | `/users/:id` |
| `user:read` | GET | `/users/me` |
| `user:write` | POST | `/admin/users` |
| `user:write` | PUT | `/admin/users/:id` |
| `user:write` | POST | `/admin/users/:id/change-password` |
| `user:write` | POST | `/users/me/change-password` |
| `user:write` | PUT | `/users/me/subscriptions` |
| `user:read` | GET | `/users/me/subscriptions` |
| `user:delete` | DELETE | `/admin/users/:id` |

---

### Admin Templates

| Action | HTTP | Route |
|---|---|---|
| `template:read` | GET | `/admin/risk-templates` |
| `template:write` | POST | `/admin/risk-templates` |
| `template:write` | PUT | `/admin/risk-templates/:id` |
| `template:delete` | DELETE | `/admin/risk-templates/:id` |
| `template:read` | GET | `/admin/subject-templates` |
| `template:write` | POST | `/admin/subject-templates` |
| `template:write` | PUT | `/admin/subject-templates/:id` |
| `template:delete` | DELETE | `/admin/subject-templates/:id` |

---

### Agent Endpoints

Agent endpoints are accessible only to valid agent JWTs. They do not map to user roles — the `evidence:create` action is implicitly granted to any authenticated agent token.

| Action | HTTP | Route |
|---|---|---|
| `evidence:create` (implicit) | POST | `/agent/heartbeat` |
| `evidence:create` (implicit) | GET | `/agent/heartbeat/over-time` |
| `evidence:create` (implicit) | GET | `/agent/risk-templates` |
| `evidence:create` (implicit) | GET | `/agent/subject-templates` |

---

### OSCAL Import

| Action | HTTP | Route |
|---|---|---|
| `import:write` | POST | `/oscal/import` |

---

## Role-to-Action Mapping (Built-in PDP)

This table summarises which roles grant which actions in the built-in PDP. An external PDP may define this mapping independently.

| Action | `admin` | `global:reader` | `global:writer` | `global:risk-assessor` | `ssp:reader` | `ssp:writer` | `ssp:risk-assessor` | `evidence:creator` |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `evidence:read` | ✓ | ✓ | ✓ | ✓ | — | — | — | — |
| `evidence:create` | ✓ | — | ✓ | — | — | — | — | ✓ |
| `ssp:read` | ✓ | ✓ | ✓ | ✓ | ✓ (scoped) | ✓ (scoped) | ✓ (scoped) | — |
| `ssp:write` | ✓ | — | ✓ | — | — | ✓ (scoped) | — | — |
| `ssp:delete` | ✓ | — | ✓ | — | — | — | — | — |
| `risk:read` | ✓ | ✓ | ✓ | ✓ | ✓ (scoped) | ✓ (scoped) | ✓ (scoped) | — |
| `risk:write` | ✓ | — | ✓ | ✓ | — | ✓ (scoped) | ✓ (scoped) | — |
| `risk:assess` | ✓ | — | — | ✓ | — | — | ✓ (scoped) | — |
| `risk:delete` | ✓ | — | ✓ | ✓ | — | — | — | — |
| `poam:read` | ✓ | ✓ | ✓ | ✓ | ✓ (scoped) | ✓ (scoped) | ✓ (scoped) | — |
| `poam:write` | ✓ | — | ✓ | — | — | ✓ (scoped) | — | — |
| `poam:delete` | ✓ | — | ✓ | — | — | — | — | — |
| `catalog:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| `catalog:write` | ✓ | — | ✓ | — | — | — | — | — |
| `catalog:delete` | ✓ | — | — | — | — | — | — | — |
| `profile:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| `profile:write` | ✓ | — | ✓ | — | — | — | — | — |
| `assessment-plan:read` | ✓ | ✓ | ✓ | ✓ | ✓ (scoped) | ✓ (scoped) | ✓ (scoped) | — |
| `assessment-plan:write` | ✓ | — | ✓ | — | — | ✓ (scoped) | — | — |
| `assessment-plan:delete` | ✓ | — | ✓ | — | — | — | — | — |
| `assessment-result:read` | ✓ | ✓ | ✓ | ✓ | ✓ (scoped) | ✓ (scoped) | ✓ (scoped) | — |
| `assessment-result:write` | ✓ | — | ✓ | ✓ | — | ✓ (scoped) | ✓ (scoped) | — |
| `assessment-result:delete` | ✓ | — | ✓ | — | — | — | — | — |
| `poam-document:read` | ✓ | ✓ | ✓ | ✓ | ✓ (scoped) | ✓ (scoped) | ✓ (scoped) | — |
| `poam-document:write` | ✓ | — | ✓ | ✓ | — | ✓ (scoped) | — | — |
| `poam-document:delete` | ✓ | — | ✓ | — | — | — | — | — |
| `component-definition:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| `component-definition:write` | ✓ | — | ✓ | — | — | — | — | — |
| `filter:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| `filter:write` | ✓ | — | ✓ | — | — | — | — | — |
| `filter:delete` | ✓ | — | — | — | — | — | — | — |
| `workflow:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| `workflow:write` | ✓ | — | ✓ | — | — | — | — | — |
| `workflow:action` | ✓ | — | ✓ | — | — | ✓ | — | — |
| `user:read` | ✓ | ✓ | — | — | — | — | — | — |
| `user:write` | ✓ | — | — | — | — | — | — | — |
| `user:delete` | ✓ | — | — | — | — | — | — | — |
| `template:read` | ✓ | ✓ | — | — | — | — | — | — |
| `template:write` | ✓ | — | — | — | — | — | — | — |
| `template:delete` | ✓ | — | — | — | — | — | — | — |
| `import:write` | ✓ | — | ✓ | — | — | — | — | — |

> ✓ (scoped) means the role only grants this action on the specific SSP UUID it is bound to. ✓ without qualifier means the role grants the action globally across all resources of that type.

---

## Extending Actions

When a new handler or route is added to the API, the following steps are required:

### 1. Define the action name

Follow the naming convention: `<resource-type>:<verb>`. Examples:
- New `GET /oscal/component-definitions/:id/test-cases` → `component-definition:read`
- New `POST /admin/audit-logs/export` → `audit-log:write`
- New `PUT /oscal/system-security-plans/:id/approve` (a state transition) → `ssp:action`

### 2. Add the action to this catalogue

Add a row to the relevant section table in this document.

### 3. Add the action to the role-to-action mapping table

Determine which roles should grant the new action. Update the Role-to-Action Mapping table. If the new action is entirely new (no existing role covers it), consider whether a new role is warranted or whether `admin` should be the only grantee until explicitly delegated.

### 4. Update the internal PDP

In the Go implementation, the internal PDP will have a `roleActionMap` or equivalent data structure mapping `(role, action)` → `bool`. Add the new entries there.

```go
// Example — conceptual, not final code
var roleActionMap = map[string][]string{
    "admin":               {"*"},                    // wildcard
    "global:writer":       {"ssp:read", "ssp:write", "evidence:create", ...},
    "ssp:writer":          {"ssp:read", "ssp:write", "risk:read", ...},
    "evidence:creator":    {"evidence:create"},
    // add new role/action pairs here
}
```

### 5. Update middleware wiring in `handler/api.go`

Apply `RequirePermission` to the new route group with the correct action and resource type:

```go
newGroup := server.API().Group("/oscal/new-resource")
newGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
newGroup.Use(middleware.RequirePermission(db, cfg, logger, "new-resource:write", "new-resource"))
```

### 6. External PDP consideration

If an external PDP is configured, its policies must also be updated to handle the new action. The CCF API does not push policy updates to external PDPs — that is the operator's responsibility. Document new actions in release notes when they are introduced.

---

## Migration from Current State

The current `RequireAdminGroups` middleware checks SSO group membership for admin enforcement. The migration path is:

1. Introduce `user_role_bindings` table via a new database migration.
2. On first boot after migration, seed an `admin` role binding for all existing users that currently pass `RequireAdminGroups` (i.e., all SSO-admin users and all password-auth users).
3. Replace `RequireAdminGroups` calls with `RequirePermission(..., "manage-users", "")`.
4. Progressively add `RequirePermission` gates to other route groups.
5. The SSO group-based admin enforcement can be kept as an optional additional layer or deprecated in a later release.

---

## What This Is Not

- **It is not fine-grained ABAC.** There is no attribute-based evaluation, no relationship-based access control (ReBAC), and no field-level permissions. The `ssp:writer` role grants all write operations on the entire SSP.
- **It is not a replacement for a commercial PDP.** The built-in PDP is intentionally simple. It will not satisfy compliance frameworks that require audit-trail authorization logs, policy-as-code, or runtime policy updates without a restart.
- **It is not workflow role management.** The existing `WorkflowRoleAssignment` model (assigning users to named roles within a workflow instance) is a separate concept and remains unchanged. It governs who can transition workflow steps, not who can access API routes.

---

## Open Questions

- Should read access to evidence be restricted by role, or should all authenticated users be able to read evidence? Evidence is currently label-addressed and SSP-agnostic at creation time, which makes scoping it to an SSP non-trivial.
- Should the `evidence:creator` role be assignable to human users, or is it exclusively for service accounts and agents? (Agents get it implicitly; should a human analyst also be able to hold it without any SSP access?)
- How should role bindings be managed in the UI? Admin-only screen, or self-service within an SSP?
