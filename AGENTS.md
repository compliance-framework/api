# AGENTS.md: compliance-framework/api

Guidance for coding agents working in this repo. The README covers running and configuring
the API. This file covers what you need to change it without breaking CI or other repos.

## How this repo fits

- **api** (this repo): Go/Echo service on Postgres. It stores OSCAL documents, evidence and
  policy artifacts, and serves the UI.
- **agent**: runs plugins on a schedule, evaluates their Rego policies, and posts evidence
  here. It imports this repo's `sdk/` and `pkg/policyeval`.
- **plugin-\***: one repo per plugin, importing `agent/runner`. Policies live in
  `plugin-*-policies` repos and are published as OCI bundles.
- **ui**: Vue app that talks only to this API.
- **local-dev**: Docker Compose stack running all of the above. Use it for end-to-end checks.

Versions are coupled:
- the agent's `go.mod` pins this module, and its OPA version must match ours;
- plugins pin the agent;
- the UI depends on our JSON shapes.

Releases are tags (`vX.Y.Z`, or `vX.Y.Z-rcN` for release candidates). CI publishes
`ghcr.io/compliance-framework/api`; the publish workflow takes about 20 minutes. A
mixed-version rollout must keep working: a new API must accept evidence from older agents.

## Commands

Run these before calling a change done. They are what CI runs (`.github/workflows/ci.yml`).

```sh
make swag                 # regenerate docs/ from handler annotations; commit any diff
make lint                 # golangci-lint v2.11.4 (make lint.install), default linters
make test                 # unit tests only: files with the integration tag are not compiled
make test-integration-single TEST_PATH=./internal/api/handler/... TEST_NAME=TestArtifactApi
make test-integration     # everything; slow
make reviewable           # swag + lint + integration tests + go mod tidy
make check-diff           # CI's gate on PRs: runs swag, then fails if the tree is dirty, so commit first
```

- Integration tests (`//go:build integration`, files named `*_integration_test.go`) start
  `postgres:17.5` through testcontainers, so Docker must be running. No env vars are needed.
  For Podman, see the README.
- For the full integration run, use `go test -tags integration -p 1 -timeout 40m ./...`.
  Parallel packages each start a container, and the default 10-minute timeout causes
  failures that aren't real.
- `make test` skips integration-tagged files entirely. Compile them with
  `go vet -tags integration ./...` after changing shared helpers.

## Layout

- `main.go`, `cmd/`: Cobra CLI (`run`, `migrate`, `users`, `oscal import`, `authz`, `seed`, ...).
- `internal/api/handler/`: one file per resource. Every route is wired in `RegisterHandlers` in `api.go`.
- `internal/api/middleware/`: JWT, agent ingest auth, and the PEP guards (`authorize.go`).
- `internal/api/error.go`: error helpers. `handler/response.go`: `GenericDataResponse[T]` envelopes.
- `internal/service/relational/`: GORM models and services (e.g. `evidence.go`; evidence
  `Status` is a JSON column, so read the state via `Status.Data().State`).
  `internal/service/migrator.go` holds the migrations.
- `internal/authz/`: authorisation (builtin, Cedar, AuthZEN) plus the vocabulary in `manifest.yaml`.
- `internal/artifact/`: canonical forms and digests for policy artifacts (see `docs/artifacts.md`).
- `internal/config/`: Viper config, `CCF_` env prefix. List new variables in `.env.example`.
- `internal/tests/`: `IntegrationTestSuite` and `TestMigrator`.
- `pkg/policyeval/`: Rego evaluator and playback sandbox. **Public**: the agent imports it.
- `sdk/`: Go client. **Public**: the agent uses it to post evidence and artifacts.
- `docs/`: generated Swagger (`docs.go`, `swagger.json`, `swagger.yaml`) plus design notes.

## Change together

- **New or changed route**
  - Register it in `internal/api/handler/api.go` with an auth middleware and a guard:
    `pep.Authorize(resource, action)` or `pep.For(resource)`.
  - Choose the middleware deliberately (`internal/api/middleware/`):

    | Middleware | Accepts |
    | --- | --- |
    | `JWTMiddleware(key)` | user sessions only |
    | `AgentJWTMiddleware(db, key)` | agents only |
    | `OptionalUserOrAgentJWTMiddleware(db, key, false)` | users or agents |
    | `OptionalUserOrAgentJWTMiddleware(db, key, true)` | users, agents or anonymous callers |

  - Some existing evidence read routes are deliberately public. Adding a route to one of
    their groups makes it public too, so start a new group if it shouldn't be.
  - Add swag annotations to the handler.
  - Run `make swag` and commit `docs/`. CI's `check-diff` fails on stale docs.
- **New authz resource or action**
  - Add the constant in `internal/authz/pdp.go`.
  - Add the entry in `internal/authz/manifest.yaml`, a public contract checked by
    `manifest_test.go`.
- **New GORM model**: add it to both AutoMigrate lists, `internal/service/migrator.go`
  and `internal/tests/migrate.go`.
- **`sdk/` or `pkg/policyeval` change**: this changes the agent's dependency. Keep it
  backwards compatible, tag an rc, and bump the agent's `go.mod` in a separate PR.
- **OPA version bump**: the agent must bump to the same version. Its
  `make check-opa-version` enforces this.

## Conventions

- **Errors**: return `api.NewError(err)`, `api.Validator(err)`, `api.NotFound()` and the
  like. For 5xx use `api.InternalServerError()`: never put DB or internal errors in a response.
- **Responses** are wrapped as `GenericDataResponse[T]` / `GenericDataListResponse[T]`. The
  UI unwraps `.data`.
- **Tests** are testify suites. Integration suites embed `tests.IntegrationTestSuite` and use
  its helpers (`Migrator`, `GetAuthToken`, `CreateAgent`, `CreateAgentKey`, `GetAgentToken`).
- **JSON field names**: OSCAL types are kebab-case. Other types vary, so match the
  type or endpoint you are extending. The UI camelCases every response key, so the
  name you pick reaches the UI camelCased.

## Domain rules that are easy to break

- **Evidence props are covered by the evidence signature.** Don't rewrite props after
  signing.
- **Reserved props.** `_policy_bundle_digest`, `_policy_input_digest` and
  `_policy_data_digest` are written only by the API (`artifact.IsReservedProp`), and clients
  may not set them.
- **The agent owns** `_agent`, `_plugin_source`, `_plugin_digest`, `_policy_source` and
  `_policy_digest`.
- **Artifact digests are SHA-256 over the canonical forms in `internal/artifact`.** Those
  forms are permanent and pinned by golden tests. Changing one silently invalidates every
  stored digest. Only this API computes digests: the agent sends raw data.
- **Playback** (`pkg/policyeval`, `/api/playback/*`, `/api/evidence/{id}/playback`) runs
  user-supplied Rego in a sandbox:
  - no I/O builtins;
  - a time limit;
  - a concurrency cap.

  Keep new evaluation paths inside it.

## Don't

- Hand-edit `docs/docs.go`, `docs/swagger.json` or `docs/swagger.yaml`.
- Commit `cover.out`, `tmp/`, or keys generated by `make generate-keys`.
- Add a `replace` directive or `go.work` for local cross-repo work to a commit.
