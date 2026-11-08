# API

## Overview

The API is a core component of the Continuous Compliance Framework. It manages all the data and
aggregation for compliance, and agent-collected data.

The data structures in the service are heavily based on OSCAL (Open Security Controls Assessment Language), with the
goal of full support.

## Prerequisites
- Docker / Podman
- Docker Compose / Podman Compose
- Go (if running locally without Docker)

## Getting Started

### Using Docker Compose

This will also start the required auxiliary services.

```shell
make up
# OR podman-compose up -d
# OR docker compose up -d

curl http://localhost:8080
```

### The command line

The API ships with a built in CLI, which can be used to run administrative tasks within.

Some examples include:
```shell
$ go run main.go run # Run the API itself

$ go run main.go bootstrap # Bootstrap JWT key files (defaults to CCF_JWT_* or private.pem/public.pem)

$ go run main.go users add # Create a new user in the CCF API which can be used to authenticate with

$ go run main.go migrate up # Create the database schema, or upgrade it to the current version

$ go run main.go oscal import -f testdata/full_ar.json # Import a single OSCAL document
$ go run main.go oscal import -f testdata/ # Import a directory with OSCAL documents

$ go run main.go help # Learn more about all the available commands
```

### Accessing Swagger Documentation

The API exposes all of its endpoints using Swagger.

The Swagger artefacts (`docs/docs.go`, `docs/swagger.json`, `docs/swagger.yaml`) are generated from the handler annotations by the [swag cli tool](https://github.com/swaggo/swag) and committed to the repository. After changing a handler's annotations or its request/response types, run `make swag` and commit the result: CI fails if the committed docs are out of date.

You can access the Swagger documentation to test and interact with the API at: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

## Configuration

You can configure the API using environment variables or a `.env` file.

Available variables are shown in [`.env.example`](./.env.example)

JWT key behavior:
- If both `CCF_JWT_PRIVATE_KEY` and `CCF_JWT_PUBLIC_KEY` are set, `run` bootstraps key files at those paths (if needed) and then loads them.
- If either variable is unset, the API falls back to in-memory key generation.

Copy this file to .env to configure environment variables
```shell
cp .env.example .env
```

### Evidence compliance badge

`GET /api/evidence/badge.svg?provider=aws&environment=production` returns an SVG
badge using the latest evidence per stream matching **all** supplied labels.
Every query key is a label name; `source`, `repo`, and `branch` have no special
meaning, required format, or defaults. The one exception is `label`: it is reserved
for the repeatable `label=<name>:<value>` form (split at the first colon), e.g.
`?label=provider:aws&label=environment:production`. This form is what Swagger UI
sends, and it can be mixed with plain `name=value` labels. Send a label literally
named `label` as `label=label:<value>`.

Supply between one and `CCF_EVIDENCE_BADGE_MAX_PARAMS` labels (default **3**).
The setting must be a positive integer; an explicitly empty setting is invalid.
Empty names/values, repeated keys
(case-insensitive), and exceeding the limit return HTTP 400. Names and values
must be valid UTF-8, at most 255 characters, without surrounding whitespace or
control characters. Internal spaces are allowed; URL-encode label names and values.

The badge is red for `not-satisfied`, green for `satisfied` when no failures are
present, and grey for `unknown` (including no matching evidence). Responses use
`Cache-Control: no-store`. Existing evidence-read authentication and authorization
rules apply.

## Contributing

We welcome contributions to the API!

## Testing

### Integration Tests

The API contains integration tests, which will run tests against a real database, ensuring the service
works as expected.

The tests are marked with special build markers to avoid running them during normal development.

```shell
make test-integration
```

#### Notes

When using Podman instead of Docker, some changes are necessary for testcontainers to function correctly

```shell
# This is a workaround currently, and is currently being worked on by the testcontainers folks.
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
export TESTCONTAINERS_RYUK_DISABLED=true;
```

## License
This project is licensed under the GNU AGPLv3 License - see the [LICENSE](LICENSE) file for details.
