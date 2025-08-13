# API

## Overview

The API is a core component of the Continuous Compliance Framework. It manages all the data and
aggregation for compliance, and agent-collected data.

The data structures in the service are heavily based on OSCAL (Open Security Controls Assessment Language), with the
goal of full support.

## Deployment

All Kubernetes, Helm, and ArgoCD deployment configurations have been moved to a centralized repository:
**https://github.com/compliance-framework/ccf-deployments**

Please refer to that repository for:
- Helm charts with PostgreSQL configuration
- ArgoCD configurations
- Environment-specific deployments
- Deployment scripts and documentation

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

$ go run main.go users add # Create a new user in the CCF API which can be used to authenticate with

$ go run main.go migrate up # Create the database schema, or upgrade it to the current version

$ go run main.go oscal import -f testdata/full_ar.json # Import a single OSCAL document
$ go run main.go oscal import -f testdata/ # Import a directory with OSCAL documents

$ go run main.go help # Learn more about all the available commands
```

## Deployment Options

> 📚 **New to deployment?** See our [Deployment Guide](DEPLOYMENT.md) to choose the best method for your needs.

### Option 1: Docker Compose (Simplest for Development)
```shell
make up
# OR docker compose up -d
```

### Option 2: Kubernetes with Plain YAML (Basic)
```shell
cd k8s
./deploy.sh
```
See [k8s/README.md](k8s/README.md) for detailed instructions.

### Option 3: Kubernetes with Helm (Recommended for Production)
```shell
# Install Helm first: https://helm.sh/docs/intro/install/
helm install my-ccf ./helm-chart/ccf -f ./helm-chart/ccf/values-dev.yaml
```
See [helm-chart/ccf/README.md](helm-chart/ccf/README.md) for detailed Helm instructions.

### Accessing Swagger Documentation

> [!IMPORTANT]
> Make sure you run `make swag` when first cloning the repository (either locally or in CI steps) otherwise the build will fail

The API exposes all of its endpoints using Swagger.

Swagger artefacts (docs.json/docs.yaml) are not stored within the repository as it is automatically generated using the [swag cli tool](https://github.com/swaggo/swag) and stored in the `docs/` directory. A helper function `make swag` can be run anytime to generate the most up to date swagger docs.

You can access the Swagger documentation to test and interact with the API at: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

## Configuration

You can configure the API using environment variables or a `.env` file.

Available variables are shown in [`.env.example`](./.env.example)

Copy this file to .env to configure environment variables
```shell
cp .env.example .env
```

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
