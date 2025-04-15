# Configuration Service

## Overview

The Configuration service is a core component of The Continuous Compliance Framework. It manages all the data and 
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

### Accessing Swagger Documentation

The configuration service exposes all of its endpoints using Swagger.

You can access the Swagger documentation to test and interact with the API at: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

## Configuration

You can configure configuration-service using environment variables or a `.env` file.

Available variables are shown in [`.env.example`](./.env.example)

Copy this file to .env to configure environment variables
```shell
cp .env.example .env
```

## Contributing

We welcome contributions to configuration-service!

## Testing

### Integration Tests

The Configuration Service contains integration tests, which will run tests against a real database, ensuring the service
works as expected. 

The tests are marked with special build markers to avoid running them during normal development.

```shell
make test-integration
```

#### Notes

When using Podman instead of Docker, some changes are necessary for testcontainers to function correctly

```shell
# This is a workaround currently, and is currently being worked on by the testcontainers folks.
# Ensure Podman is running rootfully
podman machine stop; podman machine set --rootful; podman machine start;
export DOCKER_HOST=unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
export TESTCONTAINERS_RYUK_DISABLED=true;
export TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED=true;
```

## License
This project is licensed under the GNU AGPLv3 License - see the [LICENSE](LICENSE) file for details.
