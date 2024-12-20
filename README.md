# Configuration Service

## Overview
`configuration-service` is a service responsible for storing and retrieving OSCAL (Open Security Controls Assessment Language) configurations.

## Features
- Store OSCAL configurations
- Retrieve OSCAL configurations

## Prerequisites
- Docker / Podman
- Docker Compose / Podman Compose
- Go (if running locally without Docker)

## Getting Started

### Using Docker Compose

You can easily run `configuration-service` using Docker Compose. This will also start the required MongoDB and NATS services.

1. Clone the repository:

   ```sh
   git clone https://github.com/compliance-framework/configuration-service.git
   cd configuration-service
   ```

2. Start and stop the services:

   ```sh

   make dev        # starts service (does not build container)
   make dev_stop   # stops the service
   ```

3. Build, start and stop the services:

   ```sh

   make debug        # builds container with local code and starts service
   make debug_stop   # stops the service
   ```

Then see [https://raw.githubusercontent.com/compliance-framework/infrastructure/main/hack/setup.sh](here) for example setup code you can run.

### Accessing Swagger Documentation

Once the service is running, you can access the Swagger documentation to test and interact with the API at: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

## Configuration
You can configure configuration-service using environment variables. 
An example is located at [`.env.example`](./.env.example)

Copy this file to .env to configure your environment variables
```shell
cp .env.example .env
```

## Contributing
We welcome contributions to configuration-service!

## Integration Tests

```shell
make test-integration
```

When using Podman instead of Docker:
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
This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
