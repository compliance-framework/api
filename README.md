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
You can configure configuration-service using environment variables. These are located in the [`.env`](./.env) file.

## Contributing
We welcome contributions to configuration-service!

## License
This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
