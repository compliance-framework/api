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

2. Start the services:

   ```sh
   docker-compose -f docker-compose.dev.yml up
   podman-compose -f docker-compose.dev.yml up
   ```

This command will build the container image for configuration-service and start the containers.

### Accessing Swagger Documentation

Once the service is running, you can access the Swagger documentation to test and interact with the API at: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

## Configuration
You can configure configuration-service using environment variables. Here are some of the key environment variables:

- `NATS_URL`: URL for connecting to NATS (e.g., "nats://nats:4222")
- `MONGODB_URI`: URI for connecting to MongoDB (e.g., "mongodb://mongodb:27017")

## Contributing
We welcome contributions to configuration-service!

## License
This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
