# Use the official Golang image to create a build artifact.
# This is based on Debian.
FROM golang:1.25 AS local

# Create and change to the app directory.
WORKDIR /app

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN make swag

CMD ["go", "tool", "air"]

FROM golang:1.25 AS builder

# Create and change to the app directory.
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN make swag

# Build it
RUN GOOS=linux go build -o /api


# Runtime image with a shell for IaC and operational one-off commands.
FROM debian:bookworm-slim AS production

# Install CA certificates (TLS) and minimal tzdata, then clean apt cache.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /api /api
# Open port 8080 to traffic
EXPOSE 8080

# Specify the command to run on container start.
ENTRYPOINT ["/api"]
CMD ["run"]
