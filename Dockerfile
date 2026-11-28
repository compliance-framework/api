# Use the official Golang image to create a build artifact.
# This is based on Debian.
FROM golang:1.27@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS local
# Build with the go.mod toolchain line (Renovate bumps it for Go security fixes), downloading it when this image's Go is older.
ENV GOTOOLCHAIN=auto

# Create and change to the app directory.
WORKDIR /app

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN make swag

CMD ["go", "tool", "air"]

FROM golang:1.27@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS builder
# Build with the go.mod toolchain line (Renovate bumps it for Go security fixes), downloading it when this image's Go is older.
ENV GOTOOLCHAIN=auto

# Create and change to the app directory.
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN make swag

# Build it: a static binary, since the production image has no libc.
RUN CGO_ENABLED=0 GOOS=linux go build -o /api

FROM gcr.io/distroless/static-debian13@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a AS production

# The release and preview workflows pass VERSION (X.Y.Z, X.Y.Z-rcN, main-<sha7> or
# pr-<number>-<sha7>) and set the source and revision labels themselves.
ARG VERSION=dev
LABEL org.opencontainers.image.title="api" \
	org.opencontainers.image.description="Service responsible for storing and retrieving OSCAL configuration" \
	org.opencontainers.image.url="https://github.com/compliance-framework/api" \
	org.opencontainers.image.licenses="AGPL-3.0" \
	org.opencontainers.image.version="${VERSION}"

COPY --from=builder /api /api
# Open port 8080 to traffic
EXPOSE 8080

# Specify the command to run on container start.
ENTRYPOINT ["/api"]
CMD ["run"]
