# Use the official Golang image to create a build artifact.
# This is based on Debian.
FROM golang:1.22 AS builder

# Create and change to the app directory.
WORKDIR /app

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN go install github.com/swaggo/swag/cmd/swag@latest
RUN make swag

# Build it
RUN CGO_ENABLED=0 GOOS=linux go build -o /configuration-service

FROM alpine
WORKDIR /

COPY --from=builder /configuration-service /configuration-service
# Open port 8080 to traffic
EXPOSE 8080

# Specify the command to run on container start.
CMD ["/configuration-service"]
