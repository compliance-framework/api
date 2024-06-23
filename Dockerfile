# Use the official Golang image to create a build artifact.
# This is based on Debian.
FROM golang:1.21 as builder

# Create and change to the app directory.
WORKDIR /app

# Copy local code to the container image.
COPY . ./

# Build it
RUN CGO_ENABLED=0 GOOS=linux go build -o /configuration-service

# Regenerate the swagger
RUN go install github.com/swaggo/swag/cmd/swag@latest
RUN make swag

FROM alpine
WORKDIR /

COPY --from=builder /configuration-service /configuration-service
COPY .env /.env
# Open port 8080 to traffic
EXPOSE 8080

# Specify the command to run on container start.
CMD ["/configuration-service"]
