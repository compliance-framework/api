# Use the official Golang image to create a build artifact.
# This is based on Debian.
FROM golang:1.21 as builder

# Create and change to the app directory.
WORKDIR /app


# Copy local code to the container image.
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /configuration-service

# Make sure the swagger.yaml file is in the same directory as your Dockerfile, or adjust the path accordingly
COPY ./docs/swagger.yaml /app/swagger.yaml

FROM alpine
WORKDIR /app

COPY --from=builder /configuration-service ./configuration-service
# Open port 8080 to traffic
EXPOSE 8080

# Specify the command to run on container start.
CMD ["./configuration-service"]
