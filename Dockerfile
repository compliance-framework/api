# Use the official Golang image to create a build artifact.
# This is based on Debian.
FROM golang:1.24 AS local

# Create and change to the app directory.
WORKDIR /app

RUN go install github.com/swaggo/swag/cmd/swag@latest && go install github.com/air-verse/air@latest

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN make swag

CMD ["air"]

FROM golang:1.24 AS builder

# Create and change to the app directory.
WORKDIR /app

RUN go install github.com/swaggo/swag/cmd/swag@latest

COPY go.mod go.sum ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN make swag

# Build it
RUN GOOS=linux go build -o /configuration-service

FROM golang:1.24 AS production
WORKDIR /

COPY --from=builder /configuration-service /configuration-service
# Open port 8080 to traffic
EXPOSE 8080

# Specify the command to run on container start.
CMD ["/configuration-service", "run"]

FROM production
