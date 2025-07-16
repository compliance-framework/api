# Use the official Golang image to create a build artifact.
# This is based on Debian.
FROM golang:1.23 AS local

# Create and change to the app directory.
WORKDIR /app

RUN go install github.com/swaggo/swag/cmd/swag@latest && go install github.com/air-verse/air@v1.61.5

# Copy local code to the container image.
COPY . ./

# Regenerate the swagger
RUN make swag

CMD ["air"]

FROM golang:1.23 AS builder

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
RUN GOOS=linux go build -o /api

FROM golang:1.23 AS production
WORKDIR /

COPY --from=builder /api /api
# Open port 8080 to traffic
EXPOSE 8080

# Specify the command to run on container start.
CMD ["/api", "run"]

FROM production
