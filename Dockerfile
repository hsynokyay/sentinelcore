FROM golang:1.22-alpine AS builder
ARG SERVICE=controlplane
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/service ./cmd/${SERVICE}

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata git
COPY --from=builder /app/bin/service /usr/local/bin/service
ENTRYPOINT ["/usr/local/bin/service"]
