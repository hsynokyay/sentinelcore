FROM golang:1.26-alpine AS builder
ARG SERVICE=controlplane
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY go.mod go.sum ./
RUN go version && go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/service ./cmd/${SERVICE}

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata wget
RUN addgroup -g 1000 app && adduser -u 1000 -G app -D -h /app -s /sbin/nologin app
WORKDIR /app
COPY --from=builder /app/bin/service /usr/local/bin/service
USER app
ENTRYPOINT ["/usr/local/bin/service"]
