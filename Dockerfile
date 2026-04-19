# Phase 8 §4.4 R1 — pin base images by digest so the resulting image
# is reproducible and Cosign-verifiable against a specific upstream.
# Rebase via `docker manifest inspect <tag>` when Go or Alpine is
# bumped; re-pin to the new digest in one commit.
FROM golang:1.26-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder
ARG SERVICE=controlplane
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY go.mod go.sum ./
RUN go version && go mod download
COPY . .
# -trimpath strips absolute paths from the binary (reproducibility)
# -ldflags "-s -w" strips symbol + DWARF (smaller binary, less info
# for an attacker to pivot with on a compromised container).
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /app/bin/service ./cmd/${SERVICE}

FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
RUN apk add --no-cache ca-certificates tzdata wget
RUN addgroup -g 1000 app && adduser -u 1000 -G app -D -h /app -s /sbin/nologin app
WORKDIR /app
COPY --from=builder /app/bin/service /usr/local/bin/service
USER app
ENTRYPOINT ["/usr/local/bin/service"]
