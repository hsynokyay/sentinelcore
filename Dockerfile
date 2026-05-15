# Phase 8 §4.4 R1 — pin base images by digest so the resulting image
# is reproducible and Cosign-verifiable against a specific upstream.
# Rebase via `docker manifest inspect <tag>` when Go or Alpine is
# bumped; re-pin to the new digest in one commit.
FROM golang:1.26.3-alpine@sha256:f44b851aa23dfa219d18db6eab743203245429d355cb619cf96a2ffe2a84ba7a AS builder
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

FROM alpine:3.22@sha256:2039be0c5ec6ce8566809626a252c930216a92109c043f282504accb5ee3c0c6
RUN apk add --no-cache ca-certificates tzdata wget
RUN addgroup -g 1000 app && adduser -u 1000 -G app -D -h /app -s /sbin/nologin app
WORKDIR /app
COPY --from=builder /app/bin/service /usr/local/bin/service
USER app
ENTRYPOINT ["/usr/local/bin/service"]
