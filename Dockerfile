# syntax=docker/dockerfile:1
FROM golang:1.26.10-bookworm AS builder
WORKDIR /src
COPY . .
# The optional CA mount supports builds behind an HTTPS inspection proxy.
RUN --mount=type=secret,id=proxy_ca \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca GIT_SSL_CAINFO=/run/secrets/proxy_ca; fi; \
    ./scripts/prepare-oidc.sh && \
    GOMAXPROCS=4 CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags='-s -w' -o /usr/bin/caddy ./cmd/caddy

# The runtime supplies CA roots and Caddy's container layout. Its executable is
# replaced with our pinned Caddy v2.11.8 build (see go.mod).
FROM caddy:2.11.7-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
