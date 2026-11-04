# syntax=docker/dockerfile:1
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /backend .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /backend /backend
ENTRYPOINT ["/backend"]
