.PHONY: prepare test build
prepare:
	./scripts/prepare-oidc.sh
test: prepare
	go test -race ./...
build: prepare
	go build -trimpath -o bin/caddy ./cmd/caddy
