#!/usr/bin/env bash
# Check the exact image that will be tested with Keycloak and published.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s IMAGE\n' "$0" >&2
    exit 2
fi

image=$1
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
expected_version=$(awk '$1 == "github.com/caddyserver/caddy/v2" { print $2; exit }' "$project_dir/go.mod")
if [[ -z "$expected_version" ]]; then
    printf 'Cannot determine the pinned Caddy version from go.mod\n' >&2
    exit 1
fi

smoke_dir=$(mktemp -d "${TMPDIR:-/tmp}/caddy-image-smoke.XXXXXX")
container_id=
cleanup() {
    if [[ -n "$container_id" ]]; then
        docker rm -f "$container_id" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$smoke_dir"
}
trap cleanup EXIT

actual_version=$(docker run --rm "$image" caddy version)
if [[ "${actual_version%% *}" != "$expected_version" ]]; then
    printf 'Expected Caddy %s, got %s\n' "$expected_version" "$actual_version" >&2
    exit 1
fi

docker run --rm "$image" caddy list-modules > "$smoke_dir/modules"
for module in \
    http.handlers.oidc \
    http.oidc.authenticators.cookie \
    http.handlers.oidc_session \
    http.handlers.oidc_backchannel \
    http.handlers.oidc_signout \
    http.reverse_proxy.transport.oidc_session \
    oidc_logout; do
    if ! grep -Fxq "$module" "$smoke_dir/modules"; then
        printf 'Image is missing required Caddy module: %s\n' "$module" >&2
        exit 1
    fi
done

# This also checks the optional retain_access_token patch and custom directives.
# Adaptation does not contact Keycloak or load the configured session database.
docker run --rm \
    --mount "type=bind,src=$project_dir/examples/keycloak/Caddyfile,dst=/tmp/example.Caddyfile,readonly" \
    "$image" caddy adapt --config /tmp/example.Caddyfile --adapter caddyfile \
    > "$smoke_dir/config.json"

# Exercise the image's inherited default command, config, assets and runtime.
# Bind an ephemeral host port on loopback so concurrent checks do not collide.
container_id=$(docker run -d --rm -p 127.0.0.1::80 "$image")
address=$(docker port "$container_id" 80/tcp)
if [[ "$address" != 127.0.0.1:* ]]; then
    printf 'Unexpected smoke-test port binding: %s\n' "$address" >&2
    exit 1
fi

for ((attempt=0; attempt<30; attempt++)); do
    if curl --noproxy 127.0.0.1 --fail --silent --show-error \
        --connect-timeout 1 --max-time 2 "http://$address/" \
        > "$smoke_dir/index.html" 2> "$smoke_dir/curl.error"; then
        printf 'PASS: Caddy %s, required modules, example adaptation and default HTTP server\n' "$expected_version"
        exit 0
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != true ]]; then
        break
    fi
    sleep 1
done

cat "$smoke_dir/curl.error" >&2
docker logs "$container_id" >&2 || true
printf 'Image did not serve its default HTTP page\n' >&2
exit 1
