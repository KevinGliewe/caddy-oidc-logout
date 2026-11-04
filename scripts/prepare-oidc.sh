#!/bin/sh
# Materialize the pinned upstream authentication module with the optional patch.
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_dir=${1:-"$project_dir/.build/oidc"}
patch_file="$project_dir/patches/caddy-oidc-v0.4.3-token-retention.patch"
upstream_commit=4552b569c6b9920c5d37001c856d26be108bb8c7
patch_id=$(git hash-object "$patch_file")

if [ -e "$target_dir" ]; then
    if [ -f "$target_dir/.caddy-oidc-logout-patch" ] &&
       [ "$(cat "$target_dir/.caddy-oidc-logout-patch")" = "$patch_id" ] &&
       [ "$(git -C "$target_dir" rev-parse HEAD)" = "$upstream_commit" ] &&
       git -C "$target_dir" apply --reverse --check "$patch_file"; then
        printf 'Patched caddy-oidc is ready at %s\n' "$target_dir"
        exit 0
    fi
    printf 'Refusing to overwrite %s; remove this generated checkout and rerun.\n' "$target_dir" >&2
    exit 1
fi

mkdir -p "$(dirname -- "$target_dir")"
temporary_dir=$(mktemp -d "$(dirname -- "$target_dir")/.oidc-prepare.XXXXXX")
trap 'rm -rf -- "$temporary_dir"' EXIT HUP INT TERM
git -c advice.detachedHead=false clone --quiet --depth 1 --branch v0.4.3 \
    https://github.com/relvacode/caddy-oidc.git "$temporary_dir"
if [ "$(git -C "$temporary_dir" rev-parse HEAD)" != "$upstream_commit" ]; then
    printf 'Upstream v0.4.3 no longer resolves to the pinned commit.\n' >&2
    exit 1
fi
git -C "$temporary_dir" apply --check "$patch_file"
git -C "$temporary_dir" apply "$patch_file"
printf '%s\n' "$patch_id" > "$temporary_dir/.caddy-oidc-logout-patch"
mv -- "$temporary_dir" "$target_dir"
trap - EXIT HUP INT TERM
printf 'Patched caddy-oidc is ready at %s\n' "$target_dir"
