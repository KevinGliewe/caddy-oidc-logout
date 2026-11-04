#!/usr/bin/env bash
# Promote already-tested artifacts; this script never builds an image.
set -euo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
mode=${1:-publish}
case "$mode" in check|tags|publish) ;; *) die 'Expected check, tags or publish' ;; esac
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || die 'GITHUB_SHA must be a full commit SHA'
[[ ${GITHUB_EVENT_NAME:-} != pull_request* ]] || die 'Pull requests cannot publish images'

tags=("sha-$GITHUB_SHA")
case ${GITHUB_REF:-} in
    refs/heads/main) tags+=(latest) ;;
    refs/tags/v*)
        version=${GITHUB_REF#refs/tags/v}
        # Docker tags cannot contain SemVer +build metadata. Only exact version
        # tags are published; older releases cannot move major/minor aliases.
        [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] || die 'Release tags must be vX.Y.Z or vX.Y.Z-prerelease'
        if [[ $version == *-* ]]; then
            IFS=. read -r -a identifiers <<< "${version#*-}"
            for identifier in "${identifiers[@]}"; do
                [[ ! $identifier =~ ^0[0-9]+$ ]] || die 'Numeric prerelease identifiers must not have leading zeroes'
            done
        fi
        (( ${#version} <= 128 )) || die 'Release version exceeds the Docker tag length limit'
        tags+=("$version")
        ;;
    *) die 'Only main or a version tag can publish' ;;
esac

if [[ $mode == tags ]]; then printf '%s\n' "${tags[@]}"; exit 0; fi
[[ -n ${DOCKERHUB_USERNAME:-} ]] || die 'Set the DOCKERHUB_USERNAME repository secret'
image=${DOCKERHUB_IMAGE:-${DOCKERHUB_USERNAME,,}/caddy-oidc-logout}
# Dots and the literal localhost in the first component would select a
# different registry in Docker, even though the value contains just one slash.
[[ $image =~ ^[a-z0-9]+([_-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*$ && $image != localhost/* ]] || die 'DOCKERHUB_IMAGE must be a lowercase Docker Hub namespace/repository'
if [[ $mode == check ]]; then
    [[ -n ${DOCKERHUB_TOKEN:-} ]] || die 'Set the DOCKERHUB_TOKEN repository secret'
    printf 'Docker Hub publication configuration is valid.\n'
    exit 0
fi

# A slow old build must never move latest backwards after main has advanced.
# Read the repository as data; no ref or repository value is evaluated as code.
if [[ $GITHUB_REF == refs/heads/main ]]; then
    [[ -n ${GITHUB_REPOSITORY:-} ]] || die 'GITHUB_REPOSITORY is required'
    main_sha=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq '.object.sha')
    [[ $main_sha =~ ^[0-9a-f]{40}$ ]] || die 'Could not verify the current main commit'
    if [[ $main_sha != "$GITHUB_SHA" ]]; then
        tags=("sha-$GITHUB_SHA")
        printf 'Main has advanced; publishing this tested commit without changing latest.\n'
    fi
fi

# Validate BOTH artifacts before the first registry write.
for arch in amd64 arm64; do
    archive="image-artifacts/caddy-$arch.tar.gz"
    [[ -s $archive ]] || die "Missing tested $arch image artifact"
    gzip -dc "$archive" | docker load
    local_image="caddy-oidc-logout:test-$arch"
    actual=$(docker image inspect "$local_image" --format '{{.Os}}/{{.Architecture}}')
    [[ $actual == "linux/$arch" ]] || die "Wrong platform in $arch artifact"
    revision=$(docker image inspect "$local_image" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
    [[ $revision == "$GITHUB_SHA" ]] || die "Wrong source revision in $arch artifact"
done

sources=()
for arch in amd64 arm64; do
    target="$image:sha-$GITHUB_SHA-$arch"
    docker tag "caddy-oidc-logout:test-$arch" "$target"
    docker push "$target"
    # Read the digest returned to the local engine by this push, rather than
    # resolving an architecture tag which could later be moved.
    digest=$(docker image inspect "$target" --format '{{range .RepoDigests}}{{println .}}{{end}}' |
        awk -F@ -v repo="$image" '$1 == repo || $1 == "docker.io/" repo { print $2; exit }')
    [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "Missing pushed $arch digest"
    sources+=("$image@$digest")
done

tag_args=()
for tag in "${tags[@]}"; do tag_args+=(--tag "$image:$tag"); done
docker buildx imagetools create "${tag_args[@]}" "${sources[@]}"
docker buildx imagetools inspect "$image:sha-$GITHUB_SHA"

if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
    {
        printf 'Published the tested AMD64 and ARM64 Caddy images:\n\n'
        for tag in "${tags[@]}"; do printf -- '- `%s:%s`\n' "$image" "$tag"; done
        printf '\nBoth images passed Caddy/module checks and the real Keycloak logout test before publication.\n'
        printf '\nUse an image digest when you need a fixed deployment artifact.\n'
    } >> "$GITHUB_STEP_SUMMARY"
fi
