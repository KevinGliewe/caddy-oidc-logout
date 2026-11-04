#!/usr/bin/env bash
# Exercise publication policy and artifact promotion without a registry or secrets.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
publisher="$script_dir/publish-image.sh"
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root/bin"
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
new_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
amd_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111
arm_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222
passed=0

# Only the Docker/GitHub operations used to promote images are implemented.
# In particular, attempting to rebuild an image makes a successful test fail.
cat > "$test_root/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
{ printf 'docker'; printf '\t%s' "$@"; printf '\n'; } >> "$MOCK_CALLS"
case "${1:-} ${2:-} ${3:-}" in
    'load  ')
        read -r arch
        [[ $arch == amd64 || $arch == arm64 ]]
        touch "$MOCK_STATE/loaded-$arch"
        ;;
    'image inspect '*)
        image=$3
        [[ ${4:-} == --format && $# == 5 ]]
        case "$image" in
            caddy-oidc-logout:test-amd64) arch=amd64; local_image=true ;;
            caddy-oidc-logout:test-arm64) arch=arm64; local_image=true ;;
            *-amd64) arch=amd64; local_image=false ;;
            *-arm64) arch=arm64; local_image=false ;;
            *) exit 80 ;;
        esac
        [[ -f $MOCK_STATE/loaded-$arch ]]
        if [[ $local_image == true ]]; then
            case "$5" in
                '{{.Os}}/{{.Architecture}}')
                    key=MOCK_PLATFORM_${arch^^}
                    printf '%s\n' "${!key:-linux/$arch}"
                    ;;
                '{{index .Config.Labels "org.opencontainers.image.revision"}}')
                    key=MOCK_REVISION_${arch^^}
                    printf '%s\n' "${!key:-$GITHUB_SHA}"
                    ;;
                *) exit 81 ;;
            esac
        else
            [[ $5 == '{{range .RepoDigests}}{{println .}}{{end}}' ]]
            [[ -f $MOCK_STATE/pushed-$arch ]]
            # A preexisting, unrelated digest must not be selected.
            printf 'unrelated/image@sha256:%064d\n' 3
            key=MOCK_DIGEST_${arch^^}
            if [[ $arch == amd64 ]]; then digest=$MOCK_AMD_DIGEST; else digest=$MOCK_ARM_DIGEST; fi
            printf '%s%s@%s\n' "${MOCK_DIGEST_PREFIX:-}" "${image%%:*}" "${!key:-$digest}"
        fi
        ;;
    'tag '*)
        [[ $# == 3 ]]
        arch=${2##*:test-}
        [[ -f $MOCK_STATE/loaded-$arch ]]
        printf '%s\n' "$3" > "$MOCK_STATE/tagged-$arch"
        ;;
    'push '*)
        [[ $# == 2 ]]
        arch=${2##*-}
        [[ $(cat "$MOCK_STATE/tagged-$arch") == "$2" ]]
        touch "$MOCK_STATE/pushed-$arch"
        ;;
    'buildx imagetools create'|'buildx imagetools inspect') ;;
    *) printf 'Unexpected Docker operation\n' >&2; exit 82 ;;
esac
MOCK
cat > "$test_root/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
{ printf 'gh'; printf '\t%s' "$@"; printf '\n'; } >> "$MOCK_CALLS"
[[ $# == 4 && $1 == api && $2 == repos/acme/project/git/ref/heads/main && $3 == --jq && $4 == .object.sha ]]
printf '%s\n' "${MOCK_MAIN_SHA:-$GITHUB_SHA}"
MOCK
chmod +x "$test_root/bin/docker" "$test_root/bin/gh"

fail() {
    printf 'FAIL: %s: %s\n' "$case_name" "$*" >&2
    cat "$case_dir/output" "$case_dir/calls" >&2
    exit 1
}
new_case() {
    case_name=$1
    case_dir="$test_root/$case_name"
    mkdir -p "$case_dir/image-artifacts" "$case_dir/state"
    : > "$case_dir/calls"
    : > "$case_dir/output"
    for arch in amd64 arm64; do
        printf '%s\n' "$arch" | gzip > "$case_dir/image-artifacts/caddy-$arch.tar.gz"
    done
}
run_publisher() {
    local expected=$1 mode=$2 status=0
    shift 2
    (
        cd "$case_dir"
        env -i PATH="$test_root/bin:/usr/bin:/bin" HOME="$case_dir" \
            GITHUB_SHA="$sha" GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
            GITHUB_REPOSITORY=acme/project GITHUB_STEP_SUMMARY="$case_dir/summary" \
            DOCKERHUB_USERNAME=TestAccount DOCKERHUB_TOKEN=synthetic-test-token \
            MOCK_CALLS="$case_dir/calls" MOCK_STATE="$case_dir/state" \
            MOCK_AMD_DIGEST="$amd_digest" MOCK_ARM_DIGEST="$arm_digest" \
            "$@" bash "$publisher" "$mode"
    ) > "$case_dir/output" 2>&1 || status=$?
    if [[ $expected == success ]]; then
        [[ $status == 0 ]] || fail "Expected success; exit status $status"
    else
        [[ $status != 0 ]] || fail 'Expected rejection'
    fi
    if grep -Fq synthetic-test-token "$case_dir/output"; then fail 'Credential leaked to output'; fi
}
assert_no_calls() { [[ ! -s $case_dir/calls ]] || fail 'Unexpected external operation'; }
assert_no_push() {
    if grep -Eq $'^docker\t(push|buildx)\t' "$case_dir/calls"; then
        fail 'Registry write attempted before all artifacts were valid'
    fi
}
assert_line() {
    local expected
    expected=$(printf '%s\t' "$@")
    expected=${expected%$'\t'}
    grep -Fxq -- "$expected" "$case_dir/calls" || fail "Missing command: $expected"
}
assert_tags() {
    local expected
    expected=$(printf '%s\n' "$@")
    [[ $(cat "$case_dir/output") == "$expected" ]] || fail 'Unexpected image tags'
    assert_no_calls
}
pass() { passed=$((passed + 1)); }

new_case main-tags
run_publisher success tags
assert_tags "sha-$sha" latest
pass

new_case stable-release-tags
run_publisher success tags GITHUB_REF=refs/tags/v1.2.3
assert_tags "sha-$sha" 1.2.3
pass

new_case prerelease-tags
run_publisher success tags GITHUB_REF=refs/tags/v1.2.3-rc.1
assert_tags "sha-$sha" 1.2.3-rc.1
pass

new_case valid-numeric-and-alphanumeric-prerelease
run_publisher success tags GITHUB_REF=refs/tags/v1.2.3-0.01a.rc.10
assert_tags "sha-$sha" 1.2.3-0.01a.rc.10
pass

for event in pull_request pull_request_target; do
    new_case "reject-$event"
    run_publisher failure publish "GITHUB_EVENT_NAME=$event"
    assert_no_calls
    pass
done
for ref in refs/heads/feature refs/tags/v1.2 refs/tags/v01.2.3 \
    refs/tags/v1.2.3- refs/tags/v1.2.3-rc..1 refs/tags/v1.2.3-01 \
    refs/tags/v1.2.3-rc.01 refs/tags/v1.2.3+build.1; do
    new_case "reject-ref-$passed"
    run_publisher failure publish "GITHUB_REF=$ref" GITHUB_EVENT_NAME=workflow_dispatch
    assert_no_calls
    pass
done
for invalid_sha in short AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
    gggggggggggggggggggggggggggggggggggggggg; do
    new_case "reject-sha-$passed"
    run_publisher failure publish "GITHUB_SHA=$invalid_sha"
    assert_no_calls
    pass
done

new_case reject-oversized-release
printf -v long_identifier '%0130d' 0
run_publisher failure publish "GITHUB_REF=refs/tags/v1.2.3-rc$long_identifier"
assert_no_calls
pass

new_case valid-credentials
run_publisher success check
assert_no_calls
pass

new_case explicit-image-namespace
run_publisher success check DOCKERHUB_IMAGE=example-org/caddy-oidc-logout
assert_no_calls
pass

for missing in DOCKERHUB_USERNAME DOCKERHUB_TOKEN; do
    new_case "reject-missing-$missing"
    run_publisher failure check "$missing="
    assert_no_calls
    pass
done
for image in Example/image registry.example.com/acme/image registry.example.com/acme \
    localhost/image acme/image:latest \
    acme/image/extra 'acme/$(touch injected)' $'acme/image\nother/image'; do
    new_case "reject-image-$passed"
    run_publisher failure check "DOCKERHUB_IMAGE=$image"
    assert_no_calls
    [[ ! -e $case_dir/injected ]] || fail 'Image name was evaluated as shell code'
    pass
done

new_case missing-second-architecture
rm "$case_dir/image-artifacts/caddy-arm64.tar.gz"
run_publisher failure publish
assert_no_push
pass

new_case wrong-second-platform
run_publisher failure publish MOCK_PLATFORM_ARM64=linux/amd64
assert_no_push
pass

new_case wrong-second-operating-system
run_publisher failure publish MOCK_PLATFORM_ARM64=windows/arm64
assert_no_push
pass

new_case wrong-second-revision
run_publisher failure publish "MOCK_REVISION_ARM64=$new_sha"
assert_no_push
pass

new_case corrupt-second-archive
printf 'invalid gzip\n' > "$case_dir/image-artifacts/caddy-arm64.tar.gz"
run_publisher failure publish
assert_no_push
pass

new_case invalid-main-response
run_publisher failure publish MOCK_MAIN_SHA=invalid
assert_no_calls_except_gh=$(wc -l < "$case_dir/calls")
[[ $assert_no_calls_except_gh == 1 ]] || fail 'Publication continued without a valid main commit'
assert_no_push
pass

assert_promotion() {
    local image=$1
    shift
    local args=(docker buildx imagetools create) tag
    for tag in "$@"; do args+=(--tag "$image:$tag"); done
    args+=("$image@$amd_digest" "$image@$arm_digest")
    assert_line "${args[@]}"
    for arch in amd64 arm64; do
        assert_line docker tag "caddy-oidc-logout:test-$arch" "$image:sha-$sha-$arch"
        assert_line docker push "$image:sha-$sha-$arch"
    done
    [[ $(grep -c $'^docker\tload$' "$case_dir/calls") == 2 ]] || fail 'Expected both saved artifacts to be loaded'
    [[ $(grep -c $'^docker\tpush\t' "$case_dir/calls") == 2 ]] || fail 'Expected one push per architecture'
    # The second artifact's validation must finish before either push starts.
    local validation_line first_push_line
    validation_line=$(grep -nF $'docker\timage\tinspect\tcaddy-oidc-logout:test-arm64\t--format\t{{index .Config.Labels "org.opencontainers.image.revision"}}' "$case_dir/calls" | cut -d: -f1)
    first_push_line=$(grep -n $'^docker\tpush\t' "$case_dir/calls" | head -1 | cut -d: -f1)
    [[ $validation_line -lt $first_push_line ]] || fail 'Pushed before validating both artifacts'
    assert_line docker buildx imagetools inspect "$image:sha-$sha"
}

new_case promote-main
run_publisher success publish
assert_promotion testaccount/caddy-oidc-logout "sha-$sha" latest
grep -Fq 'testaccount/caddy-oidc-logout:latest' "$case_dir/summary" || fail 'Published tags missing from summary'
pass

new_case promote-stale-main
run_publisher success publish "MOCK_MAIN_SHA=$new_sha"
assert_promotion testaccount/caddy-oidc-logout "sha-$sha"
if grep -Fq ':latest' "$case_dir/calls" "$case_dir/summary"; then fail 'Stale main moved latest'; fi
pass

new_case promote-release
run_publisher success publish GITHUB_REF=refs/tags/v1.2.3 \
    DOCKERHUB_IMAGE=example-org/custom-caddy MOCK_DIGEST_PREFIX=docker.io/
assert_promotion example-org/custom-caddy "sha-$sha" 1.2.3
if grep -Eq $'^gh\t|:latest' "$case_dir/calls"; then fail 'Release must not consult main or move latest'; fi
pass

new_case reject-unusable-push-digest
run_publisher failure publish MOCK_DIGEST_AMD64=invalid
if grep -Fq $'docker\tbuildx\timagetools\tcreate' "$case_dir/calls"; then
    fail 'Promoted a manifest without valid pushed digests'
fi
pass

printf 'Publication regression checks passed (%s cases).\n' "$passed"
