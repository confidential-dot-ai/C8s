#!/usr/bin/env bash
# Called only by the isolated manual fixture leg. Production defaults never use it.
set -euo pipefail
mode=$1
baseline=$(realpath -e "$2")
overlay=$(realpath -e "$3")
work=$(realpath -m "$4")
fixture="$overlay/test/tdxpod/fixtures/pod-recovery"
test "$(git -C "$baseline" rev-parse HEAD)" = 05211a8b106415a0aefd5f47bc40b266b0c1dacd
test -z "$(git -C "$baseline" status --porcelain)"
test "$(git -C "$overlay" rev-parse HEAD)" = "$GITHUB_SHA"
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]
test "${GITHUB_EVENT_NAME:-}" = workflow_dispatch

case "$mode" in
prepare)
    test ! -e "$work"
    mkdir -p "$work"
    # Resolve the same immutable component inputs before the production sync.
    while IFS=$'\t' read -r name ref; do
        actual=$(oras resolve "ghcr.io/confidential-dot-ai/$name:05211a8")
        test "${ref##*@}" = "$actual"
    done < <(jq -r '.components | to_entries[] | [.key,.value] | @tsv' "$fixture/baseline.json")
    cp -a "$fixture/profile" "$work/pod-recovery"
    chmod +x "$work/pod-recovery/mkosi.finalize"
    mkdir -p "$work/pod-recovery/mkosi.extra/usr/local/libexec"
    (
        cd "$overlay"
        GOTOOLCHAIN=go1.27.3 GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
            go build -trimpath -o "$work/pod-recovery/mkosi.extra/usr/local/libexec/pod-recovery-fixture" \
            ./test/tdxpod/fixtures/pod-recovery/controller
    )
    test -z "$(git -C "$overlay" status --porcelain)"
    go version -m "$work/pod-recovery/mkosi.extra/usr/local/libexec/pod-recovery-fixture" > "$work/controller-build.txt"
    grep -q 'vcs.modified=false' "$work/controller-build.txt"
    grep -q "vcs.revision=$GITHUB_SHA" "$work/controller-build.txt"
    ;;
verify)
    # Download the captured production disk by immutable blob digest. The same
    # receipt's OCI descriptors were independently checked before this fixture.
    disk=$(jq -r .diskSHA256 "$fixture/baseline.json")
    oras blob fetch "ghcr.io/confidential-dot-ai/node-guest-base@sha256:$disk" --output "$work/baseline.raw"
    printf '%s  %s\n' "$disk" "$work/baseline.raw" | sha256sum -c -
    built=$(jq -r .outputs.disk_image.sha256 "${5%/*}/manifest.json")
    [[ "$built" =~ ^[0-9a-f]{64}$ ]]
    printf '%s  %s\n' "$built" "$5" | sha256sum -c -
    sudo --preserve-env=GITHUB_SHA bash "$fixture/verify-roots.sh" \
        "$work/baseline.raw" "$5" "$fixture" "$work"
    ;;
capture)
    python3 "$fixture/capture.py" "$work" "$5" "$GITHUB_RUN_ID" "$GITHUB_SHA"
    ;;
*) echo 'unknown fixture build phase' >&2; exit 1 ;;
esac
