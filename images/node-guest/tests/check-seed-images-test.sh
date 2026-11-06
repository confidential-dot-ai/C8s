#!/usr/bin/env bash
set -euo pipefail
checker="$(dirname "$0")/../c8s/check-seed-images.sh"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
printf 'example.com/core@sha256:abc\n' > "$test_dir/images.txt"
for slot in containers initContainers; do
    jq -n --arg slot "$slot" '{workloads:{core:{($slot):[{image:"example.com/core@sha256:abc",digest:"sha256:abc"}]}}}' > "$test_dir/seed.json"
    bash "$checker" "$test_dir/seed.json" "$test_dir/images.txt"
    jq --arg slot "$slot" '.workloads.core[$slot][0].image="core@sha256:abc"' \
        "$test_dir/seed.json" > "$test_dir/alias.json"
    bash "$checker" "$test_dir/alias.json" "$test_dir/images.txt"
    jq --arg slot "$slot" '.workloads.helper={($slot):[{image:"busybox@sha256:stale",digest:"sha256:stale"}]}' \
        "$test_dir/seed.json" > "$test_dir/stale.json"
    if bash "$checker" "$test_dir/stale.json" "$test_dir/images.txt"; then
        echo "FAIL: extra $slot image admitted" >&2
        exit 1
    fi
    jq --arg slot "$slot" '.workloads.core[$slot][0].digest="sha256:stale"' \
        "$test_dir/seed.json" > "$test_dir/mismatched.json"
    if bash "$checker" "$test_dir/mismatched.json" "$test_dir/images.txt"; then
        echo "FAIL: stale $slot digest with rendered image label admitted" >&2
        exit 1
    fi
done
printf 'PASS: rendered seed images; extra regular/init images rejected\n'
