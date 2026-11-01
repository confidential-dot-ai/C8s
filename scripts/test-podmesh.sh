#!/usr/bin/env bash
# Shared privileged suite for required CI and coverage. Extra arguments are
# go test flags, such as -race or -coverprofile; the working tree is the subject.
set -euo pipefail

runner="env C8S_REQUIRE_NFT=1"
[ "$(id -u)" = 0 ] || runner="sudo -n $runner"
go test -count=1 -exec "$runner" \
  -run 'InTheNamespace|^TestNodeImagePodRoleConfig_StartsAndRetainsServedPolicy$|^TestPodCredentialRoot|^TestPodBroker|^TestGuest' \
  "$@" ./internal/podmesh/ruleset ./internal/cmds/nri-image-policy \
  ./internal/cmds/armtlsmesh ./internal/cmds/getcert
