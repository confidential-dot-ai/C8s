#!/usr/bin/env bash
# Shared privileged suite for required CI and coverage. Extra arguments are
# go test flags, such as -race or -coverprofile; the working tree is the subject.
set -euo pipefail

runner="env C8S_REQUIRE_NFT=1"
[ "$(id -u)" = 0 ] || runner="sudo -n $runner"
# The coverage gate measures the base revision with the head's copy of this
# script, so a package the base does not have yet is left out, not an error.
packages=()
for package in ./internal/podmesh/ruleset ./internal/cmds/nri-image-policy \
  ./internal/cmds/armtlsmesh ./internal/cmds/getcert; do
  [ -d "$package" ] && packages+=("$package")
done
# Real BPF link creation in one package must not race another's global scan.
go test -p 1 -count=1 -exec "$runner" \
  -run 'InTheNamespace|^TestNodeImagePodRoleConfig_StartsAndRetainsServedPolicy$|^TestPodCredentialRoot|^TestPodBroker|^TestPodRecovery|^TestPodIdentityServesTheConnectBroker|^TestEndpointStartWakesTheBroker|^TestRecoverMatchesTheSandboxNamespaceByIdentity|^TestPodTransportProcess|^TestGuest' \
  "$@" "${packages[@]}"
