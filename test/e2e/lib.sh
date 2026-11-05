#!/usr/bin/env bash
# Shared helpers for the live-cluster e2e checks under test/e2e/. Source it
# after `set -euo pipefail`:
#
#   . "$(dirname "$0")/lib.sh"

# fail prints a FAIL: line to stderr and exits non-zero. The "FAIL:" prefix is
# the convention CI greps for, so keep both scripts on this one definition.
fail() { echo "FAIL: $*" >&2; exit 1; }

# cw_namespace creates a new namespace with the current Restricted profile.
# Refuse to adopt an existing namespace: callers may clean up only one they
# created. Credential sidecars receive their claims socket through NRI, so
# confidential workloads need no PodSecurity exemption.
cw_namespace() {
  CW_NAMESPACE_CREATED=
  kubectl create namespace "$1" >/dev/null || return
  CW_NAMESPACE_CREATED=$1
  kubectl label namespace "$1" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted >/dev/null
}

# cw_namespace_owned lets cleanup check ownership without adopting old state.
cw_namespace_owned() { [ "${CW_NAMESPACE_CREATED:-}" = "$1" ]; }

# cds_measurement_args fills the measurement_args array with the CDS endpoint
# pin: a complete policy file (C8S_MEASUREMENTS_CONFIG) when supplied, else the
# launch-only digest (C8S_MEASUREMENTS), which is then required.
# shellcheck disable=SC2034  # the array is consumed by the sourcing script
cds_measurement_args() {
  if [ -n "${C8S_MEASUREMENTS_CONFIG:-}" ]; then
    measurement_args=(--image-policy-file "$C8S_MEASUREMENTS_CONFIG")
  else
    : "${C8S_MEASUREMENTS:?pins the launch measurement of the CDS endpoint}"
    measurement_args=(--measurements "$C8S_MEASUREMENTS")
  fi
}

# cds_write <command...> runs one signed CDS write, such as `c8s allowlist
# add`. A CDS without persistence refuses operator tokens for
# --jwt-clock-skew (30s) after it starts (docs/operator.md, "CDS is a
# singleton"), and the first write of a lane can land inside that window, so
# that refusal is retried, re-running the command for a fresh token, for
# longer than the window. Any other outcome returns at once with the
# command's status, its stdout and its stderr.
cds_write() {
  local status err noted=
  for _ in $(seq 1 20); do
    status=0
    { err=$("$@" 2>&1 >&3); } 3>&1 || status=$?
    if [ "$status" -eq 0 ] || [[ "$err" != *'issued too early'* ]]; then
      if [ -n "$err" ]; then printf '%s\n' "$err" >&2; fi
      return "$status"
    fi
    if [ -z "$noted" ]; then
      echo "note: CDS refuses operator tokens until --jwt-clock-skew after it starts; retrying the write with a fresh token" >&2
      noted=1
    fi
    sleep 2
  done
  printf '%s\n' "$err" >&2
  return "$status"
}
