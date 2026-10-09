#!/usr/bin/env bash
# Live-cluster check of the encrypted-volume flow (docs/volumes.md) end to end:
# operator-written key blobs, workload entries with argv policy and a secrets
# grant, and a busybox consumer per volume mode serving its plaintext over HTTP.
#
# Sequence:
#   1. PUT both pre-built volume key blobs into the CDS secret store
#      (two-phase flow: the lane built the images with `c8s volume create
#      --dry-run` before boot, because volume devices must be attached at VM
#      creation — there is no disk hotplug on the metal node kernels).
#   2. Allowlist the reader busybox invocation as a WORKLOAD entry (digest +
#      exact argv + secrets grant), run it, and curl its served secret back out
#      of the immutable volume.
#   3. Prove argv enforcement: the same image with a different argv is denied.
#   4. Allowlist the writer invocation, run it, and curl its served file out of
#      the mutable volume; delete and recreate the pod and read it again to
#      prove the write reached the ciphertext device, not a pod-local fs.
#
# Needs kubectl pointed at a cluster with C8s installed with --volumes, `c8s`
# and `crane` on PATH, the volume devices already attached to E2E_VOL_NODE
# (serials c8s-vol-<name>), and:
#   C8S_MEASUREMENTS    launch measurement pinning the CDS endpoint
#   C8S_OPERATOR_KEY    path to the operator EC key PEM pinned on CDS
#   E2E_VOL_NODE        node name the volume devices are attached to
#   E2E_VOL_IMM_ESCROW  escrow (key blob) file of the pre-built immutable volume
#   E2E_VOL_MUT_ESCROW  escrow file of the pre-built mutable volume
#   E2E_VOL_IMM_CONTENT exact bytes the immutable volume's secret.txt must serve
# Optional:
#   E2E_BUSYBOX         image ref for the consumers (default busybox:1.36 —
#                       1.38 is in the node image's baked floor, so it would
#                       not exercise the entries)
#   E2E_VOL_IMM_NAME / E2E_VOL_MUT_NAME   volume names (default imm / mut)
#   E2E_VOL_MUT_MARKER  bytes the writer writes; a single shell word, no quotes
#                       (default: c8s-e2e-mut-proof)
#   E2E_VOL_UID         numeric non-root UID/GID used by both consumers
#                       (default 65534). The immutable source must be readable
#                       and the mutable source root writable by this identity;
#                       c8s volume create --source preserves those modes.
#   E2E_CDS_LOCAL_PORT  local port for the CDS port-forward (default 18443)
#   E2E_MESH_CA         path to a pinned mesh CA bundle (default: read from the
#                       router pod, which serves the live CA on its cert volume)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

: "${C8S_MEASUREMENTS:?pins the launch measurement of the CDS endpoint}"
: "${C8S_OPERATOR_KEY:?path to the operator EC key PEM}"
: "${E2E_VOL_NODE:?node the c8s-vol-* devices are attached to}"
: "${E2E_VOL_IMM_ESCROW:?escrow blob of the pre-built immutable volume}"
: "${E2E_VOL_MUT_ESCROW:?escrow blob of the pre-built mutable volume}"
: "${E2E_VOL_IMM_CONTENT:?expected bytes of secret.txt in the immutable volume}"

BUSYBOX=${E2E_BUSYBOX:-busybox:1.36}
IMM=${E2E_VOL_IMM_NAME:-imm}
MUT=${E2E_VOL_MUT_NAME:-mut}
MARKER=${E2E_VOL_MUT_MARKER:-c8s-e2e-mut-proof}
CDS_PORT=${E2E_CDS_LOCAL_PORT:-18443}
VOL_UID=${E2E_VOL_UID:-65534}

[[ "$VOL_UID" =~ ^[1-9][0-9]*$ ]] \
  || fail "E2E_VOL_UID must be a positive numeric UID (got '$VOL_UID')"

ns=c8s-e2e-volumes               # opened for CW pods by cw_namespace below
READER=e2e-vol-reader
WRITER=e2e-vol-writer
DENIED=e2e-vol-denied
IMM_PATH=/e2e/volumes/$IMM       # secret-store path and volume-dir subtree share the name
MUT_PATH=/e2e/volumes/$MUT

# Both HTTP consumers pin this exact argv; the workload entries and the pod
# specs are generated from the same variables so they cannot drift apart. The
# scripts must stay free of double quotes and backslashes: they are embedded
# raw into JSON (the workload entry and the pod manifest).
reader_script="until [ -f /run/c8s/volumes/$IMM/secret.txt ]; do sleep 1; done; httpd -f -p 8080 -h /run/c8s/volumes/$IMM"
writer_script="until mountpoint -q /run/c8s/volumes/$MUT; do sleep 1; done; printf %s $MARKER > /run/c8s/volumes/$MUT/proof.txt; httpd -f -p 8080 -h /run/c8s/volumes/$MUT"

PF_PODS=""
cleanup() {
  for p in $PF_PODS ${PF_CDS:-}; do kill "$p" 2>/dev/null || true; done
  if cw_namespace_owned "$ns"; then
    kubectl delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    al delete "$READER" "$WRITER" >/dev/null 2>&1 || true
  fi
  return 0
}
trap cleanup EXIT
cw_namespace "$ns"

# Every CDS call goes over a port-forward: router fronts /allowlist but not
# /secrets, and the armTLS client verifies attestation rather than PKI
# hostnames, so one channel serves both APIs (README.md "Operator access").
kubectl -n c8s-system port-forward svc/c8s-cds "$CDS_PORT:8443" >/dev/null 2>&1 &
PF_CDS=$!
CDS_UP=""
for _ in $(seq 1 30); do
  curl -sk --max-time 2 -o /dev/null "https://127.0.0.1:$CDS_PORT/healthz" && { CDS_UP=1; break; }
  sleep 1
done
[ -n "$CDS_UP" ] || fail "CDS port-forward never came up"

c8s_conn() { c8s "$@" --url "https://127.0.0.1:$CDS_PORT" --measurements "$C8S_MEASUREMENTS"; }
al() { c8s_conn allowlist "$@"; }

# serve <pod> <local-port> — wait Ready, port-forward, and answer curl_poll.
serve() {
  kubectl -n "$ns" wait --for=condition=Ready "pod/$1" --timeout=240s >/dev/null \
    || { kubectl -n "$ns" describe pod "$1" | tail -25; fail "$1 never became Ready"; }
  kubectl -n "$ns" port-forward "pod/$1" "$2:8080" >/dev/null 2>&1 &
  PF_PODS="$PF_PODS $!"
}

# curl_poll <port> <path> — poll until the port-forwarded HTTP endpoint answers
# (connection refused while the pod's httpd is still waiting on its mount).
curl_poll() {
  local port=$1 path=$2 out=""
  for _ in $(seq 1 60); do
    out=$(curl -fsS --max-time 3 "http://127.0.0.1:$port$path" 2>/dev/null) && { printf %s "$out"; return 0; }
    sleep 3
  done
  return 1
}

# --- 1. key blobs into the store ---------------------------------------------

MESH_CA=${E2E_MESH_CA:-}
if [ -z "$MESH_CA" ]; then
  MESH_CA=$(mktemp)
  # Read it from CDS over the attested connection: the router's pod is a mesh
  # member, and a member admits no exec.
  c8s_conn cds ca --out "$MESH_CA" >/dev/null \
    || fail "could not read the mesh CA from CDS over armTLS"
fi

c8s_conn secrets put "$IMM_PATH" --from-file "$E2E_VOL_IMM_ESCROW" \
  --operator-key "$C8S_OPERATOR_KEY" --mesh-ca "$MESH_CA" >/dev/null \
  || fail "secrets put $IMM_PATH rejected"
echo "ok: immutable volume key blob stored at $IMM_PATH"
c8s_conn secrets put "$MUT_PATH" --from-file "$E2E_VOL_MUT_ESCROW" \
  --operator-key "$C8S_OPERATOR_KEY" --mesh-ca "$MESH_CA" >/dev/null \
  || fail "secrets put $MUT_PATH rejected"
echo "ok: mutable volume key blob stored at $MUT_PATH"

# --- 2. the reader: workload entry + pod + curl -------------------------------

digest=$(c8s allowlist inspect-image "$BUSYBOX" | awk '$1 == "digest:" { print $2 }')
[ -n "$digest" ] || fail "no digest resolved for $BUSYBOX"
image="$BUSYBOX@$digest"

entry() {
  # $1 = entry name, $2 = argv script, $3 = granted secret path
  cat <<EOF
{
  "$1": {
    "label": "$image",
    "initContainers": [],
    "containers": [
      {
        "digest": "$digest",
        "image": "$image",
        "command": { "policy": "exact", "argv": ["sh", "-c"] },
        "args":    { "policy": "exact", "argv": ["$2"] }
      }
    ],
    "secrets": { "policy": "allow", "read": ["$3"] }
  }
}
EOF
}

consumer_pod() {
  # $1 = pod name, $2 = cw entry name, $3 = volume name, $4 = secret path, $5 = argv script
  cat <<EOF
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "$1",
    "namespace": "$ns",
    "annotations": {
      "confidential.ai/cw": "$2",
      "confidential.ai/c8s-volumes": "$3=$4"
    }
  },
  "spec": {
    "nodeSelector": { "kubernetes.io/hostname": "$E2E_VOL_NODE" },
    "restartPolicy": "Never",
    "securityContext": {
      "runAsNonRoot": true,
      "runAsUser": $VOL_UID,
      "runAsGroup": $VOL_UID,
      "seccompProfile": { "type": "RuntimeDefault" }
    },
    "containers": [
      {
        "name": "app",
        "image": "$image",
        "command": ["sh", "-c"],
        "args": ["$5"],
        "securityContext": {
          "allowPrivilegeEscalation": false,
          "capabilities": { "drop": ["ALL"] }
        }
      }
    ]
  }
}
EOF
}

entry "$READER" "$reader_script" "$IMM_PATH" | al apply - >/dev/null \
  || fail "reader workload entry rejected"
echo "ok: reader workload entry applied (grant $IMM_PATH)"
# The plugin polls CDS for allowlist changes on a 5s interval.
sleep 8

consumer_pod "$READER" "$READER" "$IMM" "$IMM_PATH" "$reader_script" | kubectl apply -f - >/dev/null
serve "$READER" 18080
got=$(curl_poll 18080 /secret.txt) \
  || fail "reader never served /secret.txt (volume mount or httpd missing; check the c8s-volume sidecar logs)"
[ "$got" = "$E2E_VOL_IMM_CONTENT" ] \
  || fail "immutable volume served the wrong bytes: got '$got', want '$E2E_VOL_IMM_CONTENT'"
echo "ok: immutable volume decrypted, mounted, and served the exact sealed bytes over HTTP"

# --- 3. argv enforcement: same digest, an argv no entry declares --------------

cat <<EOF | kubectl apply -f - >/dev/null
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": { "name": "$DENIED", "namespace": "$ns" },
  "spec": {
    "nodeSelector": { "kubernetes.io/hostname": "$E2E_VOL_NODE" },
    "restartPolicy": "Never",
    "securityContext": {
      "runAsNonRoot": true,
      "runAsUser": $VOL_UID,
      "runAsGroup": $VOL_UID,
      "seccompProfile": { "type": "RuntimeDefault" }
    },
    "containers": [
      {
        "name": "app",
        "image": "$image",
        "command": ["sh", "-c"],
        "args": ["sleep 300"],
        "securityContext": {
          "allowPrivilegeEscalation": false,
          "capabilities": { "drop": ["ALL"] }
        }
      }
    ]
  }
}
EOF
argv_denied=""
for _ in $(seq 1 30); do
  msg=$(kubectl -n "$ns" get pod $DENIED \
    -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' 2>/dev/null || true)
  case "$msg" in *"satisfies no workload entry's argv policy"*) argv_denied=1; break ;; esac
  sleep 2
done
if [ -z "$argv_denied" ]; then
  kubectl -n "$ns" describe pod $DENIED | tail -20
  fail "SECURITY REGRESSION: $BUSYBOX with an undeclared argv was admitted;" \
       "workload argv policy is not enforced (waiting message: ${msg:-none})"
fi
echo "ok: same image with an undeclared argv denied (argv_not_admitted)"
kubectl -n "$ns" delete pod $DENIED --wait=true --timeout=60s >/dev/null

# --- 4. the writer: mutable volume, write + read + persistence -----------------

entry "$WRITER" "$writer_script" "$MUT_PATH" | al apply - >/dev/null \
  || fail "writer workload entry rejected"
echo "ok: writer workload entry applied (grant $MUT_PATH)"
sleep 8

consumer_pod "$WRITER" "$WRITER" "$MUT" "$MUT_PATH" "$writer_script" | kubectl apply -f - >/dev/null
serve "$WRITER" 18081
got=$(curl_poll 18081 /proof.txt) \
  || fail "writer never served /proof.txt (mutable mount or httpd missing)"
[ "$got" = "$MARKER" ] \
  || fail "mutable volume served the wrong bytes: got '$got', want '$MARKER'"
echo "ok: writer wrote the marker into the mutable volume and served it"

# Pod churn must not lose the write: the recreated pod's sidecar re-opens the
# same ciphertext device. The old mapping closes when the reaper sees the old
# pod's cgroup die (a sweep interval); the sidecar's retry budget covers it.
kubectl -n "$ns" delete pod $WRITER --wait=true --timeout=120s >/dev/null
for p in $PF_PODS; do kill "$p" 2>/dev/null || true; done
PF_PODS=""
consumer_pod "$WRITER" "$WRITER" "$MUT" "$MUT_PATH" "$writer_script" | kubectl apply -f - >/dev/null
serve "$WRITER" 18082
got=$(curl_poll 18082 /proof.txt) \
  || fail "recreated writer never served /proof.txt"
[ "$got" = "$MARKER" ] \
  || fail "mutable volume lost the write across a pod recreate: got '$got', want '$MARKER'"
echo "ok: write survived a pod delete+recreate (persisted on the ciphertext device)"

echo "PASS: encrypted volumes end to end — blob release, argv-scoped entries, immutable read, mutable write+persist"
