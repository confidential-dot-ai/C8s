#!/usr/bin/env bash
# Integration test for the router.
# Starts the mock attestation-api and mock CDS, runs get-cert as an init
# container through the real armTLS attestation flow, and verifies nginx
# serves HTTPS with the issued certificate, chained to the mock CDS CA.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

WORKDIR="$(mktemp -d)"
COMPOSE_CMD="docker compose"

cleanup() {
    echo "--- Cleaning up ---"
    $COMPOSE_CMD down -v --remove-orphans 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    $COMPOSE_CMD logs 2>&1 || true
    exit 1
}

# Hard prerequisites: a missing tool fails the run.
for tool in docker make openssl curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool not available" >&2; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "FAIL: docker compose (v2) not available" >&2; exit 1; }

echo "=== Building get-cert binary ==="
make -C "$REPO_ROOT" build-c8s

echo "=== Building and starting services ==="
# Clean slate: a reused tls-certs volume pairs a stale leaf with a fresh CA.
$COMPOSE_CMD down -v --remove-orphans 2>/dev/null || true
$COMPOSE_CMD build || fail "image build failed"
$COMPOSE_CMD up -d || fail "services did not start"

# The chain anchor, fetched out-of-band from the mock CDS container.
$COMPOSE_CMD cp mock-cds:/ca/mock-cds-ca.pem "$WORKDIR/mock-cds-ca.pem" || fail "could not fetch the mock CDS CA"
CACERT="$WORKDIR/mock-cds-ca.pem"

# Verified HTTPS access to the LB: the chain is checked against the mock CDS
# CA and the hostname against the leaf SAN.
LB="https://nginx-lb:8443"
CURL=(curl -sS --cacert "$CACERT" --resolve nginx-lb:8443:127.0.0.1)

echo ""
echo "=== Verifying TLS endpoint ==="

# Wait for nginx to be ready (it depends on get-cert completing).
ready=0
for _ in $(seq 1 30); do
    if "${CURL[@]}" "$LB/healthz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" -eq 1 ] || fail "nginx did not become ready in time"

CHECKS=0

# Test 1: Health endpoint works over verified TLS.
HEALTH_RESPONSE=$("${CURL[@]}" "$LB/healthz") || fail "healthz request failed"
[ "$HEALTH_RESPONSE" = "ok" ] || fail "expected 'ok' from /healthz, got: $HEALTH_RESPONSE"
CHECKS=$((CHECKS + 1))
echo "PASS: /healthz returns ok over a verified chain"

# Test 2: Proxied backend content is served.
BODY=$("${CURL[@]}" "$LB/") || fail "proxy request failed"
echo "$BODY" | grep -q "Welcome to nginx" || fail "expected nginx welcome page from proxy, got: $BODY"
CHECKS=$((CHECKS + 1))
echo "PASS: reverse proxy serves backend content"

# The leaf nginx serves, for the certificate checks.
LEAF="$WORKDIR/leaf.pem"
echo | openssl s_client -connect 127.0.0.1:8443 -servername nginx-lb 2>/dev/null | openssl x509 >"$LEAF" 2>/dev/null || true
[ -s "$LEAF" ] || fail "could not read the served certificate"

# Test 3: Certificate chains to the mock CDS CA.
openssl verify -CAfile "$CACERT" "$LEAF" >/dev/null || fail "served certificate does not chain to the mock CDS CA"
CHECKS=$((CHECKS + 1))
echo "PASS: certificate chains to the mock CDS CA"

# Test 4: Certificate has the expected SAN.
SAN_INFO=$(openssl x509 -in "$LEAF" -noout -ext subjectAltName 2>/dev/null) || fail "served certificate carries no SAN extension"
echo "$SAN_INFO" | grep -qE 'DNS:nginx-lb(,|$)' || fail "certificate lacks SAN DNS:nginx-lb: $SAN_INFO"
CHECKS=$((CHECKS + 1))
echo "PASS: certificate contains SAN DNS:nginx-lb"

# Test 5: Certificate carries an ECDSA P-256 key.
KEY_INFO=$(openssl x509 -in "$LEAF" -noout -text 2>/dev/null) || fail "could not read the served certificate"
echo "$KEY_INFO" | grep -q "Public Key Algorithm: id-ecPublicKey" || fail "certificate is not an ECDSA certificate"
echo "$KEY_INFO" | grep -q "prime256v1" || fail "certificate key is not P-256"
CHECKS=$((CHECKS + 1))
echo "PASS: certificate uses an ECDSA P-256 key"

# Test 6: the leaf names the sandbox the mock inventory asserted, in the
# workload-instance extension (1.3.6.1.4.1.66378.1.4) mock CDS stamped after
# verifying the signed token.
SANDBOX_ID=$($COMPOSE_CMD logs mock-inventory 2>/dev/null | grep -o 'sandbox_id=[A-Za-z0-9._-]\{1,128\}' | head -1 | cut -d= -f2) || true
[ -n "$SANDBOX_ID" ] || fail "the mock inventory asserted no sandbox"
SANDBOX_EXT=$(echo "$KEY_INFO" | grep -A1 -F "1.3.6.1.4.1.66378.1.4") || fail "certificate carries no workload-instance extension"
echo "$SANDBOX_EXT" | grep -qF "$SANDBOX_ID" || fail "certificate does not name sandbox $SANDBOX_ID: $SANDBOX_EXT"
CHECKS=$((CHECKS + 1))
echo "PASS: certificate names the asserted workload instance"

# Test 7: the three reader paths resolve into one published generation, so a
# consumer reads a whole credential set or nothing.
GENERATIONS=$($COMPOSE_CMD exec -T tls-holder sh -c \
    'for f in cert.pem key.pem ca.pem; do dirname "$(readlink -f /tls/$f)"; done | sort -u') \
    || fail "could not resolve the reader paths"
[ "$(echo "$GENERATIONS" | wc -l)" -eq 1 ] || fail "reader paths resolve into different generations: $GENERATIONS"
echo "$GENERATIONS" | grep -qE '^/tls/generations/[ab]$' || fail "reader paths bypass the generation layout: $GENERATIONS"
CHECKS=$((CHECKS + 1))
echo "PASS: cert, key and CA resolve into one generation ($GENERATIONS)"

echo ""
echo "=== All $CHECKS integration checks passed ==="
