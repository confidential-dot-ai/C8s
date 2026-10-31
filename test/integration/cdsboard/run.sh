#!/usr/bin/env bash
# The decree board against a real object store: the requests
# internal/cdsboard makes, answered by an S3-compatible store instead of the
# server in test code.
#
#   test/integration/cdsboard/run.sh
#
# The store speaks plain HTTP, and nginx in the same network namespace serves
# HTTPS in front of it with a certificate this run generates, because a
# replica addresses its board over HTTPS with the image's system roots. Only
# the HTTPS port is published, on loopback, which is the whole of the store's
# network scope: a board carries signed objects and no credentials.
#
# Linux only: the client reads the certificate through SSL_CERT_FILE.
# Needs docker, go, openssl and curl.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)/../../.."

# Bump both pins with their release; the store is any S3-compatible one.
STORE_IMAGE=chrislusf/seaweedfs:4.51@sha256:f7a49e3f3972ebed5be2ed4befa4a0c68eb7bdddba6e692d42729ceb545134b8
TLS_IMAGE=nginx:1.30-alpine@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949
STORE_CONTAINER=c8s-cdsboard-store
TLS_CONTAINER=c8s-cdsboard-tls
# The store answers plain HTTP here, and the front door HTTPS there.
STORE_PORT=9000
BOARD_PORT=9443
BUCKET=c8s-boards
PREFIX=lanes
CLUSTER=lane

work=$(mktemp -d)
cleanup() {
  docker rm -f "$TLS_CONTAINER" "$STORE_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  docker logs "$STORE_CONTAINER" --tail 30 2>&1 || true
  docker logs "$TLS_CONTAINER" --tail 30 2>&1 || true
  exit 1
}

# waiting runs a command every second until it succeeds, for up to a minute.
waiting() {
  local what="$1"
  shift
  for _ in $(seq 1 60); do
    "$@" && return 0
    sleep 1
  done
  fail "$what"
}

for tool in docker go openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool not available" >&2; exit 1; }
done

echo "=== The certificate the board serves ==="
# One self-signed certificate for the loopback address the configuration
# names, which the client reads as its system roots.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -days 1 -subj "/CN=c8s-cdsboard" -addext "subjectAltName=IP:127.0.0.1" \
  -keyout "$work/board.key" -out "$work/board.pem" 2>/dev/null \
  || fail "could not generate the board's certificate"
cat > "$work/nginx.conf" <<EOF
events {}
http {
  server {
    listen 127.0.0.1:$BOARD_PORT ssl;
    ssl_certificate     /tls/board.pem;
    ssl_certificate_key /tls/board.key;
    location / {
      proxy_pass http://127.0.0.1:$STORE_PORT;
      proxy_set_header Host \$host;
    }
  }
}
EOF

echo "=== The store and the front door ==="
docker rm -f "$TLS_CONTAINER" "$STORE_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$STORE_CONTAINER" \
  -p "127.0.0.1:$BOARD_PORT:$BOARD_PORT" --tmpfs /data \
  "$STORE_IMAGE" server -dir=/data -s3 "-s3.port=$STORE_PORT" -ip.bind=0.0.0.0 >/dev/null \
  || fail "could not start the store"
# The front door shares the store's network namespace, so it reaches the
# store on loopback and answers on the one published port.
docker run -d --name "$TLS_CONTAINER" \
  --network "container:$STORE_CONTAINER" \
  -v "$work:/tls:ro" -v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" \
  "$TLS_IMAGE" >/dev/null \
  || fail "could not start the board's front door"

board="https://127.0.0.1:$BOARD_PORT"
on_board=(curl -sS --cacert "$work/board.pem" --max-time 10)
answers() { "${on_board[@]}" -o /dev/null "$board/" 2>/dev/null; }
# Any answer is the store serving; its root is not a key this client reads.
waiting "the store never answered at $board" answers

echo "=== The bucket the boards lie in ==="
"${on_board[@]}" -f -X PUT -o /dev/null "$board/$BUCKET" || fail "could not create the bucket $BUCKET"
# The store must admit this client before the client is judged on it: it
# carries no credentials, and the store admits it by network scope alone.
"${on_board[@]}" -f -X PUT --data-binary "probe" -o /dev/null "$board/$BUCKET/$PREFIX/$CLUSTER/lane-probe" \
  || fail "the store refused an unauthenticated write: this lane needs a store that admits its client by network scope"

echo "=== The client against the store ==="
C8S_BOARD_ENDPOINT="$board" \
C8S_BOARD_BUCKET="$BUCKET" \
C8S_BOARD_PREFIX="$PREFIX" \
C8S_BOARD_CLUSTER="$CLUSTER" \
SSL_CERT_FILE="$work/board.pem" \
  go test -tags integration -count=1 -timeout 5m -v -run 'TestARealStore' ./internal/cdsboard/ \
  || fail "the board client against $STORE_IMAGE"

echo "PASS: the decree board against a real object store"
