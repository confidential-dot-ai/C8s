#!/usr/bin/env bash
# The acme front door for the confidential-inference e2e: a pebble ACME CA on
# the runner, and a public name for the guest that is fixed before boot.
#
# The name must resolve on the runner (pebble's HTTP-01 check) and in the
# guest (the acme sidecar probes its own public challenge path before an
# order), and it is signed into the launch, so it cannot wait for the VM's
# pod IP. A Service in front of the virt-launcher pod gets its ClusterIP
# before the VM starts; <ip>.sslip.io resolves to it everywhere.
#
# The guest trusts pebble's directory TLS through launch-config
# --acme-ca-file. Pebble's issuing root is fetched after it starts and given
# to TEErminator with `certs add`.
#
# Env: VM, NS, CIE_DIR. Writes $CIE_DIR/front-door.env and leaves pebble
# running in the background.
set -euo pipefail
: "${VM:?}" "${NS:?}" "${CIE_DIR:?}"
cd "$CIE_DIR"

PEBBLE_VERSION=v2.10.1
PEBBLE_SHA256=4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed

kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $VM-front
  namespace: $NS
  labels: {ci.confidential.ai/managed: "true"}
spec:
  selector: {kubevirt.io/domain: $VM}
  ports:
    - {name: http, port: 80}
    - {name: https, port: 443}
EOF
front_ip=$(kubectl -n "$NS" get service "$VM-front" -o jsonpath='{.spec.clusterIP}')
[[ "$front_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::no IPv4 ClusterIP for $VM-front"; exit 1; }
hostname=${front_ip//./-}.sslip.io
runner_ip=$(hostname -I | awk '{print $1}')

curl -fsSL --retry 4 -o pebble.tgz "https://github.com/letsencrypt/pebble/releases/download/$PEBBLE_VERSION/pebble-linux-amd64.tar.gz"
echo "$PEBBLE_SHA256  pebble.tgz" | sha256sum -c -
tar -xzf pebble.tgz --strip-components 3 -C bin pebble-linux-amd64/linux/amd64/pebble

# Pebble's own TLS, for the address the guest dials.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=c8s-e2e-pebble-ca -keyout acme-ca.key -out acme-ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=pebble \
  -keyout pebble.key -out pebble.csr
openssl x509 -req -in pebble.csr -CA acme-ca.pem -CAkey acme-ca.key -CAcreateserial -days 1 \
  -extfile <(printf 'subjectAltName=IP:%s,IP:127.0.0.1\n' "$runner_ip") -out pebble.crt
cat > pebble.json <<EOF
{"pebble": {
  "listenAddress": "0.0.0.0:14000",
  "managementListenAddress": "127.0.0.1:15000",
  "certificate": "$CIE_DIR/pebble.crt",
  "privateKey": "$CIE_DIR/pebble.key",
  "httpPort": 80,
  "tlsPort": 443,
  "ocspResponderURL": "",
  "externalAccountBindingRequired": false
}}
EOF
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 nohup bin/pebble -config pebble.json > pebble.log 2>&1 &
for _ in $(seq 1 30); do
  curl -fs --cacert acme-ca.pem "https://127.0.0.1:14000/dir" >/dev/null && break
  sleep 1
done
curl -fs --cacert acme-ca.pem "https://127.0.0.1:14000/dir" >/dev/null || { cat pebble.log; echo "::error::pebble did not start"; exit 1; }

cat > front-door.env <<EOF
FRONT_DOOR_MODE=acme
SERVER_NAME=$hostname
ACME_DIRECTORY_URL=https://$runner_ip:14000/dir
EOF
echo "acme front door: $hostname, pebble at $runner_ip"
