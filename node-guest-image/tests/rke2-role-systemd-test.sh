#!/bin/bash
# Boot real systemd with production host bootstrap units and role conditions.
# The test replaces service payloads and device/verifier I/O only; dependency
# ordering, Requires= failures, role selection and presets remain production.
# Driver mode needs Docker; --inside runs only in its disposable container.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" != --inside ]]; then
    command -v docker >/dev/null || { echo "docker required" >&2; exit 2; }
    IMG=c8s-launch-systemd-test
    CTR=c8s-launch-systemd-$$
    docker build -q -t "$IMG" - <<'EOF' >/dev/null
FROM debian:12
# python3 provides http.server and json for the fake Cilium agent.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv python3 && apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
EOF
    trap 'docker rm -f "$CTR" >/dev/null 2>&1 || true' EXIT
    docker run -d --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        --name "$CTR" "$IMG" >/dev/null
    state=""
    for _ in $(seq 1 30); do
        state=$(docker exec "$CTR" systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) break ;; esac
        sleep 1
    done
    case "$state" in running|degraded) ;; *) echo "systemd failed to settle: $state" >&2; exit 2 ;; esac
    docker cp "$TESTS_DIR/.." "$CTR":/ngi >/dev/null
    # The stale Cilium address case runs the real c8s command.
    command -v go >/dev/null || { echo "go required" >&2; exit 2; }
    BIN=$(mktemp -d)
    trap 'docker rm -f "$CTR" >/dev/null 2>&1 || true; rm -rf "$BIN"' EXIT
    (cd "$TESTS_DIR/../.." && CGO_ENABLED=0 GOOS=linux go build -o "$BIN/c8s" ./cmd/c8s)
    docker cp "$BIN/c8s" "$CTR":/usr/local/lib/c8s-real >/dev/null
    docker exec "$CTR" bash /ngi/tests/rke2-role-systemd-test.sh --inside
    exit $?
fi
[[ $EUID == 0 && $(cat /proc/1/comm) == systemd ]] || { echo "--inside requires disposable root systemd" >&2; exit 2; }
. "$TESTS_DIR/lib.sh"
. "$TESTS_DIR/launch-fixtures.sh"
EXTRA=$TESTS_DIR/../c8s/mkosi.extra
SOURCE_UNITS=$EXTRA/etc/systemd/system
UNITDIR=/usr/local/lib/systemd/system
mkdir -p "$UNITDIR" /dev/disk/by-label

for p in etc/systemd/system/rke2-role.service \
         etc/systemd/system/apparmor-enforce.service \
         etc/systemd/system/rke2-server.service.d/no-modprobe.conf \
         etc/systemd/system/rke2-agent.service.d/no-modprobe.conf \
         etc/systemd/system/rke2-server.service.d/20-role.conf \
         etc/systemd/system/rke2-agent.service.d/20-role.conf \
         etc/tmpfiles.d/confos-rke2.conf \
         usr/lib/systemd/system-preset/50-rke2.preset; do
    install -D -m644 "$EXTRA/$p" "/$p"
done
install -D -m755 "$EXTRA/usr/local/bin/rke2-role.sh" /usr/local/bin/rke2-role.sh
install_launch_stubs /usr/local/bin
install -D -m644 /dev/stdin /etc/systemd/system/rke2-role.service.d/90-test.conf <<EOF
[Service]
Environment=CRED_PLATFORM=tdx
Environment=C8S_ROLE_FIXTURE=$C8S_ROLE_FIXTURE
EOF

# Exercise the production dependency/preset wiring without changing the
# test host's AppArmor policy or letting FailureAction power it off. The
# isolated apparmor-enforce-test.sh separately executes the unchanged probe.
install -D -m644 /dev/stdin /etc/systemd/system/apparmor-enforce.service.d/test.conf <<'EOF'
[Unit]
FailureAction=none
[Service]
ExecStart=
ExecStart=/bin/test ! -e /run/apparmor-enforce-test-fail
EOF
install -D -m644 /dev/stdin "$UNITDIR/apparmor.service" <<'EOF'
[Unit]
Description=fake stock AppArmor loader
[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

# RKE2's tarball units and the external attester are the only units not
# available in this repository. Their test payloads wait indefinitely.
for u in rke2-server rke2-agent attestation-api; do
    install -D -m644 /dev/stdin "$UNITDIR/$u.service" <<EOF
[Unit]
Description=test $u payload
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
EOF
done

# Application services are Kubernetes workloads. These host services retain
# the authenticated launch dependency before any pod can start.
core_units=(attest-proxy.service cred-release.service nri-node-ip.service cilium-node-ip.service)

for unit in "${core_units[@]}"; do
    install -D -m644 "$SOURCE_UNITS/$unit" "/etc/systemd/system/$unit"
    install -D -m644 /dev/stdin "/etc/systemd/system/$unit.d/90-test-payload.conf" <<'EOF'
[Service]
Type=simple
ExecStartPre=
ExecStart=
ExecStart=/bin/sleep infinity
ExecStartPost=
ExecStop=
EOF
done

systemctl daemon-reload
payload_units=(rke2-server.service rke2-agent.service "${core_units[@]}")
active() { systemctl is-active --quiet "$1"; }
not_active() { ! active "$1"; }
cond_skipped() { [[ $(systemctl show -p ConditionResult --value "$1") == no ]]; }
boot_roles() { systemctl start "${payload_units[@]}"; }
scenario_reset() {
    systemctl stop "${payload_units[@]}" rke2-role.service attestation-api.service apparmor-enforce.service >/dev/null 2>&1 || true
    systemctl reset-failed >/dev/null 2>&1 || true
    reset_launch_fixture
    rm -f /dev/disk/by-label/opkeydata /run/apparmor-enforce-test-fail
    systemd-tmpfiles --create /etc/tmpfiles.d/confos-rke2.conf
    # Paths mounted read-only by production hardening normally exist after
    # RKE2 initializes. Payload stubs need empty equivalents for its sandbox.
    mkdir -p /etc/confai /etc/rancher/rke2 \
        /var/lib/rancher/rke2/server/tls /var/lib/rancher/rke2/agent
}

CASE=presets
systemctl enable apparmor.service >/dev/null 2>&1
ok "production preset applies" systemctl preset rke2-role.service apparmor-enforce.service apparmor.service "${payload_units[@]}"
for unit in rke2-role.service apparmor-enforce.service "${payload_units[@]}"; do
    ok "$unit enabled" systemctl is-enabled --quiet "$unit"
done

ok "preset disables the stock AppArmor loader" \
    test "$(systemctl is-enabled apparmor.service 2>/dev/null || true)" = disabled
for role in server agent; do
    ok "AppArmor is required by rke2-$role" \
        test -L "/etc/systemd/system/rke2-$role.service.requires/apparmor-enforce.service"
done

for role in server agent; do
    CASE="boot-$role"
    scenario_reset
    launch_media "$role"
    : > /dev/disk/by-label/opkeydata
    ok "selected role boots" boot_roles
    ok "launch verification is active" active rke2-role.service
    ok "AppArmor gate is active" active apparmor-enforce.service
    selected=rke2-server.service; skipped=rke2-agent.service
    if [[ $role == agent ]]; then selected=rke2-agent.service; skipped=rke2-server.service; fi
    ok "$selected active" active "$selected"
    ok "$skipped inactive" not_active "$skipped"
    ok "$skipped condition skipped" cond_skipped "$skipped"
    for unit in "${core_units[@]}"; do
        if [[ $role == agent ]] && grep -qF 'ConditionPathExists=/run/confos/role-server' "$SOURCE_UNITS/$unit"; then
            ok "$unit inactive on agent" not_active "$unit"
            ok "$unit condition skipped on agent" cond_skipped "$unit"
        else
            ok "$unit active on $role" active "$unit"
        fi
    done
done

for scenario in missing-launch invalid-signature prepare-failure; do
    CASE="boot-$scenario"
    scenario_reset
    if [[ $scenario != missing-launch ]]; then
        launch_media server
        : > /dev/disk/by-label/opkeydata
    fi
    case "$scenario" in
        invalid-signature) printf '%s\n' invalid > "$C8S_ROLE_FIXTURE/media/launch.yaml.sig" ;;
        prepare-failure) : > "$C8S_ROLE_FIXTURE/prepare-fails" ;;
    esac
    ok "startup fails visibly" not boot_roles
    ok "launch unit failed" systemctl is-failed --quiet rke2-role.service
    ok "no role authorized" no_launch_markers
    for unit in "${payload_units[@]}"; do ok "$unit stayed down" not_active "$unit"; done
done

for role in server agent; do
    CASE="boot-$role-AppArmor-failure"
    scenario_reset
    launch_media "$role"
    : > /dev/disk/by-label/opkeydata
    : > /run/apparmor-enforce-test-fail
    ok "failed AppArmor gate blocks boot" not boot_roles
    ok "AppArmor failure is visible" systemctl is-failed --quiet apparmor-enforce.service
    ok "server stays down" not_active rke2-server.service
    ok "agent stays down" not_active rke2-agent.service
done

# A node that came back with a new address has a Cilium agent announcing the
# previous one. The production unit runs the real command against a fake agent
# (its API socket, comm and pod cgroup) and must restart only that one.
CASE=cilium-node-ip-restarts-stale-agent
scenario_reset
launch_media agent
: > /dev/disk/by-label/opkeydata
# Drop the payload stub installed for every core unit above: this case runs
# the production unit.
run_production_unit() {
    rm -f "/etc/systemd/system/$1.d/90-test-payload.conf"
    systemctl daemon-reload
}
run_production_unit cilium-node-ip.service
mkdir -p /run/nri-image-policy
echo 192.0.2.10 > /run/nri-image-policy/node-ip
install -D -m755 /dev/stdin /usr/local/bin/cilium-agent <<'EOF'
#!/usr/bin/python3
import http.server, json, os, socketserver, sys
path = "/var/run/cilium/cilium.sock"
os.makedirs(os.path.dirname(path), exist_ok=True)
if os.path.exists(path):
    os.unlink(path)
class H(http.server.BaseHTTPRequestHandler):
    def address_string(self):
        return "local"
    def do_GET(self):
        body = json.dumps({"self": "default/n", "nodes-added": [
            {"name": "default/n", "primary-address": {"ipv4": {"ip": sys.argv[1]}}}]}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
socketserver.UnixStreamServer(path, H).serve_forever()
EOF
ok "selected role boots" boot_roles
ok "cilium-node-ip runs the real command" active cilium-node-ip.service
agent() { systemd-run --quiet --unit="$1" --slice=kubepods-burstable.slice /usr/local/bin/cilium-agent "$2"; }
cilium_poll_seconds=10  # c8s node-services cilium-node-ip
agent fake-cilium-current 192.0.2.10
/bin/sleep $((cilium_poll_seconds + 2))
ok "an agent announcing the current address keeps running" active fake-cilium-current.service
systemctl stop fake-cilium-current.service
agent fake-cilium-stale 192.0.2.99
for _ in $(seq 30); do active fake-cilium-stale.service || break; /bin/sleep 1; done
ok "the agent announcing a stale address was restarted" not_active fake-cilium-stale.service
ok "the restart is logged with both addresses" bash -c \
    "journalctl -b -u cilium-node-ip.service --no-pager | grep -F 'restarting cilium-agent' | grep 'announced=192.0.2.99' | grep -q 'published=192.0.2.10'"
ok "the watch keeps running" active cilium-node-ip.service
systemctl stop fake-cilium-stale.service >/dev/null 2>&1 || true
rm -f /usr/local/bin/cilium-agent /run/nri-image-policy/node-ip

scenario_reset
summarize "authenticated launch systemd dependencies"
