#!/usr/bin/env bash
# Install a dedicated host from a verified site archive.
set -euo pipefail
umask 077
media=/opt/c8s-offline
site=$media/site
state=/var/lib/c8s-offline
config=$site/target.json
kubeconfig=/etc/rancher/k3s/k3s.yaml
cli=$media/release/c8s-linux-amd64

fail() { echo "$*" >&2; exit 1; }
field() { jq -er --arg key "$1" '.[$key] | strings | select(length > 0)' "$config"; }
need() { for f in "$@"; do [ -s "$f" ] || fail "Missing local input: $f"; done; }

install_packages() {
    local tmp
    tmp=$(mktemp -d)
    chmod 0755 "$tmp"
    printf 'deb [trusted=yes arch=amd64] file:%s/apt ./\n' "$media" > "$tmp/site.list"
    chmod 0644 "$tmp/site.list"
    mapfile -t roots < "$site/packages.txt"
    [ "${#roots[@]}" -gt 0 ] || fail "No approved root packages"
    for pkg in "${roots[@]}"; do
        [[ $pkg =~ ^[a-z0-9][a-z0-9.+-]*=[a-zA-Z0-9.:+~_-]+$ ]] || fail "Invalid package pin: $pkg"
    done
    # Package maintainer scripts run before the registry and QGS are configured.
    # shellcheck disable=SC2016
    unshare --mount --net --propagation private /bin/bash -euc '
        mount -t tmpfs tmpfs /run
        export DEBIAN_FRONTEND=noninteractive SYSTEMD_OFFLINE=1
        tmp=$1; shift
        mkdir -p "$tmp/lists/partial" "$tmp/archives/partial"
        apt=(apt-get -o "Dir::Etc::sourcelist=$tmp/site.list" -o Dir::Etc::sourceparts=-
            -o "Dir::State::lists=$tmp/lists" -o "Dir::Cache::archives=$tmp/archives"
            -o Acquire::Languages=none -o Acquire::Retries=0)
        "${apt[@]}" update
        "${apt[@]}" --yes install "$@"
    ' _ "$tmp" "${roots[@]}"
    rm -rf -- "$tmp"
}

start_registry() {
    local registry pin ref dest
    registry=$(field registry)
    [[ $registry =~ ^[a-z0-9.-]+:[0-9]+$ ]] || fail "registry must be site hostname:port"
    need /etc/c8s-site/registry.crt /etc/c8s-site/registry.key "$site/registry-ca.pem"
    local dir=/etc/c8s-site/distribution
    install -d -m 0750 -g docker-registry "$dir"
    install -m 0640 -g docker-registry /etc/c8s-site/registry.key "$dir/tls.key"
    install -m 0644 /etc/c8s-site/registry.crt "$dir/tls.crt"
    install -m 0644 "$site/registry-ca.pem" /usr/local/share/ca-certificates/c8s-registry.crt
    update-ca-certificates
    cat > "$dir/config.yml" <<EOF
version: 0.1
storage:
  filesystem:
    rootdirectory: /var/lib/docker-registry
http:
  addr: :${registry##*:}
  tls:
    certificate: $dir/tls.crt
    key: $dir/tls.key
EOF
    chmod 0644 "$dir/config.yml"
    systemctl stop docker-registry.service
    install -d /etc/systemd/system/docker-registry.service.d
    cat > /etc/systemd/system/docker-registry.service.d/site.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/docker-registry serve $dir/config.yml
EOF
    systemctl daemon-reload
    systemctl enable --now docker-registry
    curl --noproxy '*' --retry 10 --retry-connrefused --retry-max-time 30 --max-time 5 -fsS "https://$registry/v2/"
    while IFS= read -r ref; do
        pin=${ref##*@sha256:}
        [[ $pin =~ ^[0-9a-f]{64}$ ]] || fail "Invalid registry pin: $ref"
        dest="${ref#*/}"
        dest="${dest%@*}"
        need "$media/oci/$pin/manifest.json"
        skopeo copy --all --preserve-digests "dir:$media/oci/$pin" "docker://$registry/$dest:sha256-$pin"
        skopeo inspect --raw "docker://$registry/$dest@sha256:$pin" | sha256sum |
            awk -v want="$pin" '$1 != want {exit 1}'
    done < "$media/oci/refs.txt"
}

start_qgs() {
    local cache
    cache=$(jq -er '.file | select(test("^[0-9A-Fa-f]+_[0-9A-Fa-f]+$"))' "$site/pck-cache.json")
    need "$site/pck/$cache"
    grep -q '"local_cache_only"' /etc/sgx_default_qcnl.conf ||
        fail "The installed Intel QCNL must support local_cache_only"
    printf '%s\n' '{"local_cache_only":true,"pccs_url":"https://127.0.0.1/sgx/certification/v4/"}' > /etc/c8s-site/qcnl.json
    chmod 0644 /etc/c8s-site/qcnl.json
    install -d -m 0755 /var/lib/c8s-qgs/.dcap-qcnl /etc/systemd/system/qgsd.service.d
    install -m 0644 "$site/pck/$cache" "/var/lib/c8s-qgs/.dcap-qcnl/$cache"
    cat > /etc/systemd/system/qgsd.service.d/offline.conf <<EOF
[Service]
Environment=AZDCAP_CACHE=/var/lib/c8s-qgs
Environment=QCNL_CONF_PATH=/etc/c8s-site/qcnl.json
RestrictAddressFamilies=AF_UNIX AF_VSOCK AF_NETLINK
EOF
    systemctl daemon-reload
    systemctl enable qgsd
    systemctl restart qgsd
    timeout 30 bash -c 'until test -S /run/tdx-qgs/qgs.socket; do sleep 1; done' ||
        fail "QGS did not create /run/tdx-qgs/qgs.socket; check platform cache and Unix transport"
}

unit() {
    local name=$1 action=$2 after="network-online.target qgsd.service docker-registry.service"
    if [ "$name" = worker ]; then after+=" c8s-offline-ta.service c8s-offline-control-plane.service"; fi
    cat > "/etc/systemd/system/c8s-offline-$name.service" <<EOF
[Unit]
Description=C8s disconnected $name
After=$after
[Service]
ExecStart=$site/install.sh $action
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "c8s-offline-$name"
}

start_vm() {
    local role=$1
    need "$site/qemu/$role.json" "$site/$role/disk.raw" "$site/firmware.fd" "$state/$role.iso"
    jq -e 'type == "array" and length > 0 and all(.[]; type == "string" and length > 0 and
        (test("[[:cntrl:]]") | not))' "$site/qemu/$role.json" >/dev/null
    mapfile -t topology < <(jq -r '.[]' "$site/qemu/$role.json")
    local disks=(-drive "if=none,id=root,file=$site/$role/disk.raw,format=raw,readonly=on"
        -device "virtio-blk-pci,drive=root,bootindex=1"
        -drive "if=none,id=launch,file=$state/$role.iso,format=raw,readonly=on" -device "virtio-blk-pci,drive=launch")
    if [ "$role" = worker ]; then
        check_devices
        disks+=(-drive "if=none,id=scratch,file=$state/scratch.raw,format=raw"
            -device "virtio-blk-pci,drive=scratch,serial=confai-scratch")
    fi
    exec qemu-system-x86_64 -accel kvm -cpu host -no-reboot -display none -serial stdio \
        -machine q35,kernel-irqchip=split,confidential-guest-support=tdx \
        -object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type":"unix","path":"/run/tdx-qgs/qgs.socket"}}' \
        -bios "$site/firmware.fd" "${disks[@]}" "${topology[@]}"
}

check_devices() {
    jq -e '.gpuPCI | type == "array" and length == 8 and (unique | length == 8) and
        all(.[]; type == "string" and test("^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}[.][0-7]$"))' "$config" >/dev/null ||
        fail "target.json must list eight distinct GPU PCI addresses"
    local bdf
    while IFS= read -r bdf; do
        [ "$(basename "$(readlink "/sys/bus/pci/devices/$bdf/driver")")" = vfio-pci ] ||
            fail "GPU $bdf must already be assigned to vfio-pci"
        jq -e --arg bdf "$bdf" 'any(.[]; startswith("vfio-pci,") and
            (split(",") | index("host=" + $bdf) != null))' "$site/qemu/worker.json" >/dev/null ||
            fail "approved QEMU launch lacks GPU $bdf"
    done < <(jq -r '.gpuPCI[]' "$config")
}

render_control_plane() {
    local dest=$state/rendered
    local chart=("$media"/charts/c8s-worker-*.tgz)
    if [ "${#chart[@]}" != 1 ] || [ ! -s "${chart[0]}" ]; then fail "expected one verified worker chart"; fi
    install -d "$state/charts"
    tar -xzf "${chart[0]}" -C "$state/charts"
    PATH="$site:$PATH" "$cli" worker control-plane render --hardware-platform tdx --document "$site/worker.yaml" \
        --webhook-host "$(field webhookHost)" --chart-dir "$state/charts/c8s-worker" \
        --kube-version "$(field kubeVersion)" --image-digest "$(field operatorImageDigest)" \
        --armtls-mesh-image-digest "$(field meshImageDigest)" --volumed-image-digest "$(field volumedImageDigest)" \
        --output-dir "$dest"
    "$site/k3s" kubectl --kubeconfig "$kubeconfig" apply -f "$dest/cluster.yaml"
    if ! [ -s "$state/credentials/c8s-operator.kubeconfig" ] ||
       ! [ -s "$state/credentials/c8s-cilium-operator.kubeconfig" ]; then
        "$cli" worker control-plane credentials --kubeconfig "$kubeconfig" --output-dir "$state/credentials"
    fi
}

host() {
    [ -c /dev/kvm ] || fail "host does not expose /dev/kvm"
    [ "$(uname -r)" = "$(field kernel)" ] || fail "host kernel differs from target.json"
    need "$site/qemu/ta.json" "$site/qemu/worker.json" "$site/pck-cache.json" "$site/registry-ca.pem" \
        "$site/k3s-config.yaml" "$site/ta.yaml" "$media/apt/Packages" "$media/oci/refs.txt" \
        /var/lib/rancher/k3s/server/tls/server-ca.crt /etc/c8s-site/registry.crt /etc/c8s-site/registry.key
    install_packages
    python3 - "$site/worker.yaml" /var/lib/rancher/k3s/server/tls/server-ca.crt <<'PYCA'
import pathlib, ssl, sys, yaml
pin = yaml.safe_load(pathlib.Path(sys.argv[1]).read_bytes())["kubernetes"]["caCertificate"]
chain = pathlib.Path(sys.argv[2]).read_text()
if ssl.PEM_cert_to_DER_cert(pin) not in [ssl.PEM_cert_to_DER_cert(c.lstrip() + "-----END CERTIFICATE-----")
        for c in chain.split("-----END CERTIFICATE-----") if c.strip()]:
    sys.exit("host control-plane CA does not match worker.yaml")
PYCA
    check_devices
    start_qgs
    start_registry
    unit control-plane run-control-plane
    # shellcheck disable=SC2016
    timeout 120 bash -c 'until "$1" kubectl --kubeconfig "$2" get --raw=/readyz >/dev/null 2>&1; do sleep 1; done' \
        _ "$site/k3s" "$kubeconfig" || fail "control plane did not become ready"
    render_control_plane
    unit operator run-operator
    unit cilium run-cilium
    genisoimage -quiet -R -V opkeydata -o "$state/ta.new.iso" -graft-points "pubkey=$site/ta.yaml"
    mv "$state/ta.new.iso" "$state/ta.iso"
    unit ta run-ta
    echo "Verify the TA and submit Genesis and workload grants on the trusted workstation; then run '$site/install.sh worker'."
}

worker() {
    systemctl is-active --quiet c8s-offline-ta || fail "start the TA before the worker"
    systemctl is-active --quiet c8s-offline-worker && fail "worker is already active"
    if [ ! -e "$state/scratch.raw" ]; then truncate -s 64G "$state/scratch.raw"; fi
    [ "$(stat -c %s "$state/scratch.raw")" -ge 68719476736 ] || fail "worker scratch disk is smaller than 64 GiB"
    unit worker run-worker
}

worker_launch_iso() (
    local token
    trap 'rm -f "$state/bootstrap-token" "$state/worker.new.iso"' EXIT
    token=$("$site/k3s" token create --ttl 24h)
    token=${token##*::}
    [[ $token =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || fail "k3s returned an invalid bootstrap token"
    printf '%s\n' "$token" > "$state/bootstrap-token"
    genisoimage -quiet -R -V opkeydata -o "$state/worker.new.iso" -graft-points \
        "pubkey=$site/worker.yaml" "bootstrap-token=$state/bootstrap-token"
    mv "$state/worker.new.iso" "$state/worker.iso"
)

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return; fi
[ "$EUID" = 0 ] || fail "run as root on the target host"
[ "$(realpath "$0")" = "$site/install.sh" ] || fail "extract verified media at $media"
install -d -m 0700 "$state"
case "${1:-}" in
host) host ;;
worker) worker ;;
run-ta) start_vm ta ;;
run-worker) worker_launch_iso; start_vm worker ;;
run-control-plane)
    exec "$site/k3s" server --config "$site/k3s-config.yaml" --disable-agent --egress-selector-mode disabled \
        --flannel-backend none --disable-kube-proxy --disable coredns,traefik,servicelb,local-storage,metrics-server ;;
run-operator)
    exec "$cli" operator --kubeconfig "$state/credentials/c8s-operator.kubeconfig" --webhook-host "$(field webhookHost)" \
        --get-cert-image "ghcr.io/confidential-dot-ai/c8s-operator@$(field operatorImageDigest)" \
        --mesh-image "ghcr.io/confidential-dot-ai/armtls-mesh@$(field meshImageDigest)" ;;
run-cilium)
    exec "$site/cilium-operator-generic" --k8s-kubeconfig-path "$state/credentials/c8s-cilium-operator.kubeconfig" \
        --k8s-namespace kube-system --ipam kubernetes --identity-allocation-mode crd --enable-l7-proxy=false ;;
*) fail "usage: $0 host | worker" ;;
esac
