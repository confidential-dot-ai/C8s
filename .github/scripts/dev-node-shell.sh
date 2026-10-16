#!/usr/bin/env bash
# A metal lane's node shell on a C8S_DEV=1 SSH image: the guest's sshd
# authorizes root by the launch key (node-guest-image/c8s/mkosi.sync), so the
# key that signed the launch opens it. Waits for sshd, then fetches RKE2's
# admin kubeconfig, pointed at the guest's API server address. Writes
# C8S_NODE_SSH_CONFIG (an ssh config naming the node "node") and
# C8S_ADMIN_KUBECONFIG to $GITHUB_ENV.
#
# Usage: dev-node-shell.sh <guest-ip> <launch-private-key>
# The host key is fresh every boot and is taken on first use: this channel
# is a debug image's, not an attested one.
set -euo pipefail
ip="$1" key="$2"
dir="${RUNNER_TEMP:-/tmp}/node-ssh"
mkdir -p "$dir"
install -m 0600 "$key" "$dir/id"
cat > "$dir/config" <<EOF
Host node
  HostName $ip
  User root
  IdentityFile $dir/id
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  UserKnownHostsFile $dir/known_hosts
  ConnectTimeout 5
  ServerAliveInterval 15
EOF
command -v ssh >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y -qq --no-install-recommends openssh-client; }

for _ in $(seq 60); do
    ssh -F "$dir/config" node true 2>/dev/null && break
    sleep 5
done
ssh -F "$dir/config" node true || { echo "::error::no ssh to root@$ip with the launch key"; exit 1; }

admin="${RUNNER_TEMP:-/tmp}/guest-admin.kubeconfig"
ssh -F "$dir/config" node cat /etc/rancher/rke2/rke2.yaml > "$admin"
chmod 0600 "$admin"
# The API server's certificate names the node's own addresses, not the
# launcher's address for it; 127.0.0.1 is always among them.
KUBECONFIG="$admin" kubectl config set-cluster default --server "https://$ip:6443" --tls-server-name 127.0.0.1 >/dev/null
test "$(KUBECONFIG="$admin" kubectl auth can-i create pods/exec --all-namespaces)" = yes ||
    { echo "::error::the node's admin kubeconfig cannot exec"; exit 1; }
{
    echo "C8S_NODE_SSH_CONFIG=$dir/config"
    echo "C8S_ADMIN_KUBECONFIG=$admin"
} >> "$GITHUB_ENV"
echo "OK: node shell root@$ip, admin kubeconfig $admin"
