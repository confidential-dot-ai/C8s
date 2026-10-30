# Convenience for interactive shells: put rke2's bundled kubectl/ctr/crictl
# on PATH and point KUBECONFIG at the supervisor's generated kubeconfig.
# Sourced by /etc/profile for login shells.
if [ -d /var/lib/rancher/rke2/bin ]; then
    export PATH="/var/lib/rancher/rke2/bin:$PATH"
fi
if [ -f /etc/rancher/rke2/rke2.yaml ]; then
    export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
fi
