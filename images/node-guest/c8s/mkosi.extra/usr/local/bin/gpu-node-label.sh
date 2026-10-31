#!/bin/sh
# Label this node when an NVIDIA GPU is attached, so the baked
# nvidia-device-plugin DaemonSet (which selects on the label) schedules only
# where a GPU exists. On a GPU-less node the plugin's cdi-annotations strategy
# hard-fails generating a CDI spec with no driver and crashloops forever.
#
# The label goes on kubelet's --node-labels (via kubelet-arg), NOT rke2's
# node-label: rke2 node-label is applied only at first node registration, so a
# re-join under an existing node name (any agent relaunch) would silently drop
# it. kubelet re-asserts --node-labels on every start, so the label survives.
# confidential.ai/ is a non-reserved prefix, so NodeRestriction lets the
# kubelet self-set it.
#
# Detection is PCI presence, not /dev/nvidia*: the device nodes only exist once
# the driver has loaded, and this runs before rke2 starts.
set -eu

FRAGMENT=/etc/rancher/rke2/config.yaml.d/20-gpu-node-label.yaml

# Clean slate: a relaunch without the GPU must not inherit the label.
rm -f "$FRAGMENT"

for vendor in /sys/bus/pci/devices/*/vendor; do
    [ -e "$vendor" ] || continue
    if [ "$(cat "$vendor")" = "0x10de" ]; then
        mkdir -p /etc/rancher/rke2/config.yaml.d
        # kubelet-arg+ appends to the base config's kubelet-arg list rather
        # than replacing it.
        printf 'kubelet-arg+:\n  - "node-labels=confidential.ai/gpu=true"\n' > "$FRAGMENT"
        exit 0
    fi
done
exit 0
