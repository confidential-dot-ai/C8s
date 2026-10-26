#!/bin/sh
# Publish the worker's node name for its kubelet. The name is derived from the
# node key (c8s node-credential makes the key on first use and keeps it), and
# CDS signs that same name into the join token, so the kubelet must register
# under it: the API server lets a node act only as the name in its token.
set -eu
name=$(/usr/local/bin/c8s node-credential --print-node-name)
case "$name" in
    n-[0-9a-f]*) ;;
    *) echo "worker-node-name: unexpected node name '$name'" >&2; exit 1 ;;
esac
printf 'KUBELET_HOSTNAME=%s\n' "$name" > /run/c8s-worker/node-name.env.tmp
mv /run/c8s-worker/node-name.env.tmp /run/c8s-worker/node-name.env
