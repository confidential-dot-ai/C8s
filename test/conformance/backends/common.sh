# shellcheck shell=bash
# Shared by every backend in this directory. A backend sources this file (it
# loads the kind harness lib for CURL_IMAGE, WORKLOAD_IMAGE and
# CLUSTER_HARNESS_DIR, and derives C8S_ROOT), sets PLATFORM, overrides what
# differs, and ends with `dispatch "$@"`. README.md beside this file says who
# calls these functions and how.
#
# Interface: a backend exposes these functions, each exiting 0 with its answer
# on stdout, 77 when this environment cannot express the request (a named
# skip), anything else when the harness is broken.
#   subject                          the system under test, for the run summary
#   kubeconfig                       the file every kubectl call of a run uses
#   setup / teardown                 once per run, before and after the scenarios
#   node_name <logical>              the Kubernetes node behind a scenario's node
#   image_ref <logical>              a pullable reference for a scenario's image
#   image_digest <ref>               the digest the enforcer compares for ref
#   image_alias <ref> <name>         make the node resolve name to ref's bytes
#   served_allowlist                 the allowlist document CDS serves, as JSON
#   enforcer_ready <node>            the node's policy enforcer is enforcing
#   node_containers <node> <digest>  ids of the runtime's containers from digest
#   pod_manifest <name> <ns> <node> <image> <command...>
#                                    a pod manifest pinned to node
# node_name, image_ref, image_digest and served_allowlist answer the same for
# a whole run; callers may cache them.
set -o pipefail

C8S_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$C8S_ROOT/test/integration/cluster/lib.sh"

UNSUPPORTED=77

subject() { echo "c8s $(git -C "$C8S_ROOT" rev-parse --short HEAD) on $PLATFORM"; }

kubeconfig() { echo "$KUBECONFIG"; }

# "rogue" is the harness's curl image, deliberately off the install-time floor;
# "nginx" is its workload image, on the floor (kind) or put there by setup (metal).
image_ref() {
    case "$1" in
        rogue) echo "docker.io/$CURL_IMAGE" ;;
        nginx) echo "docker.io/$WORKLOAD_IMAGE" ;;
        *) return $UNSUPPORTED ;;
    esac
}

# The harness's Restricted-compatible pod, pinned to the node.
pod_manifest() {
    local name="$1" ns="$2" node="$3" image="$4"
    shift 4
    python3 "$CLUSTER_HARNESS_DIR/pod-fixture.py" client "$name" "$ns" "$image" \
        --node "$node" --pull-policy IfNotPresent -- "$@"
}

# dispatch <function> <args...>: an unknown name is a harness error, not a skip.
dispatch() {
    declare -F "$1" >/dev/null || { echo "backend: no function '$1'" >&2; return 2; }
    "$@"
}
