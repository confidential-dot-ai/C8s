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
#   setup                            once per run, before the scenarios
#   teardown                         once per run, after them; shared: what
#                                    every backend kept, then teardown_backend
#   teardown_backend                 what this backend alone kept for the run
#   node_name <logical>              the Kubernetes node behind a scenario's node
#   image_ref <logical>              a pullable reference for a scenario's image
#   image_digest <ref>               the digest the plugin compares for ref
#   image_alias <ref> <name>         make the node resolve name to ref's bytes
#   served_allowlist                 the allowlist document CDS serves, as JSON
#   allowlist_put <name> <file>      write the entry in file under name, signed
#   allowlist_delete <name>          delete the entry; absent is not an error
#   base_declares <node> <digest>    yes/no: the node's base allowlist names digest
#   pull_interval                    how often the plugin pulls, as a Go duration
#   plugin_ready <node>              wait until the node's admission plugin is registered and ready
#   plugin_stop <node>               stop the plugin; the runtime creates no workload container
#                                    until plugin_start
#   plugin_start <node>              start the plugin again and wait until it is ready
#   cds_block / cds_unblock          make the CDS unreachable for every node's pull, and undo it;
#                                    cds_block returns once node_refuses says a pull is refused
#   node_refuses <port>              yes/no: a connection from the node to 127.0.0.1:<port>
#                                    is refused now; a backend without a node shell answers yes
#   cds_restart                      restart the CDS and wait until it serves again
#   cds_volatile                     yes/no: a CDS restart loses the allowlist and its version
#   served_version                   the version of the allowlist CDS serves now
#   node_containers <node> <digest>  ids of the runtime's containers from digest
#   pod_manifest [options] -- <name> <ns> <node> <image> <command...> [+ <image> <command...>]...
#                                    a pod manifest pinned to node, one
#                                    container per +-separated group; the
#                                    options, before the --, are
#                                    --host-network, --run-as-user <uid>,
#                                    --add-capability <cap>, --label <k=v>,
#                                    --annotation <k=v>,
#                                    --init-container '<image> <command...>'
#   image_entrypoint <ref>           the argv the image starts with when the pod
#                                    spec overrides nothing, one word per line
#   operator_keys                    yes/no: the CDS holds an operator key
#   seed_declares <digest>           yes/no: the seed of the CDS names digest
#   write_token <operator|foreign> <method> <path> <body-file> [validity]
#                                    the Authorization header of a write token,
#                                    signed with the operator's key or with one
#                                    that is not an operator key
#   allowlist_get [version]          read the allowlist, naming version in
#                                    If-None-Match when given; prints
#                                    "<status> <version>", then the body
#   cds_read <document> [plain]      read a document of the CDS with no client
#                                    certificate (mesh-ca, reference-values,
#                                    operator-key-set, allowlist, readiness),
#                                    over plain HTTP when asked; prints the
#                                    status (000 when nothing answered), then
#                                    the body
#   cds_serving_cert                 the certificate the CDS presents in the
#                                    TLS handshake, PEM
#   cds_pins                         the launch digests the CDS was started
#                                    with, one per line
#   operator_key_set                 the operator public keys the CDS loaded at
#                                    startup, PEM
#   cds_restart_with <parameter> <value>
#                                    restart the CDS with one parameter
#                                    changed: min-ca-validity <duration>,
#                                    pins <digest>|none, operator-keys none,
#                                    san-validation true|false, inventory-cidr
#                                    <cidr>; default restores the installed
#                                    configuration
#   attestation_service_stop / attestation_service_start
#                                    the local attestation service of the
#                                    CDS's node
#   private_keys <node>              every PEM private key held outside CDS
#                                    process memory: in Kubernetes objects and
#                                    in the files of the node
#   attest_direct                    one issuance against the CDS process from
#                                    an admitted TEE; prints the chain, PEM
#   requester_manifest <name> <ns> <node>
#                                    a pod on node that relays HTTP for the
#                                    steps and can reach the node's sandbox
#                                    inventory and its local attestation service
#   requester_request <ns> <pod> <method> <url> [body-file] [unix-socket]
#                                    send the request from inside the pod;
#                                    prints the status (000 when nothing
#                                    answered), then the body
#   cds_pod_url                      the CDS address a pod's requester dials
#   cds_arg <flag>                   the value of --<flag>= the CDS runs with,
#                                    empty when it is not set
#   evidence <ns> <pod> <report-data-hex> [launch-digest-hex]
#                                    evidence from the local attestation
#                                    service of the pod's node over the report
#                                    data, as the {platform, evidence} envelope
#                                    the CDS takes; with a launch digest,
#                                    evidence reporting that digest instead of
#                                    the node's
#   evidence_unsigned <ns> <pod> <report-data-hex>
#                                    evidence whose signature does not verify
#   pod_cert_file <ns> <pod> <file> [container]
#                                    tls.crt or tls.key from the pod's
#                                    certificate volume, through the named
#                                    container when given; nothing while absent
#   pod_sandbox_id <ns> <pod>        the runtime's sandbox ID of the pod
#   relying_party <leaf-file> <ca-file> [verify flags...]
#                                    the operator's verifier on a saved leaf;
#                                    prints accepts or rejects
#   mesh_ready <node>                wait until the node's mesh proxy runs; 77
#                                    where the mesh is not installed
#   mesh_member <node> <interception|guard> <ip>
#                                    yes/no: the address is in the node's
#                                    interception membership (a local
#                                    eligible pod) or its guard membership
#   mesh_counter <node> <inbound_connections|guard_drops>...
#                                    the node's count of connections its
#                                    inbound proxy accepted, or of packets its
#                                    inbound guard dropped, one per line from
#                                    one scrape
#   mesh_port <outbound|inbound>     the port of that mesh listener
#   mesh_uids                        the proxy UID, then the excluded UIDs,
#                                    one per line
#   mesh_cert_mode <node>            cds or self-signed: the certificate the
#                                    node's mesh proxy presents (both roles
#                                    switch together)
#   mesh_chain_ready <node>          wait until the mesh proxy's verify set
#                                    holds the mesh CA
#   mesh_pins_satisfied <node>       yes/no: the node's evidence satisfies
#                                    the pins its mesh proxy verifies with
#   mesh_platform                    the evidence family the mesh produces,
#                                    sev-snp or tdx
#   node_address <node> <ipv4|ipv6>  the node's address of that family; 77
#                                    when it has none
#   excluded_namespace               a namespace the mesh excludes
#   host_namespace_ns                a namespace admitting pods in the node's
#                                    network namespace and root pods
#   external_endpoint                <address>:<port> of a hello API outside
#                                    the cluster, or 77
#   attestation_endpoint             the URL a pod obtains evidence from, or 77
#   dialer_bin                       the armtls-dial binary for the node's
#                                    architecture, built once per run; 77
#                                    without a Go toolchain
#   cert_paths                       the certificate and key paths of a pod
#                                    carrying a workload ID, one per line
#   cds_request <method> <route> [body-file] [authorization] [client-cert] [client-key]
#                                    send the request to the CDS from here, as
#                                    given (empty arguments are omitted);
#                                    prints the status (000 when nothing
#                                    answered), then the body
# node_name, image_ref, image_digest, pull_interval, cds_pod_url, cert_paths,
# node_address, mesh_port, mesh_uids, mesh_platform, excluded_namespace,
# host_namespace_ns and attestation_endpoint answer the same for a whole run;
# callers may cache them. The allowlist is state: served_allowlist answers for
# the moment of the call.
#
# The implementations below that are the same everywhere need these from the
# backend, which the steps never call:
#   cds_url                          the base URL of the CDS, reachable from here
#   cds_plain_url                    the same listener over http://, or 77
#   operator_key                     the operator's private key, PEM
#   optoken_bin                      the token minter built from
#                                    test/integration/cluster/optoken
#   scratch                          a directory kept for the run
set -o pipefail

C8S_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$C8S_ROOT/test/integration/cluster/lib.sh"

UNSUPPORTED=77

subject() { echo "c8s $(git -C "$C8S_ROOT" rev-parse --short HEAD) on $PLATFORM"; }

kubeconfig() { echo "$KUBECONFIG"; }

# "rogue" is the harness's curl image, which no entry declares at install;
# "nginx" is its workload image, admitted under any argv by the install seed
# (kind) or by an entry setup writes (metal). The rest are public images no
# served entry and no base allowlist names, for the scenarios that write their
# own entries; each has its own digest. "requester" is the curl image of the
# pod requester_manifest renders, distinct from "rogue" so that one stays
# undeclared while a scenario admits this one. "mesh-dialer" is the pod the
# steps copy the mesh peer (tools/armtls-dial, dialer_bin) into: an image with
# tar for the copy, which no other logical image shares.
image_ref() {
    case "$1" in
        rogue) echo "docker.io/$CURL_IMAGE" ;;
        nginx) echo "docker.io/$WORKLOAD_IMAGE" ;;
        tenant-app) echo "docker.io/library/python:3.12-alpine" ;;
        job-runner) echo "docker.io/library/alpine:3.20" ;;
        model-server) echo "docker.io/library/debian:bookworm-slim" ;;
        model-loader) echo "docker.io/library/busybox:1.35.0" ;;
        requester) echo "docker.io/curlimages/curl:8.11.0" ;;
        mesh-dialer) echo "docker.io/library/busybox:1.36.1" ;;
        *) return $UNSUPPORTED ;;
    esac
}

# The mesh peer the steps drive, built from this checkout for the node's
# architecture (the steps call this once per run and copy the binary into the
# pod that dials), into a fresh directory: never an earlier run's binary, and
# never the results a metal lane uploads.
dialer_bin() {
    local bin arch
    command -v go >/dev/null || return "$UNSUPPORTED"
    bin="$(mktemp -d)/armtls-dial" || return
    arch="$(kubectl get node "$(node_name one)" -o jsonpath='{.status.nodeInfo.architecture}')" || return
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -C "$C8S_ROOT" -ldflags='-s -w' -o "$bin" ./test/conformance/tools/armtls-dial >&2 || return 1
    echo "$bin"
}

# The plugin's pull interval: the chart's nriImagePolicy.refresh.interval,
# which the node image bakes as the equal value (node-guest-image/c8s/
# image-policy.yaml.in, allowlist.pull.interval). The plugin exposes nothing
# about the version it holds, and containerd discards its log, so the steps
# wait this out rather than observe it.
pull_interval() { echo 5s; }

# The harness's Restricted-compatible pod, pinned to the node. Containers after
# the first are the fixture's --container groups, one shell-quoted string each.
# Options before -- are the fixture's own, named in the header; every pod may
# send an echo request over an ICMP datagram socket (a safe sysctl, which the
# chart's admission policy admits where NET_RAW is refused; the fixture leaves
# it out of a pod in the node's network namespace, where kubelet refuses every
# net.* sysctl). The tenant-app image is Alpine's python, whose ping uses that
# socket; the library busybox image's cannot.
PING_SYSCTL="net.ipv4.ping_group_range=0 2147483647"
pod_manifest() { render_pod --sysctl "$PING_SYSCTL" "$@"; }

# The node's admission plugin binds its socket directory into a container
# named as a sidecar an application may run itself (cds-attest) in a pod
# marked injected; the sockets are group-owned by 65532. Nothing else about
# the pod is c8s's, so the webhook leaves it alone.
REQUESTER_CONTAINER=cds-attest
requester_manifest() {
    local image
    image="$(image_ref requester)" || return
    render_pod --annotation confidential.ai/c8s-injected=true --container-name "$REQUESTER_CONTAINER" --supplemental-group 65532 \
        -- "$1" "$2" "$3" "$image" sleep 3600
}

# render_pod [fixture flags...] -- <name> <ns> <node> <image> <command...> [+ ...]
render_pod() {
    local -a flags=()
    while [ "$1" != -- ]; do
        [ $# -gt 1 ] || { echo "backend: render_pod: no -- before the pod" >&2; return 2; }
        flags+=("$1")
        shift
    done
    shift
    local name="$1" ns="$2" node="$3" image="$4"
    shift 4
    local -a first=() extras=() group=()
    local arg first_done=0
    for arg in "$@" +; do # the trailing + flushes the last group
        if [ "$arg" != + ]; then
            group+=("$arg")
        elif [ "$first_done" = 0 ]; then
            first=("${group[@]}") first_done=1 group=()
        else
            extras+=(--container "$(printf '%q ' "${group[@]}")") group=()
        fi
    done
    python3 "$CLUSTER_HARNESS_DIR/pod-fixture.py" client "$name" "$ns" "$image" \
        --node "$node" --pull-policy IfNotPresent ${flags[@]+"${flags[@]}"} "${extras[@]}" -- "${first[@]}"
}

# The webhook mounts the certificate volume here in every container of a pod
# carrying a workload ID; read through one of them, once it runs.
CERT_VOLUME_PATH=/etc/c8s/certs
pod_cert_file_in() { kubectl -n "$1" exec "$2" -c "$3" -- cat "$CERT_VOLUME_PATH/$4" 2>/dev/null || true; }

# Sent by curl inside the requester, so the source address the CDS sees is
# the pod's. Status 000 when nothing answered; empty when the pod cannot run
# curl at all.
requester_request() {
    local ns="$1" pod="$2" method="$3" url="$4" body="${5:-}" socket="${6:-}" resp
    local -a opts=(-sk --max-time 30 -X "$method" -w $'\n%{http_code}')
    [ -z "$socket" ] || opts+=(--unix-socket "$socket")
    if [ -n "$body" ]; then
        resp="$(kubectl -n "$ns" exec -i "$pod" -c "$REQUESTER_CONTAINER" -- \
            curl "${opts[@]}" -H 'Content-Type: application/json' --data-binary @- "$url" <"$body")" || true
    else
        resp="$(kubectl -n "$ns" exec "$pod" -c "$REQUESTER_CONTAINER" -- curl "${opts[@]}" "$url")" || true
    fi
    echo "${resp##*$'\n'}"
    printf '%s\n' "${resp%$'\n'*}"
}

# deploy_arg <flag> <jsonpath to the container args> <kubectl get deploy
# arguments...>: the value of --<flag>= in those args, empty when unset.
deploy_arg() {
    local flag="$1" path="$2"
    shift 2
    kubectl -n "$NS" get deploy "$@" -o jsonpath="$path" |
        jq -r --arg p "--$flag=" '.[] | select(startswith($p)) | ltrimstr($p)' | tail -1
}

operator_arg() {
    deploy_arg "$1" '{.items[0].spec.template.spec.containers[*].args}' \
        -l app.kubernetes.io/name=c8s-operator,app.kubernetes.io/component=operator
}

cds_arg() { deploy_arg "$1" '{.spec.template.spec.containers[?(@.name=="cds")].args}' c8s-cds; }

# What the webhook tells every requester it injects.
cds_pod_url() { operator_arg cds-url; }

# Every plugin pulls from https://127.0.0.1:<node port of the CDS Service>
# (the chart's nriImagePolicy.allowlist.pull.url default and the node image's
# image-policy.yaml.in). Moving the Service's node port leaves nothing
# listening on the port the plugin dials, so each pull is refused at once
# rather than after its timeout, while the Service stays reachable on its
# cluster IP for the operator's writes. The port it had is kept in an
# annotation on the Service, so cds_unblock restores it from any process.
CDS_PORT_ANNOTATION=c8s-conformance/node-port

cds_block() {
    local port candidate
    port="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath="{.metadata.annotations.$CDS_PORT_ANNOTATION}")"
    [ -z "$port" ] || return 0 # already blocked
    port="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath='{.spec.ports[0].nodePort}')"
    [ -n "$port" ] || { echo "backend: the CDS Service has no node port" >&2; return 1; }
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_PORT_ANNOTATION=$port" --overwrite >/dev/null
    for candidate in $(seq $((port + 1)) $((port + 5))); do
        kubectl -n "$NS" patch svc c8s-cds --type json \
            -p "[{\"op\":\"replace\",\"path\":\"/spec/ports/0/nodePort\",\"value\":$candidate}]" >/dev/null 2>&1 || continue
        # kube-proxy reprograms the node after the patch; until it has, a
        # pull still reaches the CDS.
        local deadline=$(($(date +%s) + 60))
        until [ "$(node_refuses "$port")" = yes ]; do
            [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the node still accepts pulls on $port after 60s" >&2; return 1; }
            sleep 1
        done
        return 0
    done
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_PORT_ANNOTATION-" >/dev/null
    echo "backend: no free node port near $port" >&2
    return 1
}

cds_unblock() {
    local port
    port="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath="{.metadata.annotations.$CDS_PORT_ANNOTATION}")"
    [ -n "$port" ] || return 0
    kubectl -n "$NS" patch svc c8s-cds --type json \
        -p "[{\"op\":\"replace\",\"path\":\"/spec/ports/0/nodePort\",\"value\":$port}]" >/dev/null
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_PORT_ANNOTATION-" >/dev/null
}

# The CDS keeps its allowlist and version counter in its data volume; a
# restart loses both when that volume is an emptyDir (the chart's
# cds.persistence.enabled=false), and the seed is applied again.
cds_volatile() {
    if [ -n "$(kubectl -n "$NS" get deploy c8s-cds -o jsonpath='{.spec.template.spec.volumes[?(@.name=="data")].emptyDir}')" ]; then
        echo yes
    else
        echo no
    fi
}

# --- The CDS API as a caller sees it ---
# The signed path (allowlist_put, allowlist_delete) is the harness's way of
# writing; these send what a scenario says, authorization included or not,
# with curl against the CDS. A backend provides what differs:
#   cds_url        the base URL of the CDS, reachable from here
#   operator_key   the operator's private key, PEM
#   optoken_bin    the token minter built from test/integration/cluster/optoken
#   scratch        a directory kept for the run

operator_keys() {
    local answer code
    # The whole answer, not its first line through head: cds_read writes the
    # body after the status, and a pipe head has left is a SIGPIPE (141).
    answer="$(cds_read operator-key-set)" || return
    code="${answer%%$'\n'*}"
    case "$code" in
        200) echo yes ;;
        404) echo no ;;
        *) echo "backend: GET /operator-keys: HTTP $code" >&2; return 1 ;;
    esac
}

operator_key_set() { openssl ec -in "$(operator_key)" -pubout 2>/dev/null; }

# The chart's seed ConfigMap, where the chart installed one.
seed_declares() {
    local seed
    seed="$(kubectl -n "$NS" get configmaps -o json |
        jq -r '.items[] | select(.metadata.name | endswith("-allowlist-seed")) | .data["allowlist-seed.json"] // empty')"
    [ -n "$seed" ] || return $UNSUPPORTED
    if printf '%s' "$seed" | grep -qF "$1"; then echo yes; else echo no; fi
}

# A key that is not an operator key, minted once per run.
foreign_key() {
    local key
    key="$(scratch)/foreign.key"
    [ -s "$key" ] || openssl ecparam -genkey -name prime256v1 -noout -out "$key" 2>/dev/null
    echo "$key"
}

write_token() {
    local key bin
    case "$1" in
        operator) key="$(operator_key)" || return ;;
        foreign) key="$(foreign_key)" || return ;;
        *) echo "backend: write_token: no signer '$1'" >&2; return 2 ;;
    esac
    shift
    bin="$(optoken_bin)" || return
    "$bin" "$key" "$@"
}

allowlist_get() {
    local url headers body status
    url="$(cds_url)" || return
    headers="$(mktemp)"
    body="$(mktemp)"
    local -a match=()
    [ -z "${1:-}" ] || match=(-H "If-None-Match: W/\"$1\"")
    status="$(curl -sSk -o "$body" -D "$headers" -w '%{http_code}' ${match[@]+"${match[@]}"} "$url/allowlist")" || status=000
    echo "$status $(awk 'tolower($1) == "etag:" {gsub(/[^0-9]/, "", $2); print $2}' "$headers")"
    cat "$body"
    rm -f "$headers" "$body"
}

# --- The CDS's own documents and state ---
# A backend provides cds_plain_url, the same listener over http://, or 77.

cds_document_path() {
    case "$1" in
        mesh-ca) echo /ca ;;
        reference-values) echo /measurements ;;
        operator-key-set) echo /operator-keys ;;
        allowlist) echo /allowlist ;;
        readiness) echo /readyz ;;
        *) echo "backend: no CDS document '$1'" >&2; return 2 ;;
    esac
}

# The request as the scenario shaped it: a body, an Authorization and a
# client certificate only when given. curl appends the status to the body; it
# moves to the first line here, as in cds_read.
cds_request() {
    local method="$1" route="$2" body="${3:-}" authorization="${4:-}" cert="${5:-}" key="${6:-}" url answer
    url="$(cds_url)" || return
    local -a opts=(-sk --max-time 30 -X "$method" -w $'\n%{http_code}')
    [ -z "$body" ] || opts+=(-H 'Content-Type: application/json' --data-binary "@$body")
    [ -z "$authorization" ] || opts+=(-H "Authorization: $authorization")
    [ -z "$cert" ] || opts+=(--cert "$cert" --key "$key")
    answer="$(curl "${opts[@]}" "$url$route" 2>/dev/null)" || answer=$'\n000'
    echo "${answer##*$'\n'}"
    printf '%s' "${answer%$'\n'*}"
}

cds_read() {
    local url path answer
    path="$(cds_document_path "$1")" || return
    if [ "${2:-}" = plain ]; then
        url="$(cds_plain_url)" || return
    else
        url="$(cds_url)" || return
    fi
    answer="$(curl -sk -w $'\n%{http_code}' --max-time 20 "$url$path" 2>/dev/null)" || answer=$'\n000'
    echo "${answer##*$'\n'}"
    printf '%s' "${answer%$'\n'*}"
}

cds_serving_cert() {
    local url host
    url="$(cds_url)" || return
    host="${url#https://}"
    host="${host%%/*}"
    openssl s_client -connect "$host" </dev/null 2>/dev/null | openssl x509
}

# --- The armTLS mesh ---
# Everything here goes through kubectl: the mesh DaemonSet in $NS, its pod on
# the node, and its health port on the node address, scraped from a pod the
# backend keeps for the run (mesh_scraper). The mesh is configured by the
# DaemonSet's args.
MESH_DS=c8s-armtls-mesh
MESH_SELECTOR=app=c8s-armtls-mesh
MESH_SYNC_CONTAINER=iptables-sync
# The ipsets the mesh keeps (internal/cmds/armtlsmesh/pod_ipsets_linux.go):
# local eligible pods, whose traffic is redirected, and guarded pods.
MESH_SET_LOCAL=ARMTLS-MESH-LOCAL-PODS
MESH_SET_GUARDED=ARMTLS-MESH-CW-PODS

# cached <key> <command...>: the command's output, kept in the run's scratch
# directory after the first call and dropped by teardown; for what does
# not change during a run (the mesh DaemonSet's spec, the mesh pod on a node,
# the node address the proxy is scraped at). An empty answer is not kept, nor
# a failure, whose status (77 included) is passed on.
cached() {
    local file rc
    file="$(scratch)/cache-$1"
    shift
    if [ ! -s "$file" ]; then
        "$@" > "$file"
        rc=$?
        [ "$rc" -eq 0 ] || { rm -f "$file"; return "$rc"; }
        [ -s "$file" ] || { rm -f "$file"; return 0; }
    fi
    cat "$file"
}

mesh_pod_on() { cached "mesh-pod-$1" kubectl -n "$NS" get pods -l "$MESH_SELECTOR" --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].metadata.name}'; }

mesh_spec() { cached mesh-ds kubectl -n "$NS" get ds "$MESH_DS" -o json; }

mesh_arg() {
    mesh_spec 2>/dev/null |
        jq -r --arg f "--$1" '[.spec.template.spec.containers[] | .args // [] | . as $a | range(length) | select($a[.] == $f) | $a[. + 1]] | first // empty'
}

mesh_ready() {
    kubectl -n "$NS" get ds "$MESH_DS" >/dev/null 2>&1 || return "$UNSUPPORTED"
    kubectl -n "$NS" rollout status "ds/$MESH_DS" --timeout=240s >/dev/null
}

mesh_member() {
    local pod set
    pod="$(mesh_pod_on "$1")"
    [ -n "$pod" ] || { echo "backend: no mesh pod on $1" >&2; return 1; }
    case "$2" in
        interception) set="$MESH_SET_LOCAL" ;;
        guard) set="$MESH_SET_GUARDED" ;;
        *) echo "backend: mesh_member: no membership '$2'" >&2; return 2 ;;
    esac
    if kubectl -n "$NS" exec "$pod" -c "$MESH_SYNC_CONTAINER" -- ipset test "$set" "$3" >/dev/null 2>&1; then echo yes; else echo no; fi
}

# A pod kept for the run that scrapes the mesh's health port on the node
# address, which no pod-IP rule intercepts; one exec per scrape instead of a
# pod per scrape. Its image is admitted by an entry of its own, since the
# plugin denies what no served entry declares; the entry goes with the pod.
MESH_SCRAPER_NS=c8s-conformance-tools
MESH_SCRAPER=mesh-scraper
mesh_scraper() {
    local ready
    ready="$(scratch)/mesh-scraper.ready"
    [ ! -e "$ready" ] || return 0
    if ! kubectl -n "$MESH_SCRAPER_NS" get pod "$MESH_SCRAPER" >/dev/null 2>&1; then
        kubectl create namespace "$MESH_SCRAPER_NS" >/dev/null 2>&1 || true
        local node image digest entry
        node="$(node_name one)" || return
        image="$(image_ref requester)" || return
        digest="$(image_digest "$image")" || return
        entry="$(scratch)/mesh-scraper.json"
        any_workload "$digest" "$image" > "$entry"
        allowlist_put "$MESH_SCRAPER" "$entry" || return
        render_pod -- "$MESH_SCRAPER" "$MESH_SCRAPER_NS" "$node" "$image" sleep 86400 | kubectl apply -f - >/dev/null
    fi
    kubectl -n "$MESH_SCRAPER_NS" wait --for=condition=Ready "pod/$MESH_SCRAPER" --timeout=180s >/dev/null || return
    touch "$ready"
}

# Once per run, after the scenarios: what every backend kept for the run (the
# scraper and its entry, the memoised answers), then what this one did.
teardown() {
    kubectl delete namespace "$MESH_SCRAPER_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    allowlist_delete "$MESH_SCRAPER" || true
    rm -f "$(scratch)/mesh-scraper.ready" "$(scratch)"/cache-*
    teardown_backend
}

# The node's /metrics, scraped once; a failed scrape is an error, never
# empty. A scraper found gone is made again, once.
mesh_metrics() {
    local addr port body _
    addr="$(cached "node-ipv4-$1" node_address "$1" ipv4)" || return
    port="$(cached mesh-health-port mesh_arg health-port)"
    port="${port:-15021}"
    for _ in 1 2; do
        mesh_scraper || return
        if body="$(kubectl -n "$MESH_SCRAPER_NS" exec "$MESH_SCRAPER" -- curl -sf --max-time 10 "http://$addr:$port/metrics")"; then
            printf '%s\n' "$body"
            return 0
        fi
        rm -f "$(scratch)/mesh-scraper.ready"
    done
    echo "backend: no scrape of $addr:$port" >&2
    return 1
}

# The sum of the series matching the pattern in a scrape on stdin.
metric_sum() { awk -v pat="$1" '$0 ~ pat {sum += $NF} END {printf "%d\n", sum + 0}'; }

mesh_metric_on() {
    local body
    body="$(mesh_metrics "$1")" || return
    metric_sum "$2" <<<"$body"
}

mesh_counter() {
    local node="$1" body name pat
    shift
    body="$(mesh_metrics "$node")" || return
    for name in "$@"; do
        case "$name" in
            inbound_connections) pat='^armtls_mesh_connections_total\{.*direction="inbound"' ;;
            guard_drops) pat='^armtls_mesh_iptables_cw_inbound_drops_total' ;;
            *) echo "backend: mesh_counter: no counter '$name'" >&2; return 2 ;;
        esac
        metric_sum "$pat" <<<"$body"
    done
}

mesh_port() {
    local port
    case "$1" in
        outbound) port="$(mesh_arg outbound-port)"; echo "${port:-15001}" ;;
        inbound) port="$(mesh_arg inbound-port)"; echo "${port:-15006}" ;;
        *) echo "backend: mesh_port: no listener '$1'" >&2; return 2 ;;
    esac
}

mesh_uids() {
    local uid excluded
    uid="$(mesh_arg uid)"
    excluded="$(mesh_arg exclude-uids)"
    echo "${uid:-1337}"
    tr ',' '\n' <<<"${excluded:-0}"
}

# Both roles switch to the CDS leaf together as far as the proxy reports
# (one cert_mode gauge); the configured mode decides whether they try.
mesh_cert_mode() {
    local v
    v="$(mesh_metric_on "$1" '^armtls_mesh_cert_mode\{mode="cds"\}')" || return
    if [ "$v" -ge 1 ]; then echo cds; else echo self-signed; fi
}

# The verify set fills on the first CA refresh after the proxy switched to
# its CDS leaf, which it does at start; the refresh is logged at debug level
# only, so the observation is the proxy in cds mode for longer than one poll
# interval with no refresh failure in its log.
mesh_chain_ready() {
    local pod interval started wait
    pod="$(mesh_pod_on "$1")"
    [ -n "$pod" ] || { echo "backend: no mesh pod on $1" >&2; return 1; }
    [ "$(mesh_cert_mode "$1")" = cds ] || { echo "backend: the mesh proxy on $1 presents no CDS leaf" >&2; return 1; }
    interval="$(mesh_arg ca-poll-interval)"
    started="$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.status.startTime}')"
    # Seconds still to wait until one poll interval and a margin have passed
    # since the pod started, and the interval in seconds.
    read -r wait interval < <(python3 - "${interval:-5m}" "$started" <<'PYEOF'
import datetime, re, sys
units = {"h": 3600, "m": 60, "s": 1}
interval = sum(int(n) * units[u] for n, u in re.findall(r"(\d+)([hms])", sys.argv[1]))
started = datetime.datetime.strptime(sys.argv[2], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
elapsed = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
print(max(0, int(interval + 30 - elapsed)), interval)
PYEOF
)
    sleep "$wait"
    local logs
    logs="$(kubectl -n "$NS" logs "$pod" -c armtls-mesh --since="${interval}s" 2>/dev/null)" || true
    if grep -q "CA bundle refresh failed" <<<"$logs"; then
        echo "backend: the mesh proxy on $1 failed a CA refresh in the last ${interval}s" >&2
        return 1
    fi
}

mesh_platform() {
    local p
    p="$(mesh_arg platform)"
    echo "${p:-sev-snp}"
}

node_address() {
    local pattern addr
    case "$2" in
        ipv4) pattern='^[^:]*$' ;;
        ipv6) pattern=':' ;;
        *) echo "backend: node_address: no family '$2'" >&2; return 2 ;;
    esac
    addr="$(kubectl get node "$1" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -m1 "$pattern")" || true
    [ -n "$addr" ] || return "$UNSUPPORTED"
    echo "$addr"
}

# The first namespace the mesh's rules exclude, which the chart sets to
# kube-system; the same namespace admits pods in the node's network
# namespace and root pods (the chart's host-namespace and UID policies leave
# it out).
excluded_namespace() {
    local ns
    ns="$(mesh_arg exclude-source-namespaces)"
    echo "${ns:-kube-system}" | cut -d, -f1
}
host_namespace_ns() { echo kube-system; }

cert_paths() { printf '%s/tls.crt\n%s/tls.key\n' "$CERT_VOLUME_PATH" "$CERT_VOLUME_PATH"; }

# dispatch <function> <args...>: an unknown name is a harness error, not a skip.
dispatch() {
    declare -F "$1" >/dev/null || { echo "backend: no function '$1'" >&2; return 2; }
    "$@"
}
