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
#   mesh_restart                     restart every mesh proxy and wait until all are
#                                    ready, so each bootstraps from the CDS's mesh CA
#   cds_volatile                     yes/no: a CDS restart loses the allowlist and its version
#   served_version                   the version of the allowlist CDS serves now
#   applied_version                  the allowlist version the admission plugin
#                                    on the node decides with, from its health
#                                    endpoint, or 77 where the node cannot be
#                                    reached
#   node_containers <node> <digest>  ids of the runtime's containers from digest
#   pod_manifest [options] -- <name> <ns> <node> <image> <command...> [+ <image> <command...>]...
#                                    a pod manifest pinned to node, one
#                                    container per +-separated group; the
#                                    options, before the --, are
#                                    --host-network, --run-as-user <uid>,
#                                    --add-capability <cap>, --label <k=v>,
#                                    --annotation <k=v>, --env <NAME=VALUE>
#                                    (the first container's),
#                                    --disk-volume <path> (an emptyDir on the
#                                    node's disk in the last container),
#                                    --init-container '<image> <command...>'
#   scratch_encrypted                yes/no: the node's disk-backed emptyDirs
#                                    sit on encrypted scratch
#   image_entrypoint <ref>           the argv the image starts with when the pod
#                                    spec overrides nothing, one word per line
#   image_env <ref>                  the NAME=VALUE entries the image's
#                                    configuration sets, one per line
#   operator_keys                    yes/no: the CDS holds an operator key
#   seed_declares <digest>           yes/no: the seed of the CDS names digest
#   seed_add <name> <file>           add the entry in file to the seed the CDS
#                                    follows, under name; 77 where the seed is
#                                    not the cluster's to change
#   seed_restore                     put back the seed seed_add changed, if any
#   cds_instance                     the CDS pod's uid and restart count, one
#                                    line, so a later read tells a restart
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
#   pod_exec                         yes: steps may exec in a pod's containers
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
#   router_request <method> <path> [body-file] [authorization]
#                                    the same to the router's public address
#   router_headers <path>            GET path at the router; prints the status,
#                                    then the response headers, one per line
#   router_serving_cert              the leaf the router presents on its public
#                                    address, PEM
#   router_nginx_conf                the router's rendered nginx configuration;
#                                    77 where the node image holds it
#   router_tls_mode                  cds, webpki or acme: the public TLS
#                                    credential the router selects
#   cds_relay_block / cds_relay_unblock
#                                    leave the CDS Service with no endpoints, so
#                                    the router's allowlist relay cannot reach
#                                    the CDS, and undo it; each returns once
#                                    the Service's endpoints say so
# node_name, image_ref, image_digest, pull_interval, cds_pod_url, cert_paths,
# node_address, mesh_port, mesh_uids, mesh_platform, excluded_namespace,
# host_namespace_ns, attestation_endpoint and pod_exec answer the same for a
# whole run;
# callers may cache them. The allowlist is state: served_allowlist answers for
# the moment of the call.
#
# The implementations below that are the same everywhere need these from the
# backend, which the steps never call:
#   cds_url                          the base URL of the CDS, reachable from here
#   router_url                       the base URL of the router's public HTTPS
#                                    address, reachable from here
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
# "nginx" is NGINX_IMAGE when a backend sets one, else the harness's workload
# image, the router's nginx digest, which the install seed admits only under
# its entrypoint; setup admits it under any argv with an entry it writes. The
# rest are public images no
# served entry and no base allowlist names, for the scenarios that write their
# own entries; each has its own digest. "requester" is the curl image of the
# pod requester_manifest renders, distinct from "rogue" so that one stays
# undeclared while a scenario admits this one. "mesh-dialer" is the pod the
# "secret-client" is the image the webhook injects its helpers from, for a
# pod that runs a helper of its own; a backend whose node holds that image
# out of the harness's reach answers 77 from injected_image. The
# steps copy the mesh peer (tools/armtls-dial, dialer_bin) into: an image with
# tar for the copy, which no other logical image shares.
image_ref() {
    case "$1" in
        rogue) echo "docker.io/$CURL_IMAGE" ;;
        nginx) echo "docker.io/${NGINX_IMAGE:-$WORKLOAD_IMAGE}" ;;
        tenant-app) echo "docker.io/library/python:3.12-alpine" ;;
        job-runner) echo "docker.io/library/alpine:3.20" ;;
        model-server) echo "docker.io/library/debian:bookworm-slim" ;;
        model-loader) echo "docker.io/library/busybox:1.35.0" ;;
        requester) echo "docker.io/curlimages/curl:8.11.0" ;;
        mesh-dialer) echo "docker.io/library/busybox:1.36.1" ;;
        secret-client) injected_image ;;
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
# image-policy.yaml.in, allowlist.pull.interval). The steps poll
# applied_version for the served version, with a deadline in these; where the
# backend cannot reach the plugin they wait this out instead.
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
pod_exec() { echo yes; }
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

# The image the webhook injects get-cert and its siblings from.
injected_image() { operator_arg get-cert-image; }

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

# The status is the first line of the read. Taking it with head would close
# the pipe before cds_read has written the body, and that SIGPIPE is the
# function's status under pipefail.
operator_keys() {
    local answer code
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

# The seed is the ConfigMap the CDS Deployment mounts; a baked node holds it
# in the image instead, and renders no ConfigMap, so there it is not the
# cluster's to change. The first change keeps the original for seed_restore.
seed_configmap() {
    kubectl -n "$NS" get configmaps -o json |
        jq -r '.items[] | select(.metadata.name | endswith("-allowlist-seed")) | .metadata.name' | head -1
}

seed_add() {
    local cm original
    cm="$(seed_configmap)"
    [ -n "$cm" ] || return $UNSUPPORTED
    original="$(scratch)/seed-original.json"
    [ -s "$original" ] || kubectl -n "$NS" get configmap "$cm" -o json > "$original" || return
    kubectl -n "$NS" get configmap "$cm" -o json |
        jq --arg name "$1" --slurpfile entry "$2" \
            '.data["allowlist-seed.json"] |= (fromjson | .workloads[$name] = $entry[0] | tojson)' |
        kubectl replace -f - >/dev/null
}

# Only the data goes back: the ConfigMap's resourceVersion moved with the
# change, so a replace of the saved object conflicts.
seed_restore() {
    local original cm
    original="$(scratch)/seed-original.json"
    [ -s "$original" ] || return 0
    cm="$(jq -r .metadata.name "$original")"
    kubectl -n "$NS" patch configmap "$cm" --type merge -p "$(jq -c '{data: .data}' "$original")" >/dev/null && rm -f "$original"
}

cds_instance() {
    kubectl -n "$NS" get pods -l app.kubernetes.io/component=cds \
        -o jsonpath='{range .items[*]}{.metadata.uid} {.status.containerStatuses[0].restartCount}{"\n"}{end}' | head -1
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

# Raw reads, so the steps see the document the CDS serves, as served.
served_allowlist() { curl -sSfk "$(cds_url)/allowlist"; }
served_version() { allowlist_get "" | awk 'NR == 1 {print $2}'; }

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
    local url
    url="$(cds_url)" || return
    http_request "$url" "$@"
}

router_request() {
    local url
    url="$(router_url)" || return
    http_request "$url" "$@"
}

# http_request <base-url> <method> <route> [body-file] [authorization] [client-cert] [client-key]
http_request() {
    local url="$1" method="$2" route="$3" body="${4:-}" authorization="${5:-}" cert="${6:-}" key="${7:-}" answer
    local -a opts=(-sk --max-time 30 -X "$method" -w $'\n%{http_code}')
    [ -z "$body" ] || opts+=(-H 'Content-Type: application/json' --data-binary "@$body")
    [ -z "$authorization" ] || opts+=(-H "Authorization: $authorization")
    [ -z "$cert" ] || opts+=(--cert "$cert" --key "$key")
    answer="$(curl_paced "${opts[@]}" "$url$route")"
    echo "${answer##*$'\n'}"
    printf '%s' "${answer%$'\n'*}"
}

# The router admits one allowlist write a second per client (burst 5), and
# the harness is one client: a 429 is waited out, never an answer. No
# scenario observes rate limiting.
curl_paced() {
    local answer _
    for _ in $(seq 10); do
        answer="$(curl "$@" 2>/dev/null)" || answer=$'\n000'
        [ "${answer##*$'\n'}" = 429 ] || break
        sleep 1
    done
    printf '%s' "$answer"
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

cds_serving_cert() { local url; url="$(cds_url)" || return; serving_cert "$url"; }

serving_cert() {
    local host="${1#https://}"
    host="${host%%/*}"
    openssl s_client -connect "$host" </dev/null 2>/dev/null | openssl x509
}

# --- The router ---
# The chart's router Deployment and its nginx ConfigMap in $NS, whether the
# chart or a node image's launch configuration drives it.
ROUTER_DEPLOY=c8s-router
CDS_SELECTOR_ANNOTATION=c8s-conformance/selector

router_serving_cert() { local url; url="$(router_url)" || return; serving_cert "$url"; }

router_headers() {
    local url answer
    url="$(router_url)" || return
    answer="$(curl -sk --max-time 30 -o /dev/null -D - "$url$1" 2>/dev/null | tr -d '\r')" || answer=""
    if [ -z "$answer" ]; then
        echo 000
        return
    fi
    echo "${answer%%$'\n'*}" | awk '{print $2}'
    printf '%s\n' "${answer#*$'\n'}" | sed '/^$/d'
}

# Off a node image the configuration is a ConfigMap, mounted directly or
# through a projected volume; a baked node mounts it from the image
# (hostPath), which nothing here can read without a node shell.
router_nginx_conf() {
    local volumes cm
    volumes="$(kubectl -n "$NS" get deploy "$ROUTER_DEPLOY" -o json | jq -c '.spec.template.spec.volumes // []')" || return
    cm="$(jq -r '.[] | (.configMap.name // empty), (.projected.sources[]?.configMap.name // empty)' <<<"$volumes" |
        grep -- '-nginx$' | head -1)"
    if [ -z "$cm" ]; then
        if jq -e '.[] | select(.name == "nginx-config") | .hostPath' <<<"$volumes" >/dev/null; then
            return "$UNSUPPORTED"
        fi
        echo "backend: the router mounts no nginx ConfigMap" >&2
        return 1
    fi
    kubectl -n "$NS" get configmap "$cm" -o json | jq -r '.data | to_entries | map(select(.key | endswith(".conf"))) | .[].value'
}

# The attest container is started with --front-door-mode, or, where a launch
# configuration drives the router, with the file that holds it. get-cert, an
# init container, reads the same file into the discovery document it writes, so that mode is
# read from the document the router serves, which needs no exec.
router_tls_mode() {
    local args mode out path conf
    args="$(kubectl -n "$NS" get deploy "$ROUTER_DEPLOY" -o json |
        jq -r '.spec.template.spec | ((.initContainers // []) + .containers)[] | (.args // [])[]')" || return
    mode="$(sed -n 's/^--front-door-mode=//p' <<<"$args" | head -1)"
    if [ -z "$mode" ]; then
        grep -q '^--front-door-mode-file=' <<<"$args" || { echo "backend: the router names no front-door mode" >&2; return 1; }
        out="$(sed -n 's/^--discovery-out=//p' <<<"$args" | head -1)"
        [ -n "$out" ] || { echo "backend: the router publishes no discovery document" >&2; return 1; }
        conf="$(router_nginx_conf)" || return
        path="$(awk -v f="$out" '$1 == "location" {loc = $(NF - 1)} $1 == "alias" && $2 == f ";" {print loc; exit}' <<<"$conf")"
        [ -n "$path" ] || { echo "backend: no router location serves $out" >&2; return 1; }
        mode="$(curl -sk --max-time 30 "$(router_url)$path" | jq -r '.public_tls.mode // empty')" || return
    fi
    echo "$mode" | tr -d '[:space:]'
}

# The selector the Service had is kept in an annotation on it, so
# cds_relay_unblock restores it from any process. Established connections
# outlive the endpoints, so the block holds only once the relay's pooled ones
# have idled out (the armTLS client's IdleConnTimeout, 30s).
RELAY_IDLE_SECONDS=31
cds_relay_block() {
    local selector
    [ -z "$(kubectl -n "$NS" get svc c8s-cds -o jsonpath="{.metadata.annotations.$CDS_SELECTOR_ANNOTATION}")" ] || return 0
    selector="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath='{.spec.selector}')"
    [ -n "$selector" ] || { echo "backend: the CDS Service has no selector" >&2; return 1; }
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_SELECTOR_ANNOTATION=$selector" --overwrite >/dev/null || return
    kubectl -n "$NS" patch svc c8s-cds --type merge -p '{"spec":{"selector":{"c8s-conformance/none":"none"}}}' >/dev/null || return
    cds_endpoints_await empty || return
    sleep "$RELAY_IDLE_SECONDS"
}

cds_relay_unblock() {
    local selector
    selector="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath="{.metadata.annotations.$CDS_SELECTOR_ANNOTATION}")"
    [ -n "$selector" ] || return 0
    kubectl -n "$NS" patch svc c8s-cds --type json \
        -p "[{\"op\":\"replace\",\"path\":\"/spec/selector\",\"value\":$selector}]" >/dev/null || return
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_SELECTOR_ANNOTATION-" >/dev/null || return
    cds_endpoints_await present
}

# cds_endpoints_await <empty|present>
cds_endpoints_await() {
    local deadline=$(($(date +%s) + 60)) ips
    while :; do
        ips="$(kubectl -n "$NS" get endpoints c8s-cds -o jsonpath='{.subsets[*].addresses[*].ip}')"
        case "$1" in
            empty) [ -n "$ips" ] || return 0 ;;
            present) [ -z "$ips" ] || return 0 ;;
        esac
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the CDS Service's endpoints are not $1 after 60s" >&2; return 1; }
        sleep 1
    done
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
# not change during a run (the mesh DaemonSet's spec, the mesh pod on a node
# until mesh_restart, the node address the proxy is scraped at). An empty answer is not kept, nor
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

# A restarted CDS mints a new mesh CA, which a running proxy refuses as a
# CA bundle with no continuity; only a proxy started after it bootstraps
# from the new one. The mesh pods are new, so their cached names go.
mesh_restart() {
    kubectl -n "$NS" get ds "$MESH_DS" >/dev/null 2>&1 || return "$UNSUPPORTED"
    kubectl -n "$NS" rollout restart "ds/$MESH_DS" >/dev/null || return
    kubectl -n "$NS" rollout status "ds/$MESH_DS" --timeout=240s >/dev/null || return
    rm -f "$(scratch)"/cache-mesh-pod-*
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
    seed_restore || true
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
# its CDS leaf, and a failed refresh keeps the set it had. Success is logged
# at debug level only, so the observation is the latest refresh tick (one
# poll interval apart from "CA bundle refresh enabled") with no failure
# logged after it; when it failed, the next tick decides.
mesh_chain_ready() {
    local pod interval started verdict wait tries=0
    pod="$(mesh_pod_on "$1")"
    [ -n "$pod" ] || { echo "backend: no mesh pod on $1" >&2; return 1; }
    [ "$(mesh_cert_mode "$1")" = cds ] || { echo "backend: the mesh proxy on $1 presents no CDS leaf" >&2; return 1; }
    interval="$(mesh_arg ca-poll-interval)"
    started="$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="armtls-mesh")].state.running.startedAt}')"
    while :; do
        read -r verdict wait < <(kubectl -n "$NS" logs "$pod" -c armtls-mesh --timestamps 2>/dev/null |
            python3 -c "$MESH_REFRESH_PY" "${interval:-5m}" "$started")
        case "$verdict" in
            ok) return 0 ;;
            failed) [ "$tries" -lt 1 ] || { echo "backend: the mesh proxy on $1 failed its last CA refresh" >&2; return 1; } ;;
        esac
        tries=$((tries + 1))
        sleep "$wait"
    done
}

# stdin: the proxy's log with timestamps; argv: the poll interval and the
# container's start. Prints ok, failed or wait, then the seconds until the
# next tick has had time to be logged.
MESH_REFRESH_PY='
import datetime, re, sys
def ts(s):
    s = re.sub(r"\.\d+", "", s.rstrip("Z"))
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()
units = {"h": 3600, "m": 60, "s": 1}
interval = sum(int(n) * units[u] for n, u in re.findall(r"(\d+)([hms])", sys.argv[1]))
anchor, failures = ts(sys.argv[2]), []
for line in sys.stdin:
    stamp, _, msg = line.partition(" ")
    if "CA bundle refresh enabled" in msg:
        anchor, failures = ts(stamp), []
    elif "CA bundle refresh failed" in msg:
        failures.append(ts(stamp))
margin = 35  # a refresh is logged within --cds-op-timeout (30s) of its tick
now = datetime.datetime.now(datetime.timezone.utc).timestamp()
ticks = int((now - anchor - margin) // interval)
nxt = anchor + (ticks + 1) * interval + margin
if ticks < 1:
    print("wait", max(1, int(nxt - now)))
else:
    last = anchor + ticks * interval
    print("failed" if any(f >= last - 1 for f in failures) else "ok", max(1, int(nxt - now)))
'

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

# --- On the node, through the backend's node_exec ---
# For a backend with a shell on the node: node_exec runs a command there as
# root, with ctr and crictl on PATH and pointed at the node's containerd, and
# with curl and procps installed. A backend without one answers 77 instead.

store_digest() { store_digests | awk -F'\t' -v ref="$1" '$2 == ref {print $1; exit}'; }

# The digest the node's store holds for ref, pulling only when it has none.
image_digest() {
    local digest
    digest="$(store_digest "$1")"
    if [ -z "$digest" ]; then
        node_exec ctr -n k8s.io images pull "$1" >/dev/null
        digest="$(store_digest "$1")"
    fi
    echo "$digest"
}

image_alias() {
    node_exec ctr -n k8s.io images pull "$1" >/dev/null
    node_exec ctr -n k8s.io images tag --force "$1" "$2" >/dev/null
}

pod_uid() { kubectl -n "$1" get pod "$2" -o jsonpath='{.metadata.uid}'; }

# The pod's certificate volume is the memory-backed emptyDir the webhook
# adds, which the kubelet keeps under the pod's directory on the node; read
# there, so the first leaf is seen before any workload container runs.
pod_cert_file() {
    if [ -n "${4:-}" ]; then
        pod_cert_file_in "$1" "$2" "$4" "$3"
        return
    fi
    local uid
    uid="$(pod_uid "$1" "$2")" || return
    node_exec cat "/var/lib/kubelet/pods/$uid/volumes/kubernetes.io~empty-dir/c8s-certs/$3" 2>/dev/null || true
}

pod_sandbox_id() {
    local uid
    uid="$(pod_uid "$1" "$2")" || return
    node_exec crictl pods --label "io.kubernetes.pod.uid=$uid" -q | awk 'NR == 1'
}

# The installer (or a node image's boot staging) renders the base allowlist
# into the plugin's config directory on the node; a digest is a string that appears nowhere else in it.
base_declares() {
    if node_exec grep -rqF "$2" /etc/nri/conf.d; then echo yes; else echo no; fi
}

# The chart's nriImagePolicy.hostPaths.pluginDir/pluginFilename, which
# containerd launches at its own start (plugin_path), and its runtimeDir/
# healthSocketName, both on the node.
PLUGIN_BIN=/opt/nri/plugins/10-nri-image-policy
PLUGIN_HEALTH=/run/nri-image-policy/health.sock

# Refused is exit 7 from curl, as a TLS failure against the CDS is not.
node_refuses() {
    local rc=0
    node_exec curl -sk --max-time 2 -o /dev/null "https://127.0.0.1:$1/healthz" 2>/dev/null || rc=$?
    if [ "$rc" -eq 7 ]; then echo yes; else echo no; fi
}

# The pids running the plugin binary.
plugin_pids() { node_exec pgrep -f "^$PLUGIN_BIN" || true; }

# The plugin's own /healthz answers 200 once its first pull has settled.
plugin_healthy() {
    node_exec curl -sf --max-time 2 --unix-socket "$PLUGIN_HEALTH" http://localhost/healthz >/dev/null 2>&1
}

# The version in that answer, whatever its status: the one the plugin applied.
applied_version() {
    node_exec curl -s --max-time 2 --unix-socket "$PLUGIN_HEALTH" http://localhost/healthz | jq -r .allowlist_version
}

# Ready within the installer's budget: a containerd restart, then the first
# pull's bounded retries (2+4+8+16s between attempts) when the CDS is away.
plugin_ready() {
    local deadline=$(($(date +%s) + 300))
    until plugin_healthy; do
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the plugin on $1 is not ready after 300s" >&2; return 1; }
        sleep 2
    done
}

# containerd does not relaunch a plugin that exited, so a killed plugin stays
# down, and required_plugins makes every workload container create fail.
plugin_stop() {
    local pids
    for _ in $(seq 1 30); do
        pids="$(plugin_pids)"
        [ -n "$pids" ] || return 0
        # shellcheck disable=SC2086  # one argument per pid
        node_exec kill $pids 2>/dev/null || true
        sleep 1
    done
    echo "backend: the plugin on $1 is still running" >&2
    return 1
}

# The ids of the runtime's containers from the digest.
node_containers() { node_exec crictl ps -a -q --image "$2"; }

# dispatch <function> <args...>: an unknown name is a harness error, not a skip.
dispatch() {
    declare -F "$1" >/dev/null || { echo "backend: no function '$1'" >&2; return 2; }
    "$@"
}
