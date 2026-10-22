# shellcheck shell=bash
# Shared by every backend in this directory. A backend sources this file (it
# loads the kind harness lib for CURL_IMAGE, WORKLOAD_IMAGE and
# CLUSTER_HARNESS_DIR, and derives C8S_ROOT), sets PLATFORM, overrides what
# differs, and ends with `dispatch "$@"`. README.md beside this file says who
# calls these functions and how.
#
# Interface: a backend exposes these functions, each exiting 0 with its answer
# on stdout, UNSUPPORTED (77; "unsupported" below) when this environment
# cannot express the request (a named skip), anything else when the harness
# is broken.
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
#   cds_block / cds_unblock          make the CDS unreachable for every node's pull, leaving
#                                    the pods' issuance alone, and undo it; cds_block returns
#                                    once node_refuses says a pull is refused
#   node_refuses <port>              yes/no: a connect from the node to 127.0.0.1:<port>
#                                    fails or hangs now; a backend without a node shell answers yes
#   cds_restart                      restart the CDS and wait until it serves again
#   api_service_name                 the fully qualified DNS name of the cluster's
#                                    API Service
#   mesh_restart                     recreate every controller-owned mesh member and wait
#                                    until all are ready, so each holds a leaf under the
#                                    CDS's mesh CA
#   cds_volatile                     yes/no: a CDS restart loses the allowlist and its version
#   served_version                   the version of the allowlist CDS serves now
#   applied_version                  the allowlist version the admission plugin
#                                    on the node decides with, from its health
#                                    endpoint, or unsupported where the node cannot be
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
#                                    changed: pins <digest>|none,
#                                    operator-keys none,
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
#   evidence <ns> <pod> <report-data-base64>
#                                    evidence from the local attestation
#                                    service of the pod's node over the report
#                                    data, as the {platform, evidence} envelope
#                                    the CDS takes
#   evidence_signed                  yes/no: the CDS checks the evidence's
#                                    signature, so editing it breaks the
#                                    evidence (yes) or makes evidence for
#                                    another launch digest (no)
#   pod_exec                         how steps run a command in a pod: kubectl
#                                    (exec), or agent (agent_run)
#   agent_run <ns> <pod> <container> <script>
#                                    where pod_exec is agent: the sh script's
#                                    combined output, its status as the
#                                    function's
#   agent_exec <ns> <pod> <container> <argv...>
#                                    agent_run of the argv
#   pod_cert_file <ns> <pod> <file> [container]
#                                    tls.crt or tls.key from the pod's
#                                    certificate volume, through the named
#                                    container when given; nothing while absent
#   pod_file <ns> <pod> <container> <path>
#                                    the file in the container, base64;
#                                    fails while it is absent
#   pod_fstype <ns> <pod> <container> <dir>
#                                    the filesystem type of the directory, as
#                                    stat -f names it; fails while it is absent
#   pod_sandbox_id <ns> <pod>        the runtime's sandbox ID of the pod
#   relying_party <leaf-file> <ca-file> [verify flags...]
#                                    the operator's verifier on a saved leaf;
#                                    prints accepts or rejects, then on a
#                                    rejection the verifier's reason
#   exempt_namespace                 a namespace the webhook exempts from the mesh, which
#                                    the harness may deploy into, or unsupported
#   cert_paths                       the certificate and key paths of a pod
#                                    carrying a workload ID, one per line
#   cds_request <method> <route> [body-file] [authorization] [client-cert] [client-key] [header...]
#                                    send the request to the CDS from here, as
#                                    given (empty arguments are omitted; each
#                                    header is "Name: value"); prints the
#                                    status, then the body (000 and curl's
#                                    exit code when nothing answered)
#   router_request <method> <path> [body-file] [authorization] [client-cert] [client-key] [header...]
#                                    the same to the router's public address
#   router_headers <path>            GET path at the router; prints the status,
#                                    then the response headers, one per line
#   router_serving_cert              the leaf the router presents on its public
#                                    address, PEM
#   router_nginx_conf                the router's rendered nginx configuration;
#                                    unsupported where the node image holds it
#   router_tls_mode                  cds, webpki or acme: the public TLS
#                                    credential the router selects
#   cds_relay_block / cds_relay_unblock
#                                    leave the CDS Service with no endpoints, so
#                                    the router's allowlist relay cannot reach
#                                    the CDS, and undo it; each returns once
#                                    the Service's endpoints say so
# node_name, image_ref, image_digest, pull_interval, cds_pod_url, cert_paths,
# pod_exec, exempt_namespace and api_service_name answer the same for a whole
# run; callers may cache them. The
# allowlist is state: served_allowlist answers for the moment of the call.
#
# The implementations below that are the same everywhere need these from the
# backend, which the steps never call:
#   cds_url                          the base URL of the CDS, reachable from here
#   router_url                       the base URL of the router's public HTTPS
#                                    address, reachable from here
#   cds_plain_url                    the same listener over http://, or unsupported
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
# undeclared while a scenario admits this one.
# "secret-client" is the image the webhook injects its helpers from, for a
# pod that runs a helper of its own; a backend whose node holds that image
# out of the harness's reach answers unsupported from injected_image. The
# suite's own images (images/, built by conformance-images.yml) stand in for
# the logical images CONFORMANCE_IMAGES names, for every backend: tenant-app,
# Alpine's python with the programs the steps run in it; a backend adds its own.
CONFORMANCE_REPO=ghcr.io/confidential-dot-ai/c8s-conformance-
declare -A CONFORMANCE_IMAGES=(
    [tenant-app]=sha256:e1c7fc0eef8212a8a5beaf993ed804e518f80cce32d858c3c7e9c1339bdb3938
)
image_ref() {
    [ -z "${CONFORMANCE_IMAGES[$1]:-}" ] || { echo "$CONFORMANCE_REPO$1@${CONFORMANCE_IMAGES[$1]}"; return; }
    case "$1" in
        rogue) echo "docker.io/$CURL_IMAGE" ;;
        nginx) echo "docker.io/${NGINX_IMAGE:-$WORKLOAD_IMAGE}" ;;
        job-runner) echo "docker.io/library/alpine:3.20" ;;
        model-server) echo "docker.io/library/debian:bookworm-slim" ;;
        model-loader) echo "docker.io/library/busybox:1.35.0" ;;
        requester) echo "docker.io/curlimages/curl:8.11.0" ;;
        secret-client) injected_image ;;
        *) return $UNSUPPORTED ;;
    esac
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
pod_manifest() { render_pod --sysctl "$PING_SYSCTL" "$@" | manifest_filter; }
# A backend's last word on every pod the harness renders for its own argv.
manifest_filter() { cat; }

# The node's admission plugin binds its socket directory into a container
# named as a sidecar an application may run itself (cds-attest) in a pod
# marked injected; the sockets are group-owned by 65532
# (workloadclaims.AttestContainerName and InventorySocketGID). Nothing else
# about the pod is c8s's, so the webhook leaves it alone.
REQUESTER_CONTAINER=cds-attest
requester_manifest() {
    local image
    image="$(image_ref requester)" || return
    render_pod --annotation confidential.ai/c8s-injected=true --annotation c8s-conformance/harness-argv=yes \
        --container-name "$REQUESTER_CONTAINER" --supplemental-group 65532 \
        -- "$1" "$2" "$3" "$image" sleep 3600 | manifest_filter
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
pod_exec() { echo kubectl; }
pod_file() { local out; out="$(kubectl -n "$1" exec "$2" -c "$3" -- cat "$4" | base64)" && tr -d '\n' <<<"$out"; }
pod_fstype() { kubectl -n "$1" exec "$2" -c "$3" -- stat -f -c %T "$4"; }
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

# Where an injected credential client dials CDS on an install: node "one"'s
# own address and the CDS Service's node port.
cds_pod_url() {
    local node host port
    node="$(node_name one)" || return
    host="$(kubectl get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')" || return
    port="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath='{.spec.ports[0].nodePort}')" || return
    if [ -z "$host" ] || [ -z "$port" ]; then
        echo "backend: no address or CDS node port for node $node" >&2
        return 1
    fi
    echo "https://${host%% *}:$port"
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
# A backend provides cds_plain_url, the same listener over http://, or unsupported.

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

# http_request <base-url> <method> <route> [body-file] [authorization] [client-cert] [client-key] [header...]
http_request() {
    local url="$1" method="$2" route="$3" body="${4:-}" authorization="${5:-}" cert="${6:-}" key="${7:-}" answer h
    local -a opts=(-sk --max-time 30 -X "$method" -w $'\n%{http_code}')
    [ -z "$body" ] || opts+=(-H 'Content-Type: application/json' --data-binary "@$body")
    [ -z "$authorization" ] || opts+=(-H "Authorization: $authorization")
    [ -z "$cert" ] || opts+=(--cert "$cert" --key "$key")
    shift "$(($# < 7 ? $# : 7))"
    for h; do opts+=(-H "$h"); done
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
        # No answer is status 000, with curl's exit code as the body.
        answer="$(curl "$@" 2>/dev/null)" || answer="curl exited $?"$'\n000'
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
# The chart's router Deployment and its nginx ConfigMap in $ROUTER_NS, whether the
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
    volumes="$(kubectl -n "$ROUTER_NS" get deploy "$ROUTER_DEPLOY" -o json | jq -c '.spec.template.spec.volumes // []')" || return
    cm="$(jq -r '.[] | (.configMap.name // empty), (.projected.sources[]?.configMap.name // empty)' <<<"$volumes" |
        grep -- '-nginx$' | head -1)"
    if [ -z "$cm" ]; then
        if jq -e '.[] | select(.name == "nginx-config") | .hostPath' <<<"$volumes" >/dev/null; then
            return "$UNSUPPORTED"
        fi
        echo "backend: the router mounts no nginx ConfigMap" >&2
        return 1
    fi
    kubectl -n "$ROUTER_NS" get configmap "$cm" -o json | jq -r '.data | to_entries | map(select(.key | endswith(".conf"))) | .[].value'
}

# The attest container is started with --front-door-mode, or, where a launch
# configuration drives the router, with the file that holds it. get-cert, an
# init container, reads the same file into the discovery document it writes, so that mode is
# read from the document the router serves, which needs no exec.
router_tls_mode() {
    local args mode out path conf
    args="$(kubectl -n "$ROUTER_NS" get deploy "$ROUTER_DEPLOY" -o json |
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

# --- Mesh members ---
# The requester the webhook injects into every per-pod mesh member.
MESH_CERT_CONTAINER=c8s-cert

# A restarted CDS mints a new mesh CA, and a per-pod mesh member is bound to
# the CA key of its first leaf for the pod's life (get-cert R3), so only a pod
# created after the restart holds a leaf under the new CA. Every member a
# controller owns, such as the router, outlives the scenario and is
# recreated; a scenario's own pods go with it.
mesh_restart() {
    local members deadline
    members="$(owned_mesh_members)" || return
    [ -n "$members" ] || return 0
    while read -r ns pod; do
        kubectl -n "$ns" delete pod "$pod" --wait=false >/dev/null || return
    done <<<"$members"
    deadline=$(($(date +%s) + 240))
    until owned_mesh_members_ready "$(wc -l <<<"$members")"; do
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the recreated mesh members are not ready after 240s" >&2; return 1; }
        sleep 2
    done
}

# "<namespace> <pod>" for each controller-owned pod carrying the requester.
owned_mesh_members() {
    kubectl get pods -A -o json | jq -r --arg c "$MESH_CERT_CONTAINER" '.items[]
        | select(.metadata.ownerReferences != null)
        | select([(.spec.initContainers // [])[], .spec.containers[]] | any(.name == $c))
        | "\(.metadata.namespace) \(.metadata.name)"'
}

# owned_mesh_members_ready <count>: at least count such pods, none
# terminating, all Ready.
owned_mesh_members_ready() {
    kubectl get pods -A -o json | jq -e --arg c "$MESH_CERT_CONTAINER" --argjson n "$1" '[.items[]
        | select(.metadata.ownerReferences != null)
        | select([(.spec.initContainers // [])[], .spec.containers[]] | any(.name == $c))]
        | length >= $n and all(.metadata.deletionTimestamp == null
            and any(.status.conditions[]?; .type == "Ready" and .status == "True"))' >/dev/null
}

# Once per run, after the scenarios: what this backend did.
teardown() {
    teardown_backend
}

# A namespace the chart's webhook excludes (c8s.webhookExcludedNamespaces),
# which also admits the harness's pods.
exempt_namespace() { echo kube-system; }
# The fully qualified name of the cluster's API Service, which every
# cluster's DNS answers.
api_service_name() { echo kubernetes.default.svc.cluster.local; }

cert_paths() { printf '%s/tls.crt\n%s/tls.key\n' "$CERT_VOLUME_PATH" "$CERT_VOLUME_PATH"; }

# dispatch <function> <args...>: an unknown name is a harness error, not a skip.
dispatch() {
    declare -F "$1" >/dev/null || { echo "backend: no function '$1'" >&2; return 2; }
    "$@"
}
