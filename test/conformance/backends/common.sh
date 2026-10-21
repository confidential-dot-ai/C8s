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
#   seed_add <name> <file>           add the entry in file to the seed the CDS
#                                    follows, under name; unsupported where
#                                    the CDS does not follow its seed or the
#                                    seed it follows is not the cluster's to
#                                    change (only a measured node image's CDS
#                                    follows its seed, and that seed is in
#                                    the image)
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
#   mesh_ready <node>                wait until the node's mesh proxy runs; unsupported
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
#   mesh_arg <flag>                  the mesh proxy's value for --<flag>,
#                                    empty when unset
#   mesh_proxy_log <node>            the mesh proxy's log, with timestamps
#   mesh_pins_satisfied <node>       yes/no: the node's evidence satisfies
#                                    the pins its mesh proxy verifies with
#   mesh_platform                    the evidence family the mesh produces,
#                                    sev-snp or tdx
#   node_address <node> <ipv4|ipv6>  the node's address of that family; unsupported
#                                    when it has none
#   excluded_namespace               a namespace the mesh excludes, or unsupported
#   host_namespace_ns                a namespace admitting pods in the node's
#                                    network namespace and root pods, or unsupported
#   node_writes                      yes, or unsupported where the harness may not
#                                    write Node objects
#   external_endpoint                <address>:<port> of a hello API outside
#                                    the cluster, or unsupported
#   attestation_endpoint             the URL a pod obtains evidence from, or unsupported
#   dialer_bin                       the armtls-dial binary for the node's
#                                    architecture, built once per run; unsupported
#                                    without a Go toolchain
#   cert_paths                       the certificate and key paths of a pod
#                                    carrying a workload ID, one per line
#   cds_request <method> <route> [body-file] [authorization] [client-cert] [client-key] [header...]
#                                    send the request to the CDS from here, as
#                                    given (empty arguments are omitted; each
#                                    header is "Name: value"); prints the
#                                    status (000 when nothing answered), then
#                                    the body
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
# undeclared while a scenario admits this one. "mesh-dialer" is the pod the
# "secret-client" is the image the webhook injects its helpers from, for a
# pod that runs a helper of its own; a backend whose node holds that image
# out of the harness's reach answers unsupported from injected_image. The
# steps copy the mesh peer (tools/armtls-dial, dialer_bin) into: an image with
# tar for the copy, which no other logical image shares. The suite's own
# images (images/, built by conformance-images.yml) stand in for the logical
# images CONFORMANCE_IMAGES names: tenant-app, Alpine's python with the
# programs the steps run in it, for every backend; a backend adds its own.
CONFORMANCE_REPO=ghcr.io/confidential-dot-ai/c8s-conformance-
declare -A CONFORMANCE_IMAGES=(
    [tenant-app]=sha256:78bda430629e5c127cc9589533fa7a343ac389f1998da576769fbe00f679e316
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
pod_manifest() { render_pod --sysctl "$PING_SYSCTL" "$@" | manifest_filter; }
# A backend's last word on every pod the harness renders for its own argv.
manifest_filter() { cat; }

# The node's admission plugin binds its socket directory into a container
# named as a sidecar an application may run itself (cds-attest) in a pod
# marked injected; the sockets are group-owned by 65532. Nothing else about
# the pod is c8s's, so the webhook leaves it alone.
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

# The seed the CDS reads is the ConfigMap only where the CDS Deployment
# mounts it; a baked node's CDS reads the seed held in the image, and the
# chart still renders the ConfigMap, which nothing reads. A CDS rereads its
# seed only with --follow-seed, which the chart sets only on a baked node. So
# seed_add answers unsupported on a chart-managed install (not followed) and on a
# baked node (followed, but not the cluster's to change), and the original
# is kept for seed_restore only once a change is possible.
seed_configmap() {
    kubectl -n "$NS" get configmaps -o json |
        jq -r '.items[] | select(.metadata.name | endswith("-allowlist-seed")) | .metadata.name' | head -1
}

seed_followed() {
    kubectl -n "$NS" get deployments -l app.kubernetes.io/component=cds -o json |
        jq -e '[.items[].spec.template.spec.containers[] | select(.name == "cds") | .args[]?] | index("--follow-seed")' >/dev/null
}

# Whether the CDS Deployment mounts the ConfigMap, as a projected volume.
seed_mounted() {
    kubectl -n "$NS" get deployments -l app.kubernetes.io/component=cds -o json |
        jq -e --arg cm "$1" '[.items[].spec.template.spec.volumes[]? | .projected.sources[]?.configMap.name // .configMap.name // empty] | index($cm)' >/dev/null
}

seed_add() {
    local cm original
    cm="$(seed_configmap)"
    [ -n "$cm" ] || return $UNSUPPORTED
    seed_followed && seed_mounted "$cm" || return $UNSUPPORTED
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
# a failure, whose status (unsupported included) is passed on.
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
        render_pod --annotation c8s-conformance/harness-argv=yes -- "$MESH_SCRAPER" "$MESH_SCRAPER_NS" "$node" "$image" sleep 86400 |
            manifest_filter | kubectl apply -f - >/dev/null
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
        if body="$(mesh_scrape curl -sf --max-time 10 "http://$addr:$port/metrics")"; then
            printf '%s\n' "$body"
            return 0
        fi
        rm -f "$(scratch)/mesh-scraper.ready"
    done
    echo "backend: no scrape of $addr:$port" >&2
    return 1
}

mesh_scrape() { kubectl -n "$MESH_SCRAPER_NS" exec "$MESH_SCRAPER" -- "$@"; }

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

mesh_proxy_log() { kubectl -n "$NS" logs "$(mesh_pod_on "$1")" -c armtls-mesh --timestamps; }

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
node_writes() { echo yes; }

cert_paths() { printf '%s/tls.crt\n%s/tls.key\n' "$CERT_VOLUME_PATH" "$CERT_VOLUME_PATH"; }

# dispatch <function> <args...>: an unknown name is a harness error, not a skip.
dispatch() {
    declare -F "$1" >/dev/null || { echo "backend: no function '$1'" >&2; return 2; }
    "$@"
}
