# Cloud router helpers

Source: [templates/router-helpers.tpl](../../templates/router-helpers.tpl).
[All helpers](../README.md).

The cloud lane's side of c8s-lib's
[router helpers](../../../lib/helpers/router/README.md).

`router.san` is the single identity baked into the router's CDS-issued mesh
certificate, which the CDS's own leaf DNS rules must admit: the first
`router.san` entry, or the chart-managed Service DNS name where the list is
empty. `router.validateSan` holds the hostname rule both go through.

`router.configDir` names the directory nginx reads the files from, and
`router.cloudNginxFiles` the file set the chart renders into one ConfigMap:
c8s-lib's, with the request-body and TLS settings this lane fixes.
`router.publicPorts` publishes nginx's HTTPS port on the node's port 443.

The remaining helpers build the pod's cds-attest and get-cert argv and mounts,
which pin this lane's front-door mode `cds`.
