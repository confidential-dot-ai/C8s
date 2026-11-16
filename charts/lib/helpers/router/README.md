# Router helpers

Source: [templates/_router.tpl](../../templates/_router.tpl).
[All helpers](../README.md).

`c8s.routerNginxWorkerFiles` reads the library's `files/router-nginx` set,
whose files name the worker image's config and settings directories.
`c8s.routerNginxFiles` returns the same files with both of those directories
replaced by the one directory its caller mounts, and fails when a file still
names a worker directory.

The ports and paths those files use are constants here: nginx's HTTPS port,
cds-attest's in-pod attest, allowlist-proxy and routing ports, the ACME
HTTP-01 and challenge ports, and the paths nginx answers itself.
`router.reservedPaths` joins the latter for cds-attest's `--reserved-paths`,
so no manifest route is selected under them.

`c8s.routerContainers` renders the pod's nginx, cds-attest and allowlist-proxy
containers from the lane's parameters, which the template's own header lists.
Each chart renders `router.podSpec` around them and names the directory its
nginx reads the files from.

`router.podReader` is the router's ServiceAccount, in the router namespace,
with a ClusterRole that lists and watches pods. cds-attest resolves the agent a
pattern route names from those pods; the dial still checks the agent's leaf, so
what it reads only decides where a dial goes. Both charts render it and run the
router pod under that ServiceAccount.
