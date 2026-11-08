# CDS helpers

Source: [templates/_cds.tpl](../../templates/_cds.tpl).
[All helpers](../README.md).

`c8s.cdsPinDocument` returns `cds.measurementsConfig` after requiring JSON
content with `schema_version` 2, the schema that carries the launch file the
CDS VM is pinned to. `c8s.checkCDSAddress` takes `cds.address` and requires
`<host>:<port>` with a lowercase DNS name or IPv4 host and a port up to 65535.
