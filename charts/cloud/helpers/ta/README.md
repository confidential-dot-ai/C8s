# Trust Authority (TA) helpers

Source: [templates/_ta.tpl](../../templates/_ta.tpl).
[All helpers](../README.md).

`c8s.validateTAPin` checks that the pin contains JSON with `schema_version` 2
or 3, which carry the launch file the TA is pinned to. `c8s.checkTAAddress` requires
`<host>:<port>` with a lowercase DNS name or IPv4 host and a port up to 65535.
