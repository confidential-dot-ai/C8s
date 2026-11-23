# Trust Authority (TA) helpers

Source: [templates/_ta.tpl](../../templates/_ta.tpl).
[All helpers](../README.md).

`c8s.trustAuthority` selects the address, measurements and operator keys from
one values block. When both `ta` and `cds` supply settings, they must agree.
`c8s.validateTAPin` checks that the pin contains JSON with `schema_version` 2,
which carries the launch file the TA VM is pinned to. `c8s.checkTAAddress` requires
`<host>:<port>` with a lowercase DNS name or IPv4 host and a port up to 65535.
