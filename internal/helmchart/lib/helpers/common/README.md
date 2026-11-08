# Common helpers

Sources: [_names.tpl](../../templates/_names.tpl),
[_ints.tpl](../../templates/_ints.tpl),
[_identities.tpl](../../templates/_identities.tpl).
[All helpers](../README.md).

Resource names derive from `.Release.Name`, truncate to 63 characters, and trim
trailing hyphens. `c8s.commonLabels` provides the shared chart labels.

`c8s.int` renders integer values through `int64`, avoiding scientific notation
for numeric values loaded from a values file. `c8s.positiveInt` takes a dict with
`value` and `label`, requires a positive decimal integer, and uses the label in
its validation error.
