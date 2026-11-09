# NRI image-policy helpers

Source: [templates/nri-image-policy-helpers.tpl](../../templates/nri-image-policy-helpers.tpl),
[templates/nri-image-policy-install-script.tpl](../../templates/nri-image-policy-install-script.tpl).
[All helpers](../README.md).

The first file holds the installer DaemonSet's names and labels, the host
paths it writes — the plugin binary, its configuration, the health socket and
the CDS address and pin it stages — and the host volumes and mounts that reach
them, plus the containerd layout it edits and the command that restarts it.
`nri-image-policy.pluginReadyScript` is the readiness endpoint the allowlist
pins as argv.

The second file holds the scripts the DaemonSet runs: the install script
installs the binary, writes the policy configuration, registers the plugin as
a pre-registered NRI plugin and restarts containerd;
`nri-image-policy.restartAndWait` is the restart and readiness tail;
`nri-image-policy.bootConfig` the configuration the plugin reads at start.
Script bodies are allowlisted argv
([Allowlist](../../../lib/helpers/allowlist/README.md#argv-pinned-entries)), so
a changed script changes the entry.
