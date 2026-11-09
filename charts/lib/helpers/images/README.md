# Image helpers

Source: [templates/_images.tpl](../../templates/_images.tpl).
[All helpers](../README.md).

Image helpers render `repository@digest` when a digest is supplied, otherwise
`repository:tag`, and fail when neither is set. Image helpers prefer the digest when both are present. `volumed.image` delegates to
`c8s-common.image`; volumed's image carries cryptsetup and veritysetup.

`c8s.imagePullSecrets` takes the root context and renders
`Values.imagePullSecrets` with the install-time `Values.imagePullSecret`
appended and deduplicated.
