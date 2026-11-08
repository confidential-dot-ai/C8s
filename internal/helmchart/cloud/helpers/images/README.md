# Image helpers

Source: [templates/_images.tpl](../../templates/_images.tpl).
[All helpers](../README.md).

Image helpers render `repository@digest` when a digest is supplied, otherwise
`repository:tag`, and fail when neither is set. Image helpers prefer the digest when both are present. `volumed.image` delegates to
`c8s-common.image`; volumed's image carries cryptsetup and veritysetup.

`c8s.imagePullSecrets` takes `(dict "root" $ "local" <list>)`. A nonempty local
list takes precedence over `Values.imagePullSecrets`; the install-time
`Values.imagePullSecret` is then appended and deduplicated. Callers indent the
rendered `imagePullSecrets:` block with `nindent`.
`c8s.serviceAccountImagePullSecrets` supplies the service account's local list.
