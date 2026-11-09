# Component table helpers

Source: [templates/_components.tpl](../../templates/_components.tpl).
[All helpers](../README.md).

`c8s.componentsFile` returns the library's `files/components.yaml`, the one
place the C8s component images and the router's nginx pin are written down. It
takes the root context of a chart depending on c8s-lib and fails without it,
since the file is read through the subchart.

`c8s.componentList` is the component table as JSON, which the image and
allowlist helpers index by repository. `c8s.routerNginxPin` is the nginx
entry's image, entrypoint and image environment as JSON.
