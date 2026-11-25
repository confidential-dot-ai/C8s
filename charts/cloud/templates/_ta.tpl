{{- define "c8s.validateTAPin" -}}
{{- $document := default "" . -}}
{{- if not $document -}}
{{- fail "VALIDATION_ERROR kind=ta_pins_required: ta.measurementsConfig is empty, so nothing pins the guest identity of this cluster's Trust Authority and nothing dialing it could tell it from any other attested TEE. Pass `c8s install --ta-pin <pin.json>` (written by `c8s ta config new`)." -}}
{{- end -}}
{{- if not (hasPrefix "{" (trim $document)) -}}
{{- fail "VALIDATION_ERROR kind=ta_pin_content: ta.measurementsConfig must be the JSON content of the Trust Authority pin, not a file path — use `c8s install --ta-pin <file>` or helm --set-file ta.measurementsConfig=<file>" -}}
{{- end -}}
{{- $schema := dig "schema_version" "" (mustFromJson $document) -}}
{{- if ne $schema "2" -}}
{{- fail (printf "VALIDATION_ERROR kind=ta_pin_schema: ta.measurementsConfig is schema_version %q, want \"2\": a Trust Authority is pinned to the launch file it serves, which only schema 2 carries" $schema) -}}
{{- end -}}
{{- end -}}

{{/* c8s.checkTAAddress refuses an endpoint this cluster's clients could not
     dial: one host, a lowercase DNS name or an IPv4 address, and one port in
     1-65535. Takes the value. */}}
{{- define "c8s.checkTAAddress" -}}
{{- $address := default "" . -}}
{{- $refusal := printf "VALIDATION_ERROR kind=ta_address_required: ta.address must be this cluster's Trust Authority as <host>:<port> (got %q), the host a lowercase DNS name or an IPv4 address. Pass `c8s install --ta-address <host:port>`." $address -}}
{{- $parts := splitList ":" $address -}}
{{- if ne (len $parts) 2 -}}{{- fail $refusal -}}{{- end -}}
{{- if not (regexMatch `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` (first $parts)) -}}{{- fail $refusal -}}{{- end -}}
{{- $port := last $parts -}}
{{- if or (not (regexMatch `^[1-9][0-9]*$` $port)) (gt (int $port) 65535) -}}{{- fail $refusal -}}{{- end -}}
{{- end -}}
