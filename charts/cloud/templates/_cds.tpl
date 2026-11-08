{{/* CDS pin and address checks. See ../helpers/cds/README.md. */}}

{{/* c8s.validatedCDSPin is the pin an operator passed as content: the
     refvalues document naming the image and launch file this cluster's CDS
     VM proves. A schema below 2 carries no launch file, which is the only
     thing binding that VM to the configuration it serves. */}}
{{- define "c8s.validatedCDSPin" -}}
{{- $document := toString .Values.cds.measurementsConfig -}}
{{- if not $document -}}
{{- fail "VALIDATION_ERROR kind=cds_pins_required: cds.measurementsConfig is empty, so nothing pins the guest identity of this cluster's CDS and nothing dialing it could tell it from any other attested TEE. Pass `c8s install --cds-pin <cds-pin.json>` (written by `c8s cds config new`)." -}}
{{- end -}}
{{- if not (hasPrefix "{" (trim $document)) -}}
{{- fail "VALIDATION_ERROR kind=cds_pin_content: cds.measurementsConfig must be the JSON content of the CDS pin, not a file path — use `c8s install --cds-pin <file>` or helm --set-file cds.measurementsConfig=<file>" -}}
{{- end -}}
{{- $schema := dig "schema_version" "" (mustFromJson $document) -}}
{{- if ne $schema "2" -}}
{{- fail (printf "VALIDATION_ERROR kind=cds_pin_schema: cds.measurementsConfig is schema_version %q, want \"2\": a CDS is pinned to the launch file it serves, which only schema 2 carries" $schema) -}}
{{- end -}}
{{- $document -}}
{{- end -}}

{{/* c8s.checkCDSAddress refuses an endpoint this cluster's clients could not
     dial: one host, a lowercase DNS name or an IPv4 address, and one port in
     1-65535. Takes the value. */}}
{{- define "c8s.checkCDSAddress" -}}
{{- $address := toString . -}}
{{- $refusal := printf "VALIDATION_ERROR kind=cds_address_required: cds.address must be this cluster's CDS as <host>:<port> (got %q), the host a lowercase DNS name or an IPv4 address. Pass `c8s install --cds-address <host:port>`." $address -}}
{{- $parts := splitList ":" $address -}}
{{- if ne (len $parts) 2 -}}{{- fail $refusal -}}{{- end -}}
{{- if not (regexMatch `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` (first $parts)) -}}{{- fail $refusal -}}{{- end -}}
{{- $port := last $parts -}}
{{- if or (not (regexMatch `^[1-9][0-9]*$` $port)) (gt (int $port) 65535) -}}{{- fail $refusal -}}{{- end -}}
{{- end -}}
