{{/* c8s.cdsContainers renders the CDS container list. .ha selects the HA
     replica variant (cds-role nodes); the rest of the context is the chart's. */}}
{{- define "c8s.cdsContainers" }}
      containers:
        - name: cds
          image: {{ include "c8s.cdsImage" . }}
          imagePullPolicy: {{ .Values.cds.image.pullPolicy }}
          args:
            - --port={{ .Values.cds.port }}
            - --log-level={{ .Values.cds.logLevel }}
            # Per-mode resolution: see c8s.attestationApiURL.
            - --attestation-api-url={{ include "c8s.attestationApiURL" . }}
            - --allowlist-db={{ .Values.cds.allowlistDB }}
            - --allowlist-persistent={{ .Values.cds.persistence.enabled }}
            {{- if .Values.node.baked }}
            - --allowlist-seed=/run/c8s-node/allowlist-seed.json
            - --operator-keys=/run/c8s-node/operator-pubkey
            - --dns-san-file=/run/c8s-node/tls-san
            {{- else }}
            - --allowlist-seed=/etc/cds/allowlist-seed.json
            {{- end }}
            - --jwt-clock-skew={{ .Values.cds.jwtClockSkew }}
            - --ca-common-name={{ .Values.cds.ca.commonName }}
            - --ca-cert-validity={{ .Values.cds.ca.certValidity }}
            - --min-ca-validity={{ .Values.cds.ca.minValidity }}
            - --cert-ttl={{ .Values.cds.certTTL }}
            - --named-cert-ttl={{ .Values.cds.namedCertTTL }}
            - --challenge-ttl={{ .Values.cds.challengeTTL }}
            - --request-timeout={{ .Values.cds.requestTimeout }}
            - --max-request-size={{ .Values.cds.maxRequestSize }}
            - --secrets-max-paths={{ include "c8s.positiveInt" (dict "value" .Values.cds.secretsMaxPaths "label" "cds.secretsMaxPaths") }}
            - --secrets-max-paths-per-workload={{ include "c8s.positiveInt" (dict "value" .Values.cds.secretsMaxPathsPerWorkload "label" "cds.secretsMaxPathsPerWorkload") }}
            - --readiness-interval={{ .Values.cds.readinessInterval }}
            - --san-validation={{ .Values.cds.sanValidation }}
            {{- /* Always allow in-cluster Service SANs so the mesh's own
                   get-cert/armtls-mesh CSRs validate; operators append public
                   hostnames via cds.dnsSanPatterns without restating this. */}}
            - --dns-san-pattern={{ include "c8s.cdsDnsSanPattern" . }}
            {{- range .Values.cds.dnsSanPatterns }}
            - --dns-san-pattern={{ . }}
            {{- end }}
            {{- if .Values.cds.cnPattern }}
            - --allowed-cn-pattern={{ .Values.cds.cnPattern }}
            {{- end }}
            {{- if .Values.node.baked }}
            - --image-policy-file=/run/c8s-node/peers.json
            {{- else if .Values.cds.measurementsConfig }}
            - --image-policy-file=/etc/c8s-measurements/cds.json
            {{- else }}
            {{- with .Values.cds.measurements }}
            - --measurements={{ join "," . }}
            {{- end }}
            {{- with .Values.cds.rtmrs }}
            - --rtmrs={{ join "," . }}
            {{- end }}
            {{- end }}
            {{- with .Values.cds.sandboxInventoryCIDRs }}
            - --sandbox-inventory-cidr={{ join "," . }}
            {{- end }}
            {{- if and (not .Values.node.baked) .Values.cds.operatorKeys }}
            - --operator-keys=/etc/cds-operator-keys/keys.pem
            {{- end }}
            - --rate-limit={{ .Values.cds.rateLimit }}
            - --rate-burst={{ .Values.cds.rateBurst }}
            - --rate-limiter-max-entries={{ .Values.cds.rateLimiterMaxEntries }}
            - --rate-limiter-evict-interval={{ .Values.cds.rateLimiterEvictInterval }}
            - --rate-limiter-idle-timeout={{ .Values.cds.rateLimiterIdleTimeout }}
            - --armtls-platform={{ .Values.cds.armtlsPlatform }}
            - --armtls-cert-ttl={{ .Values.cds.armtlsCertTTL }}
            {{- if .ha }}
            # HA replica on a cds-role node: trust roots come from the signed
            # launch document (cds-ha.json), never from these arguments.
            - --ha-config=/run/c8s-node/cds-ha.json
            - --ha-namespace={{ .Release.Namespace }}
            - --ha-decree-namespace={{ .Values.cds.ha.decreeNamespace }}
            - --ha-peers-dns={{ include "c8s.cdsName" . }}-peers.{{ .Release.Namespace }}.svc
            - --ha-port={{ .Values.cds.ha.peerPort }}
            - --ha-attestor=node
            {{- else if .Values.node.baked }}
            # The singleton exits when the launch document selects HA.
            - --ha-yield-file=/run/c8s-node/cds-mode
            {{- end }}
          {{- with (include "c8s.attestationApiHostIPEnv" .) }}
          # cvmMode=bare-metal: expands $(HOST_IP) in --attestation-api-url to the node
          # IP so this pod-netns pod reaches the node-baked host attestation-api.
          env:
            {{- . | nindent 12 }}
          {{- end }}
          ports:
            - name: https
              containerPort: {{ .Values.cds.port }}
            {{- if .ha }}
            - name: peer
              containerPort: {{ .Values.cds.ha.peerPort }}
            {{- end }}

          readinessProbe:
            httpGet:
              path: /readyz
              port: https
              scheme: HTTPS
            initialDelaySeconds: 3
            {{- if .ha }}
            # A replica that stops serving (rotation it lacks the key for,
            # retirement) must leave the Service endpoints quickly.
            periodSeconds: 2
            failureThreshold: 1
            {{- end }}
          livenessProbe:
            {{- if .ha }}
            # An HA replica opens its main port only once it holds the mesh CA
            # key, which may wait for a Genesis decree or a peer: probe the
            # peer listener, which is up from the start.
            tcpSocket:
              port: peer
            {{- else }}
            httpGet:
              path: /healthz
              port: https
              scheme: HTTPS
            {{- end }}
            periodSeconds: 30

          resources:
{{ toYaml .Values.cds.resources | indent 12 }}
          volumeMounts:
            - name: data
              mountPath: /data
            {{- include "c8s.attestationApiSocketMount" . | nindent 12 }}
            {{- include "c8s.nodeConfigMount" . | nindent 12 }}
            {{- if not .Values.node.baked }}
            - name: allowlist-seed
              mountPath: /etc/cds
              readOnly: true
            {{- if .Values.cds.operatorKeys }}
            - name: operator-keys
              mountPath: /etc/cds-operator-keys
              readOnly: true
            {{- end }}
            {{- if .Values.cds.measurementsConfig }}
            - name: measurements-config
              mountPath: /etc/c8s-measurements
              readOnly: true
            {{- end }}
            {{- end }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true

            runAsNonRoot: true
            runAsUser: 65532

            capabilities:
              drop:
                - ALL
{{- end -}}
