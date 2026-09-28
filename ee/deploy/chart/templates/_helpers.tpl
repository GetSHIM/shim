{{- define "shim.labels" -}}
app.kubernetes.io/name: shim-enterprise
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "shim.security" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile: {type: RuntimeDefault}
{{- end }}

{{- define "shim.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
{{- end }}

{{- define "shim.backendEnv" -}}
envFrom:
  - secretRef:
      name: {{ required "existingSecret is required" .Values.existingSecret | quote }}
env:
  - name: WORKER_HEARTBEAT_PATH
    value: /tmp/shim-worker.json
{{- range $key, $value := .Values.gateway.env }}
  - name: {{ $key }}
    value: {{ $value | toString | quote }}
{{- end }}
{{- if .Values.vault.tokenSecretName }}
  - name: VAULT_TOKEN_FILE
    value: /var/run/shim-vault/token
{{- end }}
{{- if .Values.caBundleConfigMap }}
  - name: SSL_CERT_FILE
    value: /var/run/shim-ca/ca.pem
{{- end }}
{{- end }}

{{- define "shim.mounts" -}}
volumeMounts:
  - name: tmp
    mountPath: /tmp
{{- if .Values.vault.tokenSecretName }}
  - name: vault-token
    mountPath: /var/run/shim-vault
    readOnly: true
{{- end }}
{{- if .Values.caBundleConfigMap }}
  - name: ca-bundle
    mountPath: /var/run/shim-ca
    readOnly: true
{{- end }}
{{- end }}

{{- define "shim.volumes" -}}
volumes:
  - name: tmp
    emptyDir: {sizeLimit: 128Mi}
{{- if .Values.vault.tokenSecretName }}
  - name: vault-token
    secret:
      secretName: {{ .Values.vault.tokenSecretName | quote }}
      defaultMode: 0440
      items:
        - key: {{ .Values.vault.tokenSecretKey | quote }}
          path: token
{{- end }}
{{- if .Values.caBundleConfigMap }}
  - name: ca-bundle
    configMap:
      name: {{ .Values.caBundleConfigMap | quote }}
{{- end }}
{{- end }}
