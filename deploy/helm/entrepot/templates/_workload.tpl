{{/* Shared env vars for server and scan-worker containers. */}}
{{- define "entrepot.env" -}}
- name: ENTREPOT_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "entrepot.dbSecretName" . }}
      key: {{ .Values.database.existingSecretKey }}
- name: ENTREPOT_AUTH_SESSIONSECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "entrepot.secretName" . }}
      key: session-secret
- name: ENTREPOT_AUTH_BOOTSTRAPTOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "entrepot.secretName" . }}
      key: bootstrap-token
      optional: true
- name: ENTREPOT_AUTH_OIDC_CLIENTSECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "entrepot.secretName" . }}
      key: oidc-client-secret
      optional: true
- name: ENTREPOT_SECRETS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "entrepot.secretName" . }}
      key: secrets-key
      optional: true
{{- range .Values.auth.gitlab }}
{{- if or .apiToken .feedback }}
- name: {{ include "entrepot.gitlabTokenEnv" .name }}
  valueFrom:
    secretKeyRef:
      name: {{ include "entrepot.secretName" $ }}
      key: gitlab-token-{{ .name }}
      optional: true
{{- end }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "entrepot.gitlabTokenEnv" -}}
ENTREPOT_GITLAB_TOKEN_{{ . | upper | replace "-" "_" | replace "." "_" }}
{{- end }}

{{/* Volume mounts shared by server and scan-worker. */}}
{{- define "entrepot.volumeMounts" -}}
- name: config
  mountPath: /etc/entrepot
  readOnly: true
- name: tmp
  mountPath: /tmp
{{- range .Values.blobStores }}
{{- if eq .type "file" }}
- name: blob-{{ .name }}
  mountPath: /data/{{ .name }}
{{- end }}
{{- end }}
{{- with .Values.extraVolumeMounts }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "entrepot.volumes" -}}
{{- $fullname := include "entrepot.fullname" . -}}
- name: config
  configMap:
    name: {{ $fullname }}
- name: tmp
  emptyDir:
    sizeLimit: {{ .Values.tmp.sizeLimit }}
{{- range .Values.blobStores }}
{{- if eq .type "file" }}
- name: blob-{{ .name }}
  persistentVolumeClaim:
    claimName: {{ default (printf "%s-blob-%s" $fullname .name) .volume.existingClaim }}
{{- end }}
{{- end }}
{{- with .Values.extraVolumes }}
{{ toYaml . }}
{{- end }}
{{- end }}
