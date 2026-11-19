{{- define "entrepot.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "entrepot.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "entrepot.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "entrepot.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "entrepot.selectorLabels" -}}
app.kubernetes.io/name: {{ include "entrepot.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector for the API server pods only. The release's other workloads
(postgresql, scan-worker, trivy) share entrepot.selectorLabels, so anything
that targets the server must also match on its component.
*/}}
{{- define "entrepot.serverSelectorLabels" -}}
{{ include "entrepot.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end }}

{{- define "entrepot.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "entrepot.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "entrepot.secretName" -}}
{{- default (printf "%s-auth" (include "entrepot.fullname" .)) .Values.auth.existingSecret }}
{{- end }}

{{- define "entrepot.dbSecretName" -}}
{{- if .Values.database.existingSecret }}
{{- .Values.database.existingSecret }}
{{- else }}
{{- printf "%s-db" (include "entrepot.fullname" .) }}
{{- end }}
{{- end }}

{{/* Returns "true" when any file blob store uses a ReadWriteOnce volume. */}}
{{- define "entrepot.hasRWO" -}}
{{- $rwo := false }}
{{- range .Values.blobStores }}
{{- if and (eq .type "file") (eq (default "ReadWriteOnce" .volume.accessMode) "ReadWriteOnce") }}
{{- $rwo = true }}
{{- end }}
{{- end }}
{{- $rwo }}
{{- end }}

{{/* Reuse an existing generated secret value across upgrades. */}}
{{- define "entrepot.secretValue" -}}
{{- $existing := lookup "v1" "Secret" .ctx.Release.Namespace .name }}
{{- if and $existing (index $existing.data .key) }}
{{- index $existing.data .key | b64dec }}
{{- else if .value }}
{{- .value }}
{{- else }}
{{- randAlphaNum (int .len) }}
{{- end }}
{{- end }}
