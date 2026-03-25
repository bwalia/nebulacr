{{/*
Expand the name of the chart.
*/}}
{{- define "nebulacr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nebulacr.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "nebulacr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nebulacr.labels" -}}
helm.sh/chart: {{ include "nebulacr.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nebulacr
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Registry selector labels
*/}}
{{- define "nebulacr.registry.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nebulacr.name" . }}-registry
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: registry
{{- end }}

{{/*
Registry labels
*/}}
{{- define "nebulacr.registry.labels" -}}
{{ include "nebulacr.labels" . }}
{{ include "nebulacr.registry.selectorLabels" . }}
{{- end }}

{{/*
Auth selector labels
*/}}
{{- define "nebulacr.auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nebulacr.name" . }}-auth
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: auth
{{- end }}

{{/*
Auth labels
*/}}
{{- define "nebulacr.auth.labels" -}}
{{ include "nebulacr.labels" . }}
{{ include "nebulacr.auth.selectorLabels" . }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "nebulacr.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nebulacr.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Registry image
*/}}
{{- define "nebulacr.registry.image" -}}
{{- $tag := default .Chart.AppVersion .Values.registry.image.tag -}}
{{- printf "%s:%s" .Values.registry.image.repository $tag }}
{{- end }}

{{/*
Auth image
*/}}
{{- define "nebulacr.auth.image" -}}
{{- $tag := default .Chart.AppVersion .Values.auth.image.tag -}}
{{- printf "%s:%s" .Values.auth.image.repository $tag }}
{{- end }}

{{/*
Secret name for JWT signing keys
*/}}
{{- define "nebulacr.jwt.secretName" -}}
{{- if .Values.jwt.existingSecret }}
{{- .Values.jwt.existingSecret }}
{{- else }}
{{- printf "%s-jwt" (include "nebulacr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for S3 credentials
*/}}
{{- define "nebulacr.s3.secretName" -}}
{{- if .Values.storage.s3.existingSecret }}
{{- .Values.storage.s3.existingSecret }}
{{- else }}
{{- printf "%s-s3" (include "nebulacr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for GCS credentials
*/}}
{{- define "nebulacr.gcs.secretName" -}}
{{- if .Values.storage.gcs.existingSecret }}
{{- .Values.storage.gcs.existingSecret }}
{{- else }}
{{- printf "%s-gcs" (include "nebulacr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for Azure credentials
*/}}
{{- define "nebulacr.azure.secretName" -}}
{{- if .Values.storage.azure.existingSecret }}
{{- .Values.storage.azure.existingSecret }}
{{- else }}
{{- printf "%s-azure" (include "nebulacr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "nebulacr.configMapName" -}}
{{- printf "%s-config" (include "nebulacr.fullname" .) }}
{{- end }}
