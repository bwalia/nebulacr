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

{{/*
Upstream registry secret name
*/}}
{{/*
Validate JWT signing key configuration.
Fails the render if no signing key source is configured in production.
*/}}
{{- define "nebulacr.jwt.validate" -}}
{{- if and (not .Values.jwt.existingSecret) (not .Values.jwt.signingKey) }}
{{- fail "SECURITY: jwt.existingSecret or jwt.signingKey must be set. Running with embedded dev keys is not supported. Generate keys with: openssl genrsa -out signing.pem 2048 && openssl rsa -in signing.pem -pubout -out verification.pem" }}
{{- end }}
{{- end }}

{{/*
Postgres (scanner metadata store).
*/}}
{{- define "nebulacr.postgres.fullname" -}}
{{- printf "%s-postgres" (include "nebulacr.fullname" .) -}}
{{- end }}

{{- define "nebulacr.postgres.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nebulacr.name" . }}-postgres
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end }}

{{- define "nebulacr.postgres.labels" -}}
{{ include "nebulacr.labels" . }}
{{ include "nebulacr.postgres.selectorLabels" . }}
{{- end }}

{{- define "nebulacr.postgres.secretName" -}}
{{- if .Values.postgres.existingSecret }}
{{- .Values.postgres.existingSecret }}
{{- else }}
{{- printf "%s-postgres" (include "nebulacr.fullname" .) -}}
{{- end }}
{{- end }}

{{/*
Resolve a postgres password. Priority: user-supplied → existing in-cluster
secret → fresh 24-char random. The lookup preserves the generated password
across helm upgrades so the registry doesn't break after re-render.
*/}}
{{- define "nebulacr.postgres.password" -}}
{{- if .Values.postgres.password -}}
{{- .Values.postgres.password -}}
{{- else -}}
  {{- $secretName := printf "%s-postgres" (include "nebulacr.fullname" .) -}}
  {{- $existing := lookup "v1" "Secret" .Release.Namespace $secretName -}}
  {{- if and $existing $existing.data (index $existing.data "password") -}}
    {{- index $existing.data "password" | b64dec -}}
  {{- else -}}
    {{- randAlphaNum 24 -}}
  {{- end -}}
{{- end -}}
{{- end }}

{{- define "nebulacr.scanner.postgresUrl" -}}
{{- $user := .Values.postgres.username | default "nebulacr" -}}
{{- $db := .Values.postgres.database | default "nebulacr" -}}
{{- $host := printf "%s.%s.svc.cluster.local" (include "nebulacr.postgres.fullname" .) .Release.Namespace -}}
{{- printf "postgres://%s:$(NEBULACR_POSTGRES_PASSWORD)@%s:5432/%s?sslmode=disable" $user $host $db -}}
{{- end }}

{{/*
Redis (scanner ephemeral result cache).
*/}}
{{- define "nebulacr.redis.fullname" -}}
{{- printf "%s-redis" (include "nebulacr.fullname" .) -}}
{{- end }}

{{- define "nebulacr.redis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nebulacr.name" . }}-redis
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: redis
{{- end }}

{{- define "nebulacr.redis.labels" -}}
{{ include "nebulacr.labels" . }}
{{ include "nebulacr.redis.selectorLabels" . }}
{{- end }}

{{- define "nebulacr.scanner.redisUrl" -}}
{{- $host := printf "%s.%s.svc.cluster.local" (include "nebulacr.redis.fullname" .) .Release.Namespace -}}
{{- printf "redis://%s:6379" $host -}}
{{- end }}

{{/*
Upstream registry secret name
*/}}
{{- define "nebulacr.upstream.secretName" -}}
{{- $fullname := index . 0 -}}
{{- $name := index . 1 -}}
{{- $upstream := index . 2 -}}
{{- if $upstream.existingSecret }}
{{- $upstream.existingSecret }}
{{- else }}
{{- printf "%s-upstream-%s" $fullname ($name | replace "." "-") }}
{{- end }}
{{- end }}
