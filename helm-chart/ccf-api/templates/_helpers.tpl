{{/*
Expand the name of the chart.
*/}}
{{- define "ccf-api.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ccf-api.fullname" -}}
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
{{- define "ccf-api.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ccf-api.labels" -}}
helm.sh/chart: {{ include "ccf-api.chart" . }}
{{ include "ccf-api.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ccf-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ccf-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create PostgreSQL connection string
*/}}
{{- define "ccf-api.postgresConnection" -}}
{{- printf "host=%s-postgresql user=%s password=%s dbname=%s port=%d sslmode=disable" (include "ccf-api.fullname" .) .Values.postgresql.auth.username .Values.postgresql.auth.password .Values.postgresql.auth.database (.Values.postgresql.service.port | int) }}
{{- end }}