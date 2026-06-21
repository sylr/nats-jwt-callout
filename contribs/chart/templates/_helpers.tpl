{{/*
Expand the name of the chart.
*/}}
{{- define "nats-oidc-callout.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nats-oidc-callout.fullname" -}}
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
{{- define "nats-oidc-callout.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nats-oidc-callout.labels" -}}
helm.sh/chart: {{ include "nats-oidc-callout.chart" . }}
{{ include "nats-oidc-callout.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nats-oidc-callout.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nats-oidc-callout.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The name of the service account to use.
*/}}
{{- define "nats-oidc-callout.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nats-oidc-callout.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding the config (rendered or existing).
*/}}
{{- define "nats-oidc-callout.configSecretName" -}}
{{- if .Values.config.existingSecret }}
{{- .Values.config.existingSecret }}
{{- else }}
{{- include "nats-oidc-callout.fullname" . }}
{{- end }}
{{- end }}

{{/*
Key within the config Secret.
*/}}
{{- define "nats-oidc-callout.configSecretKey" -}}
{{- if .Values.config.existingSecret }}
{{- .Values.config.existingSecretKey }}
{{- else }}
{{- "config.yaml" }}
{{- end }}
{{- end }}

{{/*
Whether a separate policy ConfigMap is in play (rendered or existing).
*/}}
{{- define "nats-oidc-callout.policyEnabled" -}}
{{- if or .Values.policy.existingConfigMap (not (empty .Values.policy.values)) }}true{{- end }}
{{- end }}

{{/*
Name of the policy ConfigMap (rendered or existing).
*/}}
{{- define "nats-oidc-callout.policyConfigMapName" -}}
{{- if .Values.policy.existingConfigMap }}
{{- .Values.policy.existingConfigMap }}
{{- else }}
{{- printf "%s-policy" (include "nats-oidc-callout.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Key within the policy ConfigMap.
*/}}
{{- define "nats-oidc-callout.policyConfigMapKey" -}}
{{- if .Values.policy.existingConfigMap }}
{{- .Values.policy.existingConfigMapKey }}
{{- else }}
{{- "policy.yaml" }}
{{- end }}
{{- end }}
