{{- define "guardian.name" -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}-guardian-ai
{{- end -}}

{{- define "guardian.labels" -}}
app.kubernetes.io/name: guardian-ai
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "guardian.selector" -}}
app.kubernetes.io/name: guardian-ai
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "guardian.secretName" -}}
{{- if .Values.existingSecret -}}{{ .Values.existingSecret }}{{- else -}}{{ include "guardian.name" . }}{{- end -}}
{{- end -}}

{{/* The bundled database's password: the value given, else the one already in the Secret, else a new one. */}}
{{- define "guardian.dbPassword" -}}
{{- if .Values.database.password -}}
{{- .Values.database.password -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (printf "%s-db" (include "guardian.name" .)) -}}
{{- if and $existing $existing.data (index $existing.data "POSTGRES_PASSWORD") -}}
{{- index $existing.data "POSTGRES_PASSWORD" | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}
{{- end -}}
