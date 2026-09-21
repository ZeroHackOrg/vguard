{{- define "vguard.name" -}}
{{ default .Chart.Name .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "vguard.fullname" -}}
{{ .Release.Name | printf "%s-vguard" | trunc 63 | trimSuffix "-" }}
{{- end -}}