{{- define "silver.externalIPInitContainer" -}}
- name: external-ip
  image: "{{ .Values.externalIP.image.repository }}:{{ .Values.externalIP.image.tag }}"
  imagePullPolicy: {{ .Values.externalIP.image.pullPolicy }}
  env:
    - name: EXTERNAL_IP
      value: {{ .Values.externalIP.value | quote }}
    - name: EXTERNAL_IP_SERVICE_URL
      value: {{ .Values.externalIP.serviceURL | quote }}
  command:
    - /bin/sh
    - -ec
  args:
    - |
      is_ipv4() {
        printf '%s\n' "$1" | awk -F. '
          NF != 4 { exit 1 }
          {
            for (i = 1; i <= 4; i++) {
              if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) {
                exit 1
              }
            }
          }
        '
      }

      ip="$EXTERNAL_IP"
      if [ -z "$ip" ]; then
        attempts=0
        while [ "$attempts" -lt 30 ]; do
          ip="$(wget -qO- "$EXTERNAL_IP_SERVICE_URL" 2>/dev/null | tr -d '\r\n' || true)"
          if is_ipv4 "$ip"; then
            break
          fi
          attempts=$((attempts + 1))
          sleep 2
        done
      fi

      if ! is_ipv4 "$ip"; then
        echo "Unable to determine a valid external IPv4 address" >&2
        exit 1
      fi

      printf '%s' "$ip" > /network/external-ip
  resources:
    {{- toYaml .Values.externalIP.resources | nindent 4 }}
  volumeMounts:
    - name: external-ip
      mountPath: /network
{{- end }}
