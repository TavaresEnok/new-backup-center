#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/var/log/backup_center"
LOG_FILE="${LOG_DIR}/critical_alerts.log"
STATE_DIR="/var/run/backup_center_watchdog"
APACHE_ACCESS_LOG="/var/log/apache2/backupcenter_access.log"
APACHE_ERROR_LOG="/var/log/apache2/backupcenter_error.log"
APP_CONTAINER="backup_sys_app"
WATCH_CONTAINERS=("backup_sys_app" "backup_sys_celery" "backup_sys_celery_vpn" "backup_sys_celery_beat")
ALERT_COOLDOWN_SECONDS=600
WATCHDOG_ENV_FILE="/etc/backup_center/watchdog.env"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
ALERT_WEBHOOK_TOKEN="${ALERT_WEBHOOK_TOKEN:-}"

if [[ -f "${WATCHDOG_ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${WATCHDOG_ENV_FILE}"
fi

mkdir -p "${LOG_DIR}" "${STATE_DIR}"
touch "${LOG_FILE}"

now_epoch() {
    date +%s
}

emit_alert() {
    local key="$1"
    local level="$2"
    local message="$3"
    local state_file="${STATE_DIR}/${key}.ts"
    local now ts
    now="$(now_epoch)"
    ts=0
    if [[ -f "${state_file}" ]]; then
        ts="$(cat "${state_file}" 2>/dev/null || echo 0)"
    fi
    if (( now - ts < ALERT_COOLDOWN_SECONDS )); then
        return 0
    fi
    echo "${now}" > "${state_file}"
    local line
    line="$(date -Is) [${level}] ${message}"
    echo "${line}" >> "${LOG_FILE}"
    logger -t backup-center-alert "${line}"
    send_external_alert "${line}"
}

send_external_alert() {
    local message="$1"
    if [[ -z "${ALERT_WEBHOOK_URL:-}" ]]; then
        return 0
    fi

    local auth_header=()
    if [[ -n "${ALERT_WEBHOOK_TOKEN:-}" ]]; then
        auth_header=(-H "Authorization: Bearer ${ALERT_WEBHOOK_TOKEN}")
    fi

    curl -fsS -m 8 -X POST \
        -H "Content-Type: application/json" \
        "${auth_header[@]}" \
        -d "{\"source\":\"backup-center-watchdog\",\"message\":\"${message//\"/\\\"}\"}" \
        "${ALERT_WEBHOOK_URL}" >/dev/null 2>&1 || true
}

check_http_502() {
    if [[ -f "${APACHE_ACCESS_LOG}" ]] && tail -n 500 "${APACHE_ACCESS_LOG}" | grep -q " 502 "; then
        emit_alert "apache_502_access" "CRIT" "HTTP 502 detectado no access log do Apache"
    fi
    if [[ -f "${APACHE_ERROR_LOG}" ]] && tail -n 300 "${APACHE_ERROR_LOG}" | grep -Eiq "proxy.*(error|timeout)|502"; then
        emit_alert "apache_502_error" "CRIT" "Erro de proxy/502 detectado no error log do Apache"
    fi
}

check_workers_up() {
    local container status
    for container in "${WATCH_CONTAINERS[@]}"; do
        status="$(docker inspect -f '{{.State.Status}}' "${container}" 2>/dev/null || echo missing)"
        if [[ "${status}" != "running" ]]; then
            emit_alert "container_${container}" "CRIT" "Container ${container} fora do ar (status=${status})"
        fi
    done
}

check_health() {
    local app_code proxy_code
    app_code="$(curl -s -o /dev/null -m 8 -w '%{http_code}' http://127.0.0.1:5000/healthz || true)"
    if [[ "${app_code}" != "200" ]]; then
        emit_alert "healthz_app_local" "CRIT" "Healthz local da app retornou HTTP ${app_code}"
    fi

    proxy_code="$(curl -s -o /dev/null -m 8 -w '%{http_code}' -H 'Host: backupcenter.ajustconsulting.com.br' http://127.0.0.1/healthz || true)"
    if [[ "${proxy_code}" != "200" && "${proxy_code}" != "301" ]]; then
        emit_alert "healthz_proxy_local" "CRIT" "Healthz via proxy local retornou HTTP ${proxy_code}"
    fi
}

check_bulk_failures() {
    if docker logs --since 120s "${APP_CONTAINER}" 2>&1 | grep -Eiq "falha.*lote|erro.*lote|bulk.*(fail|error)"; then
        emit_alert "bulk_backup_failure" "WARN" "Padrão de falha em backup em massa detectado"
    fi
}

check_webhook_failures() {
    if docker logs --since 120s "${APP_CONTAINER}" 2>&1 | grep -Eiq "mercadopago webhook processing failed|webhook.*(exception|error|falha)"; then
        emit_alert "payment_webhook_error" "WARN" "Erro de webhook de pagamento detectado"
    fi
}

check_auth_anomalies() {
    if docker logs --since 120s "${APP_CONTAINER}" 2>&1 | grep -Eiq "auth lockout triggered|auth login blocked|forgot-password rate limited"; then
        emit_alert "auth_lockout_or_rate_limit" "WARN" "Anomalia de autenticacao detectada (lockout/rate-limit)"
    fi
    if docker logs --since 120s "${APP_CONTAINER}" 2>&1 | grep -Eiq "account without 2fa|critical account without 2fa"; then
        emit_alert "account_without_2fa" "WARN" "Conta acessou sem 2FA configurado"
    fi
}

main() {
    check_http_502
    check_workers_up
    check_health
    check_bulk_failures
    check_webhook_failures
    check_auth_anomalies
}

main "$@"
