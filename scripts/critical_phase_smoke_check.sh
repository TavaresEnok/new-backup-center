#!/usr/bin/env bash
set -euo pipefail

ROOT_PASS="${ROOT_PASS:-}"

run_root() {
  if [[ -n "${ROOT_PASS}" ]]; then
    printf '%s\n' "${ROOT_PASS}" | su root -c "$1"
  else
    su root -c "$1"
  fi
}

ok() { echo "[OK] $*"; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

check_http_redirect() {
  local out code redirect
  out="$(run_root "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: backupcenter.ajustconsulting.com.br' http://127.0.0.1/" || true)"
  code="${out%% *}"
  redirect="${out#* }"
  [[ "${code}" == "301" ]] || fail "proxy HTTP esperado 301, obtido ${code}"
  [[ "${redirect}" == "https://backupcenter.ajustconsulting.com.br/" ]] || fail "redirect inesperado: ${redirect}"
  ok "proxy HTTP redireciona para HTTPS"
}

check_healthz() {
  local app_code proxy_code
  app_code="$(run_root "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/healthz" || true)"
  [[ "${app_code}" == "200" ]] || fail "app /healthz esperado 200, obtido ${app_code}"
  proxy_code="$(run_root "curl -s -o /dev/null -w '%{http_code}' -H 'Host: backupcenter.ajustconsulting.com.br' http://127.0.0.1/healthz" || true)"
  [[ "${proxy_code}" == "200" || "${proxy_code}" == "301" ]] || fail "proxy /healthz esperado 200/301, obtido ${proxy_code}"
  ok "healthz local app/proxy validos"
}

check_containers() {
  local missing="" container status
  for container in backup_sys_app backup_sys_celery backup_sys_celery_vpn backup_sys_celery_beat backup_sys_db backup_sys_redis; do
    status="$(run_root "docker inspect -f '{{.State.Status}}' ${container} 2>/dev/null || echo missing" || true)"
    if [[ "${status}" != "running" ]]; then
      missing+="${container}:${status} "
    fi
  done
  [[ -z "${missing}" ]] || fail "containers fora do ar: ${missing}"
  ok "containers criticos em execucao"
}

check_ports() {
  local listeners
  listeners="$(run_root "ss -ltnp | grep -E ':5001 |:5436 |:6383 ' || true")"
  [[ -z "${listeners}" ]] || fail "portas indevidas abertas: ${listeners}"
  ok "portas indevidas fechadas"
}

check_firewall() {
  local status rules
  status="$(run_root "/usr/sbin/ufw status" || true)"
  echo "${status}" | grep -q "Status: active" || fail "ufw inativo"
  rules="$(run_root "/sbin/iptables -S ufw-user-input" || true)"
  echo "${rules}" | grep -q -- "--dport 24365" || fail "regra SSH 24365 ausente"
  echo "${rules}" | grep -q -- "--dport 80" || fail "regra 80 ausente"
  echo "${rules}" | grep -q -- "--dport 443" || fail "regra 443 ausente"
  echo "${rules}" | grep -q -- "--dport 3389" && fail "regra indevida 3389 detectada"
  ok "firewall ativo com regras basicas"
}

check_legacy_disabled() {
  local active
  active="$(run_root "systemctl is-active mikrotik-legacy-gunicorn.service mikrotik-legacy-celery.service mikrotik-legacy-celery-vpn.service mikrotik-legacy-flower.service 2>/dev/null || true")"
  echo "${active}" | grep -Eq "^active$" && fail "servicos legados ainda ativos: ${active}"
  ok "servicos legados desativados"
}

check_watchdog() {
  run_root "systemctl is-enabled backup-center-watchdog.timer >/dev/null" || fail "watchdog timer desabilitado"
  run_root "systemctl is-active backup-center-watchdog.timer >/dev/null" || fail "watchdog timer inativo"
  ok "watchdog critico ativo"
}

main() {
  check_http_redirect
  check_healthz
  check_containers
  check_ports
  check_firewall
  check_legacy_disabled
  check_watchdog
  ok "smoke check da fase critica concluido"
}

main "$@"
