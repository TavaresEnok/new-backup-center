#!/bin/sh
set -eu

mkdir -p /run/dbus /run/NetworkManager /var/lib/NetworkManager
rm -f /run/dbus/pid /run/dbus/system_bus_socket /run/NetworkManager/NetworkManager.pid

# Garante que /dev/ppp existe (necessario para pppd/xl2tpd).
if [ ! -e /dev/ppp ]; then
  mknod /dev/ppp c 108 0 2>/dev/null || true
fi
cat >/etc/NetworkManager/NetworkManager.conf <<'EOF'
[main]
plugins=keyfile

[ifupdown]
managed=true

[device]
wifi.scan-rand-mac-address=no
EOF

dbus-daemon --system --fork --nopidfile

NetworkManager --no-daemon &
nm_pid="$!"

cleanup() {
  kill "$nm_pid" >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

ready=0
for _ in $(seq 1 30); do
  if nmcli --terse --fields RUNNING general status 2>/dev/null | grep -qi running; then
    ready=1
    break
  fi
  sleep 1
done

if [ "$ready" != "1" ]; then
  echo "NetworkManager nao ficou pronto no worker VPN isolado." >&2
  nmcli general status >&2 || true
  exit 1
fi

eth0_addr="$(ip -4 -o addr show dev eth0 | awk '{print $4; exit}')"
eth0_gateway="$(ip route show default 0.0.0.0/0 dev eth0 | awk '{print $3; exit}')"

if [ -z "$eth0_addr" ] || [ -z "$eth0_gateway" ]; then
  echo "Nao foi possivel detectar IP/gateway da eth0 no worker VPN isolado." >&2
  ip -4 addr show dev eth0 >&2 || true
  ip route show default >&2 || true
  exit 1
fi

nmcli device set eth0 managed yes || true
nmcli connection down container-eth0 >/dev/null 2>&1 || true
nmcli connection delete container-eth0 >/dev/null 2>&1 || true
nmcli connection delete eth0 >/dev/null 2>&1 || true
nmcli connection delete "Wired connection 1" >/dev/null 2>&1 || true
nmcli connection add \
  type ethernet \
  con-name container-eth0 \
  ifname eth0 \
  ipv4.method manual \
  ipv4.addresses "$eth0_addr" \
  ipv4.gateway "$eth0_gateway" \
  ipv4.dns "127.0.0.11" \
  ipv4.never-default no \
  ipv6.method ignore
nmcli connection up container-eth0

if ! nmcli --terse --fields GENERAL.STATE,GENERAL.CONNECTION device show eth0 | grep -q "GENERAL.CONNECTION:container-eth0"; then
  echo "NetworkManager nao assumiu a eth0 como conexao gerenciada." >&2
  nmcli device status >&2 || true
  nmcli connection show >&2 || true
  exit 1
fi

vpn_concurrency="${CELERY_VPN_WORKER_CONCURRENCY:-1}"
if [ "$vpn_concurrency" != "1" ]; then
  echo "CELERY_VPN_WORKER_CONCURRENCY=$vpn_concurrency ignorado: use --scale celery_vpn=N para paralelismo com uma VPN por container." >&2
  vpn_concurrency=1
fi

exec celery -A app.celery_app worker -E -l info -Q vpn_queue \
  --concurrency="$vpn_concurrency" \
  --prefetch-multiplier=1 \
  --max-tasks-per-child="${CELERY_VPN_MAX_TASKS_PER_CHILD:-1}" \
  --hostname="vpnworker@%h"
