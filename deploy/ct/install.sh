#!/usr/bin/env bash
# Install / upgrade omadawrite inside the CT. Idempotent: re-run after
# pushing a new tarball. Never overwrites /etc/omadawrite/env once it exists.
set -euo pipefail

SRC=$(cd "$(dirname "$0")/../.." && pwd)
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q --no-install-recommends \
    python3 python3-fastapi python3-uvicorn python3-httpx python3-cryptography \
    nginx sqlite3 ca-certificates openssl curl

id omadawrite &>/dev/null ||
    useradd --system --home-dir /var/lib/omadawrite --shell /usr/sbin/nologin omadawrite
install -d -o omadawrite -g omadawrite -m 0750 /var/lib/omadawrite /var/lib/omadawrite/captures

# The watchdog pings 8.8.8.8 / 1.0.0.1 without root or capabilities: allow ICMP
# ping sockets for the omadawrite group only (the setting is per network namespace,
# so the CT can set its own).
gid=$(getent group omadawrite | cut -d: -f3)
echo "net.ipv4.ping_group_range = $gid $gid" > /etc/sysctl.d/60-omadawrite-ping.conf
sysctl -q -p /etc/sysctl.d/60-omadawrite-ping.conf
install -d -m 0755 /opt/omadawrite
rm -rf /opt/omadawrite/omadawrite
cp -r "$SRC/app/omadawrite" /opt/omadawrite/
chmod -R go-w /opt/omadawrite

install -d -m 0700 /etc/omadawrite
if [[ ! -s /etc/omadawrite/env ]]; then
    ai=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
    key=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
    ( umask 077
      sed -e "s|^AI_TOKEN=.*|AI_TOKEN=$ai|" -e "s|^COOKIE_KEY=.*|COOKIE_KEY=$key|" \
          "$SRC/deploy/ct/env.example" > /etc/omadawrite/env )
    echo "generated /etc/omadawrite/env (AI_TOKEN, COOKIE_KEY)"
fi

install -m 0644 "$SRC/deploy/ct/omadawrite-web.service" "$SRC/deploy/ct/omadawrite-watchdog.service" \
    /etc/systemd/system/

# Placeholder cert so nginx can start before omadawrite-cert pushes the real one
install -d -m 0755 /etc/nginx/certs
if [[ ! -s /etc/nginx/certs/fullchain.pem ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
        -subj /CN=omadawrite.example.com \
        -keyout /etc/nginx/certs/privkey.pem -out /etc/nginx/certs/fullchain.pem 2>/dev/null
    chmod 600 /etc/nginx/certs/privkey.pem
fi
install -m 0644 "$SRC/deploy/ct/nginx-omadawrite.conf" /etc/nginx/sites-available/omadawrite
ln -sf ../sites-available/omadawrite /etc/nginx/sites-enabled/omadawrite
rm -f /etc/nginx/sites-enabled/default
nginx -t

systemctl daemon-reload
systemctl enable nginx omadawrite-watchdog omadawrite-web
systemctl restart omadawrite-watchdog omadawrite-web
systemctl reload nginx || systemctl restart nginx

sleep 3
curl -fsS http://127.0.0.1:8080/healthz && echo || echo "healthz not OK yet — check: journalctl -u omadawrite-web -u omadawrite-watchdog"
