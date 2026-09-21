#!/usr/bin/env bash
# ==============================================================================
# crypto55 — Script de Déploiement vers horos-prod (37.187.150.79)
# Cible : Sous-domaine crypto55.hazyhaar.fr
# ==============================================================================

set -euo pipefail

TARGET_HOST="horos-prod" # Configuré dans ~/.ssh/config ou 37.187.150.79
REMOTE_DIR="/var/www/crypto55"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== 1. Compilation du binaire Linux pur Go 1.27 statique (CGO_ENABLED=0) ==="
cd "${ROOT_DIR}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/crypto55 ./cmd/crypto55
echo "✓ Binaire compilé avec succès : bin/crypto55 ($(du -h bin/crypto55 | cut -f1))"

echo "=== 2. Préparation du répertoire distant sur ${TARGET_HOST} ==="
ssh "${TARGET_HOST}" "sudo mkdir -p ${REMOTE_DIR} /var/log/crypto55 && sudo chown -R www-data:www-data ${REMOTE_DIR} /var/log/crypto55"

echo "=== 3. Transfert du binaire statique et du service systemd ==="
scp "${ROOT_DIR}/bin/crypto55" "${TARGET_HOST}:/tmp/crypto55"
ssh "${TARGET_HOST}" "sudo mv /tmp/crypto55 ${REMOTE_DIR}/crypto55 && sudo chmod +x ${REMOTE_DIR}/crypto55 && sudo chown www-data:www-data ${REMOTE_DIR}/crypto55"

scp "${SCRIPT_DIR}/crypto55.service" "${TARGET_HOST}:/tmp/crypto55.service"
ssh "${TARGET_HOST}" "sudo mv /tmp/crypto55.service /etc/systemd/system/crypto55.service && sudo systemctl daemon-reload"

echo "=== 4. Activation et démarrage de crypto55.service ==="
ssh "${TARGET_HOST}" "sudo systemctl enable --now crypto55.service && sudo systemctl restart crypto55.service"

echo "=== 5. Vérification du statut HTTP local sur .79 ==="
ssh "${TARGET_HOST}" "sleep 1 && curl -s http://127.0.0.1:8555/health" || true

echo ""
echo "=== Déploiement achevé avec succès sur ${TARGET_HOST} ==="
echo "Portail web et simulateur actifs en arrière-plan (127.0.0.1:8555)."
echo "Pour achever le reverse proxy public, installez la conf Nginx (nginx-crypto55.conf) ou Caddy (Caddyfile)."
