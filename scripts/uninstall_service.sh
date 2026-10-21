#!/usr/bin/env bash
# ==============================================================================
# BACEN CMN 4.893 & 5.274 GRC Compliance Platform - Service Uninstaller
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "============================================================"
echo "  Desinstalador de Inicialização Automática - BACEN GRC"
echo "============================================================"

# 1. Systemd User Service
USER_SERVICE="${HOME}/.config/systemd/user/bacen-grc.service"
if [ -f "${USER_SERVICE}" ]; then
    echo "[*] Desativando e removendo Systemd User Service..."
    systemctl --user stop bacen-grc.service 2>/dev/null || true
    systemctl --user disable bacen-grc.service 2>/dev/null || true
    rm -f "${USER_SERVICE}"
    systemctl --user daemon-reload
    echo "[✓] Systemd User Service removido."
fi

# 2. XDG Autostart Desktop
DESKTOP_FILE="${HOME}/.config/autostart/bacen-grc.desktop"
if [ -f "${DESKTOP_FILE}" ]; then
    echo "[*] Removendo XDG Autostart Desktop..."
    rm -f "${DESKTOP_FILE}"
    echo "[✓] XDG Autostart Desktop removido."
fi

# 3. Crontab
CURRENT_CRON="$(crontab -l 2>/dev/null || true)"
if echo "${CURRENT_CRON}" | grep -q "bacen-grc-compliance/scripts/start.sh"; then
    echo "[*] Removendo entrada do crontab..."
    echo "${CURRENT_CRON}" | grep -v "bacen-grc-compliance/scripts/start.sh" | crontab -
    echo "[✓] Entrada do crontab removida."
fi

# 4. Systemd System Service (se existir)
SYSTEM_SERVICE="/etc/systemd/system/bacen-grc.service"
if [ -f "${SYSTEM_SERVICE}" ]; then
    echo "[*] Serviço de sistema encontrado em ${SYSTEM_SERVICE}."
    echo "    Para removê-lo completamente com privilégios de root, execute:"
    echo "    $ sudo systemctl stop bacen-grc.service"
    echo "    $ sudo systemctl disable bacen-grc.service"
    echo "    $ sudo rm -f ${SYSTEM_SERVICE}"
    echo "    $ sudo systemctl daemon-reload"
fi

echo "============================================================"
echo "[✓] Limpeza de inicialização automática concluída."
echo "============================================================"
