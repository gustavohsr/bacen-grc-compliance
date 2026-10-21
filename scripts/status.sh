#!/usr/bin/env bash
# ==============================================================================
# BACEN CMN 4.893 & 5.274 GRC Compliance Platform - Status Checker
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PORT=8080
PID_FILE="${PROJECT_ROOT}/logs/server.pid"

echo "============================================================"
echo "  BACEN CMN 4.893 & 5.274 GRC - Status da Aplicação"
echo "============================================================"

# 1. Status do Serviço Systemd (Sistema)
echo -n "[1] Serviço Systemd (Sistema): "
if systemctl is-active --quiet bacen-grc.service 2>/dev/null; then
    echo "● ATIVO (running)"
    systemctl status bacen-grc.service --no-pager -l | head -n 4 | sed 's/^/    /'
else
    echo "○ INATIVO / NÃO INSTALADO"
fi

# 2. Status do Serviço Systemd (Usuário)
echo -n "[2] Serviço Systemd (Usuário): "
if systemctl --user is-active --quiet bacen-grc.service 2>/dev/null; then
    echo "● ATIVO (running)"
    systemctl --user status bacen-grc.service --no-pager -l | head -n 4 | sed 's/^/    /'
else
    echo "○ INATIVO / NÃO INSTALADO"
fi

# 3. Processo e Porta 8080
echo -n "[3] Processo na Porta ${PORT}: "
RUNNING_PIDS=""
if command -v lsof >/dev/null 2>&1; then
    RUNNING_PIDS=$(lsof -ti :${PORT} 2>/dev/null || true)
fi

if [ -n "${RUNNING_PIDS}" ]; then
    echo "● EM EXECUÇÃO (PID: ${RUNNING_PIDS})"
else
    echo "○ NENHUM PROCESSO ESCUTANDO"
fi

# 4. Verificação de Integridade HTTP
echo -n "[4] Teste HTTP (http://localhost:${PORT}/): "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 http://localhost:${PORT}/ 2>/dev/null || true)
if [ -z "${HTTP_CODE}" ]; then HTTP_CODE="000"; fi
if [ "${HTTP_CODE}" == "200" ]; then
    echo "● ONLINE (HTTP 200 OK)"
else
    echo "○ INDISPONÍVEL (Código HTTP: ${HTTP_CODE})"
fi

# 5. Banco de Dados
echo -n "[5] Base de Dados SQLite: "
if [ -f "${PROJECT_ROOT}/data/compliance.db" ]; then
    DB_SIZE=$(du -h "${PROJECT_ROOT}/data/compliance.db" | cut -f1)
    echo "● PRESENTE (${DB_SIZE})"
else
    echo "○ NÃO ENCONTRADO"
fi
echo "============================================================"
