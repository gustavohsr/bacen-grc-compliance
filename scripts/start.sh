#!/usr/bin/env bash
# ==============================================================================
# BACEN CMN 4.893 & 5.274 GRC Compliance Platform - Startup Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PORT=8080
PID_FILE="${PROJECT_ROOT}/logs/server.pid"
LOG_FILE="${PROJECT_ROOT}/logs/server.log"
PYTHON_BIN="$(which python3 || echo "/usr/bin/python3")"

mkdir -p "${PROJECT_ROOT}/logs" "${PROJECT_ROOT}/uploads" "${PROJECT_ROOT}/data"

# Verifica se a porta 8080 já está em uso
if command -v ss >/dev/null 2>&1; then
    PORT_IN_USE=$(ss -tlnp 2>/dev/null | grep ":${PORT} " || true)
elif command -v netstat >/dev/null 2>&1; then
    PORT_IN_USE=$(netstat -tlnp 2>/dev/null | grep ":${PORT} " || true)
elif command -v lsof >/dev/null 2>&1; then
    PORT_IN_USE=$(lsof -ti :${PORT} 2>/dev/null || true)
else
    PORT_IN_USE=""
fi

if [ -n "${PORT_IN_USE}" ]; then
    echo "[!] A porta ${PORT} já está em uso por outro processo:"
    echo "    ${PORT_IN_USE}"
    if [ -f "${PID_FILE}" ]; then
        EXISTING_PID=$(cat "${PID_FILE}" 2>/dev/null || true)
        if [ -n "${EXISTING_PID}" ] && kill -0 "${EXISTING_PID}" 2>/dev/null; then
            echo "[*] Aplicação já ativa no PID ${EXISTING_PID}."
            exit 0
        fi
    fi
    echo "[*] Se desejar reiniciar a aplicação, execute: ${SCRIPT_DIR}/stop.sh && ${SCRIPT_DIR}/start.sh"
    exit 0
fi

# Garante inicialização do banco de dados caso não exista
if [ ! -f "${PROJECT_ROOT}/data/compliance.db" ]; then
    echo "[*] Banco de dados não encontrado. Inicializando e aplicando seeds regulatórios..."
    cd "${PROJECT_ROOT}"
    "${PYTHON_BIN}" db_init.py
    "${PYTHON_BIN}" seed_data.py
    echo "[✓] Banco de dados pronto."
fi

# Suporte ao modo daemon / background
DAEMON_MODE=false
for arg in "$@"; do
    if [ "$arg" == "--daemon" ] || [ "$arg" == "-d" ] || [ "$arg" == "--background" ]; then
        DAEMON_MODE=true
    fi
done

cd "${PROJECT_ROOT}"
export PYTHONUNBUFFERED=1

if [ "${DAEMON_MODE}" = true ]; then
    echo "[*] Iniciando BACEN GRC Platform em segundo plano (daemon)..."
    nohup "${PYTHON_BIN}" server.py >> "${LOG_FILE}" 2>&1 &
    NEW_PID=$!
    echo "${NEW_PID}" > "${PID_FILE}"
    sleep 1
    if kill -0 "${NEW_PID}" 2>/dev/null; then
        echo "[✓] BACEN GRC Platform iniciada com sucesso!"
        echo "    - PID: ${NEW_PID}"
        echo "    - URL: http://localhost:${PORT}"
        echo "    - Logs: ${LOG_FILE}"
    else
        echo "[✗] Falha ao iniciar aplicação. Verifique o log em ${LOG_FILE}"
        exit 1
    fi
else
    echo "[*] Iniciando BACEN GRC Platform em primeiro plano (Ctrl+C para encerrar)..."
    echo $$ > "${PID_FILE}"
    exec "${PYTHON_BIN}" server.py
fi
