#!/usr/bin/env bash
# ==============================================================================
# BACEN CMN 4.893 & 5.274 GRC Compliance Platform - Stop Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PORT=8080
PID_FILE="${PROJECT_ROOT}/logs/server.pid"

TARGET_PIDS=()

# 1. Verifica PID no arquivo PID_FILE
if [ -f "${PID_FILE}" ]; then
    PID_FROM_FILE=$(cat "${PID_FILE}" 2>/dev/null || true)
    if [ -n "${PID_FROM_FILE}" ] && kill -0 "${PID_FROM_FILE}" 2>/dev/null; then
        TARGET_PIDS+=("${PID_FROM_FILE}")
    fi
    rm -f "${PID_FILE}"
fi

# 2. Localiza processo escutando na porta 8080
if command -v lsof >/dev/null 2>&1; then
    LSOF_PIDS=$(lsof -ti :${PORT} 2>/dev/null || true)
    for p in ${LSOF_PIDS}; do
        if kill -0 "${p}" 2>/dev/null; then
            TARGET_PIDS+=("${p}")
        fi
    done
elif command -v fuser >/dev/null 2>&1; then
    FUSER_PIDS=$(fuser ${PORT}/tcp 2>/dev/null || true)
    for p in ${FUSER_PIDS}; do
        if kill -0 "${p}" 2>/dev/null; then
            TARGET_PIDS+=("${p}")
        fi
    done
fi

# 3. Localiza por linha de comando 'server.py' no diretório do projeto
PY_PIDS=$(pgrep -f "${PROJECT_ROOT}/server.py" 2>/dev/null || true)
for p in ${PY_PIDS}; do
    if kill -0 "${p}" 2>/dev/null; then
        TARGET_PIDS+=("${p}")
    done
done

# Deduplica PIDs
UNIQUE_PIDS=($(printf "%s\n" "${TARGET_PIDS[@]:-}" | sort -u | grep -v '^$' || true))

if [ ${#UNIQUE_PIDS[@]} -eq 0 ]; then
    echo "[*] Nenhum processo ativo da aplicação BACEN GRC foi encontrado na porta ${PORT}."
    exit 0
fi

echo "[*] Encerrando processo(s) da aplicação BACEN GRC (PID(s): ${UNIQUE_PIDS[*]:-})..."
for pid in "${UNIQUE_PIDS[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}" 2>/dev/null || true
    fi
done

# Aguarda até 5 segundos para encerramento gracioso
for i in {1..10}; do
    ALIVE=0
    for pid in "${UNIQUE_PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            ALIVE=1
        fi
    done
    if [ "${ALIVE}" -eq 0 ]; then
        break
    fi
    sleep 0.5
done

# Força SIGKILL se ainda restarem processos
for pid in "${UNIQUE_PIDS[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
        echo "[!] Processo ${pid} não encerrou a tempo. Enviando SIGKILL..."
        kill -9 "${pid}" 2>/dev/null || true
    fi
done

rm -f "${PID_FILE}"
echo "[✓] Aplicação BACEN GRC finalizada com sucesso."
