#!/usr/bin/env bash
# ==============================================================================
# BACEN CMN 4.893 & 5.274 GRC Compliance Platform - Management CLI
# ==============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"

show_help() {
    cat << EOF
Plataforma GRC BACEN CMN 4.893 & 5.274 - Utilitário de Gerenciamento

Uso: $0 [COMANDO]

Comandos disponíveis:
  start       Inicia a aplicação em segundo plano (daemon)
  run         Executa a aplicação no terminal atual (foreground)
  stop        Finaliza a aplicação com encerramento gracioso (SIGTERM)
  restart     Reinicia a aplicação
  status      Exibe o status completo (serviços, processo, porta 8080, HTTP e BD)
  logs        Acompanha os logs em tempo real (journalctl ou logs/server.log)
  install     Instala a inicialização automática com o sistema operacional
  uninstall   Remove a inicialização automática do sistema
  test        Executa a suíte de testes unitários e de integração
  help, -h    Exibe este menu de ajuda
EOF
}

COMMAND="${1:-}"

case "${COMMAND}" in
    start)
        "${SCRIPTS_DIR}/start.sh" --daemon
        ;;
    run)
        "${SCRIPTS_DIR}/start.sh"
        ;;
    stop)
        "${SCRIPTS_DIR}/stop.sh"
        ;;
    restart)
        "${SCRIPTS_DIR}/stop.sh"
        sleep 1
        "${SCRIPTS_DIR}/start.sh" --daemon
        ;;
    status)
        "${SCRIPTS_DIR}/status.sh"
        ;;
    logs)
        if systemctl is-active --quiet bacen-grc.service 2>/dev/null; then
            echo "[*] Exibindo logs do serviço systemd (sistema)..."
            journalctl -u bacen-grc.service -f
        elif systemctl --user is-active --quiet bacen-grc.service 2>/dev/null; then
            echo "[*] Exibindo logs do serviço systemd (usuário)..."
            journalctl --user -u bacen-grc.service -f
        elif [ -f "${PROJECT_ROOT}/logs/server.log" ]; then
            echo "[*] Exibindo logs de ${PROJECT_ROOT}/logs/server.log..."
            tail -f "${PROJECT_ROOT}/logs/server.log"
        else
            echo "[!] Nenhum arquivo de log encontrado em logs/server.log nem serviço ativo no systemd."
        fi
        ;;
    install)
        shift || true
        "${SCRIPTS_DIR}/install_service.sh" "$@"
        ;;
    uninstall)
        "${SCRIPTS_DIR}/uninstall_service.sh"
        ;;
    test)
        echo "[*] Executando suíte de testes de multi-tenancy e Art. 8º..."
        cd "${PROJECT_ROOT}"
        python3 tests/test_multitenancy_and_art8.py
        ;;
    help|-h|--help)
        show_help
        ;;
    "")
        show_help
        ;;
    *)
        echo "[!] Comando desconhecido: ${COMMAND}"
        echo ""
        show_help
        exit 1
        ;;
esac
