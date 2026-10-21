#!/usr/bin/env bash
# ==============================================================================
# BACEN CMN 4.893 & 5.274 GRC Compliance Platform - Service Auto-Start Installer
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="$(which python3 || echo "/usr/bin/python3")"
CURRENT_USER="${SUDO_USER:-$(id -un)}"
CURRENT_GROUP="$(id -gn "${CURRENT_USER}")"

FORCE_START=""
for arg in "$@"; do
    if [ "$arg" == "--start" ] || [ "$arg" == "-y" ] || [ "$arg" == "--yes" ]; then
        FORCE_START="s"
    elif [ "$arg" == "--no-start" ]; then
        FORCE_START="n"
    fi
done

show_help() {
    cat << EOF
Uso: $0 [OPÇÃO] [MODIFICADORES]

Opções de Instalação de Inicialização Automática:
  --user       Instala como serviço systemd no nível de usuário (~/.config/systemd/user/).
               Não necessita de privilégios de root para instalar.
  --system     Instala como daemon systemd de sistema (/etc/systemd/system/).
               Inicia no boot do sistema operacional antes do login (requer sudo).
  --desktop    Instala como entrada XDG Autostart (~/.config/autostart/) para desktop (LXQt/GNOME).
  --cron       Adiciona entrada @reboot no crontab do usuário.
  --all        Configura o serviço systemd de usuário e entrada de autostart desktop.
  --help, -h   Exibe esta mensagem de ajuda.

Modificadores:
  --start, -y  Inicia o serviço imediatamente após instalação sem perguntar.
  --no-start   Não inicia o serviço imediatamente após instalação.

Se executado sem argumentos, um menu interativo será exibido.
EOF
}

install_systemd_user() {
    echo "============================================================"
    echo "  [1/3] Configurando Systemd User Service"
    echo "============================================================"
    local USER_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${USER_DIR}"

    local SERVICE_DEST="${USER_DIR}/bacen-grc.service"
    sed -e "s|{{PROJECT_ROOT}}|${PROJECT_ROOT}|g" \
        -e "s|{{PYTHON_BIN}}|${PYTHON_BIN}|g" \
        "${SCRIPT_DIR}/bacen-grc-user.service.template" > "${SERVICE_DEST}"

    chmod 644 "${SERVICE_DEST}"
    echo "[✓] Arquivo de serviço gerado em: ${SERVICE_DEST}"

    systemctl --user daemon-reload
    systemctl --user enable bacen-grc.service
    echo "[✓] Serviço systemd de usuário habilitado para inicialização automática!"

    # Dica de linger para boot sem login
    echo ""
    echo "[ℹ] NOTA SOBRE INICIALIZAÇÃO NO BOOT:"
    echo "    Para que serviços de usuário iniciem no boot da máquina antes mesmo"
    echo "    de realizar login, execute uma única vez no terminal:"
    echo "    $ sudo loginctl enable-linger ${CURRENT_USER}"
    echo ""

    local start_now="${FORCE_START:-}"
    if [ -z "${start_now}" ] && [ -t 0 ]; then
        read -r -p "Deseja iniciar o serviço imediatamente agora? (s/N): " start_now || start_now="n"
    fi
    if [[ "${start_now}" =~ ^[sSyY]$ ]]; then
        # Para processo manual caso exista para não conflitar na porta 8080
        "${SCRIPT_DIR}/stop.sh" >/dev/null 2>&1 || true
        systemctl --user restart bacen-grc.service
        sleep 1
        systemctl --user status bacen-grc.service --no-pager -l | head -n 10
    fi
}

install_systemd_system() {
    echo "============================================================"
    echo "  Configurando Systemd System Daemon (/etc/systemd/system)"
    echo "============================================================"
    local SERVICE_DEST="/etc/systemd/system/bacen-grc.service"
    local TMP_SERVICE="/tmp/bacen-grc.service.$$"

    sed -e "s|{{PROJECT_ROOT}}|${PROJECT_ROOT}|g" \
        -e "s|{{PYTHON_BIN}}|${PYTHON_BIN}|g" \
        -e "s|{{USER}}|${CURRENT_USER}|g" \
        -e "s|{{GROUP}}|${CURRENT_GROUP}|g" \
        "${SCRIPT_DIR}/bacen-grc.service.template" > "${TMP_SERVICE}"

    echo "[*] Instalando arquivo de serviço no sistema (pode solicitar senha sudo)..."
    if [ "$(id -u)" -eq 0 ]; then
        cp "${TMP_SERVICE}" "${SERVICE_DEST}"
        chmod 644 "${SERVICE_DEST}"
        systemctl daemon-reload
        systemctl enable bacen-grc.service
    else
        sudo cp "${TMP_SERVICE}" "${SERVICE_DEST}"
        sudo chmod 644 "${SERVICE_DEST}"
        sudo systemctl daemon-reload
        sudo systemctl enable bacen-grc.service
    fi
    rm -f "${TMP_SERVICE}"

    echo "[✓] Serviço de sistema /etc/systemd/system/bacen-grc.service habilitado no boot da máquina!"

    local start_now="${FORCE_START:-}"
    if [ -z "${start_now}" ] && [ -t 0 ]; then
        read -r -p "Deseja iniciar o serviço imediatamente agora? (s/N): " start_now || start_now="n"
    fi
    if [[ "${start_now}" =~ ^[sSyY]$ ]]; then
        "${SCRIPT_DIR}/stop.sh" >/dev/null 2>&1 || true
        if [ "$(id -u)" -eq 0 ]; then
            systemctl restart bacen-grc.service
            systemctl status bacen-grc.service --no-pager -l | head -n 10
        else
            sudo systemctl restart bacen-grc.service
            sudo systemctl status bacen-grc.service --no-pager -l | head -n 10
        fi
    fi
}

install_desktop_autostart() {
    echo "============================================================"
    echo "  Configurando XDG Desktop Autostart (~/.config/autostart)"
    echo "============================================================"
    local AUTOSTART_DIR="${HOME}/.config/autostart"
    mkdir -p "${AUTOSTART_DIR}"

    local DESKTOP_DEST="${AUTOSTART_DIR}/bacen-grc.desktop"
    sed -e "s|{{PROJECT_ROOT}}|${PROJECT_ROOT}|g" \
        "${SCRIPT_DIR}/bacen-grc.desktop.template" > "${DESKTOP_DEST}"

    chmod +x "${DESKTOP_DEST}"
    echo "[✓] Entrada de inicialização criada em: ${DESKTOP_DEST}"
    echo "    A aplicação iniciará automaticamente a cada login na interface gráfica."
}

install_crontab() {
    echo "============================================================"
    echo "  Configurando Autostart via Crontab (@reboot)"
    echo "============================================================"
    local CRON_CMD="@reboot ${PROJECT_ROOT}/scripts/start.sh --daemon >/dev/null 2>&1"
    local CURRENT_CRON
    CURRENT_CRON="$(crontab -l 2>/dev/null || true)"

    if echo "${CURRENT_CRON}" | grep -q "bacen-grc-compliance/scripts/start.sh"; then
        echo "[*] Entrada no crontab já existente."
    else
        (echo "${CURRENT_CRON}"; echo "${CRON_CMD}") | crontab -
        echo "[✓] Linha adicionada com sucesso ao crontab:"
        echo "    ${CRON_CMD}"
    fi
}

# Processamento de argumentos
ACTION="${1:-}"

case "${ACTION}" in
    --user)
        install_systemd_user
        ;;
    --system)
        install_systemd_system
        ;;
    --desktop)
        install_desktop_autostart
        ;;
    --cron)
        install_crontab
        ;;
    --all)
        install_systemd_user
        install_desktop_autostart
        ;;
    --help|-h)
        show_help
        exit 0
        ;;
    "")
        echo "============================================================"
        echo "  Configurador de Inicialização Automática - BACEN GRC"
        echo "============================================================"
        echo "Selecione o método de inicialização com o sistema operacional:"
        echo "  1) Systemd User Service (Recomendado - não exige root)"
        echo "  2) Systemd System Service (Inicialização no boot do kernel - requer sudo)"
        echo "  3) XDG Desktop Autostart (Ambiente gráfico LXQt/GNOME no login)"
        echo "  4) Crontab (@reboot)"
        echo "  5) Configuração Completa (User Service + Desktop Autostart)"
        echo "  q) Sair"
        echo ""
        read -r -p "Escolha uma opção [1-5]: " choice
        case "${choice}" in
            1) install_systemd_user ;;
            2) install_systemd_system ;;
            3) install_desktop_autostart ;;
            4) install_crontab ;;
            5) install_systemd_user; install_desktop_autostart ;;
            *) echo "Operação cancelada."; exit 0 ;;
        esac
        ;;
    *)
        echo "[!] Opção desconhecida: ${ACTION}"
        show_help
        exit 1
        ;;
esac

echo ""
echo "============================================================"
echo "  Configuração concluída com sucesso!"
echo "  Para verificar o status: ${SCRIPT_DIR}/status.sh"
echo "  Para gerenciar a plataforma: ${PROJECT_ROOT}/grc.sh"
echo "============================================================"
