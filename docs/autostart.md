# Inicialização Automática com o Sistema Operacional Hospedeiro (Linux / Ubuntu)

Este documento detalha a arquitetura e os procedimentos para configurar a inicialização automática da plataforma **BACEN CMN 4.893 & 5.274 GRC Compliance Platform** no sistema operacional hospedeiro.

---

## 1. Visão Geral da Arquitetura

A plataforma foi equipada com um subsistema completo de gerenciamento de ciclo de vida de processo e inicialização automática, suportando quatro modalidades:

| Modalidade | Escopo | Requer Root / Sudo? | Momento de Inicialização |
|---|---|:---:|---|
| **Systemd User Service** *(Recomendado)* | Usuário | **Não** (apenas para *linger*) | No boot da máquina (com *linger*) ou no login |
| **Systemd System Service** | Sistema (`/etc`) | **Sim** (`sudo`) | No boot da máquina (antes do login) |
| **XDG Desktop Autostart** | Interface Gráfica | **Não** | No login da sessão gráfica (LXQt, GNOME, etc.) |
| **Crontab POSIX** | Usuário | **Não** | No boot da máquina (`@reboot`) |

---

## 2. CLI Unificada de Gerenciamento (`./grc.sh`)

Na raiz do repositório, o utilitário executável `grc.sh` fornece acesso a todas as operações:

```bash
# Exibe status detalhado (serviço systemd, processo, porta 8080, HTTP e SQLite)
./grc.sh status

# Inicia a plataforma em segundo plano (daemon)
./grc.sh start

# Executa em primeiro plano (foreground - ideal para depuração)
./grc.sh run

# Encerra graciosamente a aplicação (SIGTERM / SIGKILL)
./grc.sh stop

# Reinicia a aplicação
./grc.sh restart

# Acompanha logs em tempo real (journalctl ou logs/server.log)
./grc.sh logs

# Executa o instalador interativo de inicialização automática
./grc.sh install

# Executa a suíte completa de testes automatizados
./grc.sh test

# Remove as configurações de inicialização automática
./grc.sh uninstall
```

---

## 3. Guia de Instalação Rápida

### Opção A: Systemd User Service (Recomendado - Sem necessidade de root)

Este método instala a *unit* do systemd no diretório do usuário (`~/.config/systemd/user/bacen-grc.service`).

1. **Instale e habilite o serviço:**
   ```bash
   ./scripts/install_service.sh --user --start
   ```
2. **(Opcional, mas recomendado) Habilite execução no boot da máquina sem login:**
   Por padrão no Linux, serviços de usuário rodam enquanto a sessão do usuário estiver ativa. Para permitir que o serviço inicie assim que o computador ligar (mesmo antes de qualquer login):
   ```bash
   sudo loginctl enable-linger gustavo
   ```

### Opção B: Systemd System Service (Servidor de Produção)

Para servidores dedicados onde a aplicação deve operar como um daemon global do sistema:

1. **Execute o instalador com privilégios de administrador:**
   ```bash
   sudo ./scripts/install_service.sh --system --start
   ```
2. O arquivo será provisionado em `/etc/systemd/system/bacen-grc.service`, executando isoladamente sob o usuário `gustavo` com diretivas de hardening (`PrivateTmp=true`, `ProtectSystem=full`, `Restart=always`).

### Opção C: XDG Desktop Autostart (Ambientes Gráficos - LXQt / GNOME)

Para inicializar a aplicação automaticamente sempre que você iniciar a sessão no ambiente desktop:

```bash
./scripts/install_service.sh --desktop
```
O arquivo `.desktop` será gerado em `~/.config/autostart/bacen-grc.desktop`.

### Opção D: Crontab (`@reboot`)

Método universal sem dependência de systemd:

```bash
./scripts/install_service.sh --cron
```

---

## 4. Estrutura de Arquivos

```
bacen-grc-compliance/
├── grc.sh                              # Utilitário CLI principal
├── scripts/
│   ├── start.sh                        # Script de inicialização (com detecção de porta e criação de BD)
│   ├── stop.sh                         # Script de parada segura (SIGTERM/SIGKILL)
│   ├── status.sh                       # Verificador de saúde do sistema
│   ├── install_service.sh              # Instalador multi-modal de autostart
│   ├── uninstall_service.sh            # Desinstalador limpo
│   ├── bacen-grc.service.template      # Template de serviço de sistema
│   ├── bacen-grc-user.service.template # Template de serviço de usuário
│   └── bacen-grc.desktop.template      # Template de autostart para desktop
├── logs/
│   ├── server.log                      # Saída padrão quando executado via start.sh --daemon
│   └── server.pid                      # PID do processo em execução
└── docs/
    └── autostart.md                    # Este documento técnico
```

---

## 5. Monitoramento e Diagnóstico de Logs

### Consultar Logs via `journalctl` (Systemd)
```bash
# Caso esteja rodando como serviço de usuário:
journalctl --user -u bacen-grc.service -f

# Caso esteja rodando como serviço de sistema:
sudo journalctl -u bacen-grc.service -f
```

### Consultar Logs via Arquivo
```bash
tail -f logs/server.log
```

### Teste de Resposta da API
```bash
curl -I http://localhost:8080/
```
Resposta esperada:
```http
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.14.x
Date: ...
Content-Type: text/html; charset=utf-8
```

---

## 6. Desinstalação da Inicialização Automática

Para desativar a inicialização automática e limpar os arquivos criados:

```bash
./grc.sh uninstall
```
Caso tenha instalado a versão de sistema (`/etc/systemd/system/`), execute:
```bash
sudo systemctl disable --now bacen-grc.service
sudo rm -f /etc/systemd/system/bacen-grc.service
sudo systemctl daemon-reload
```
