# BACEN GRC Compliance | Resoluções CMN nº 4.893/2021 & CMN nº 5.274/2025

[![Python 3](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![BACEN CMN 4.893](https://img.shields.io/badge/Regulamentação-CMN%204.893%2F2021-0284c7.svg)](https://www.bcb.gov.br/)
[![BACEN CMN 5.274](https://img.shields.io/badge/Atualização-CMN%205.274%2F2025-059669.svg)](https://www.bcb.gov.br/)
[![Zero Dependencies](https://img.shields.io/badge/Dependências-Zero%20(Pure%20Python)-brightgreen.svg)]()
[![License MIT](https://img.shields.io/badge/License-MIT-amber.svg)](LICENSE)

Sistema Web Corporativo de Governança, Riscos e Conformidade (**GRC**) desenvolvido para instituições financeiras autorizadas a funcionar pelo **Banco Central do Brasil (BACEN)**. O software automatiza a gestão de compliance, a parametrização institucional, a execução do **Plano de Ação e de Resposta a Incidentes (PARI)**, a custódia pericial de evidências com **hash SHA-256**, a avaliação de fornecedores de nuvem e a emissão do **Relatório Anual do Diretor Estatutário (Art. 8º)**.

---

## 🏛️ 1. Contexto e Análise Regulatória

O Sistema Financeiro Nacional (SFN) é submetido a um dos arcabouços de cibersegurança mais rigorosos do mundo:

* **Resolução CMN nº 4.893, de 26 de fevereiro de 2021:**
  Estabelece as diretrizes para a implementação da Política de Segurança Cibernética, requisitos de governança executiva, plano de resposta a incidentes e as regras estritas para contratação de processamento, armazenamento de dados e computação em nuvem (no Brasil e no exterior).
* **Resolução CMN nº 5.274, de 18 de dezembro de 2025:**
  Atualizou substancialmente a Resolução 4.893/2021, transformando orientações gerais em **14 controles técnicos mínimos obrigatórios e auditáveis** no Artigo 3º, com prazo mandatório de adequação fixado até **1º de março de 2026**.
* **Resolução BCB nº 538, de 18 de dezembro de 2025:**
  Norma espelho do Banco Central que alterou a Resolução BCB nº 85/2021, aplicando os mesmos 14 controles mandatórios para instituições de pagamento (IPs), corretoras e distribuidoras de valores mobiliários.
* **Proporcionalidade (Resolução CMN nº 4.553/2017):**
  A aplicação dos controles é calibrada de acordo com o segmento da instituição (**S1 a S5**), considerando porte, complexidade e perfil de risco de exposição a incidentes.

---

## 🛡️ 2. Os 14 Controles Mínimos da Resolução CMN nº 5.274/2025

O sistema monitora e audita individualmente cada um dos 14 novos controles mandatórios introduzidos no Art. 3º, § 2º:

1. **Autenticação Robusta (MFA):** Múltiplos fatores obrigatórios para acessos privilegiados, sistemas críticos, RSFN e canais externos.
2. **Criptografia Avançada:** Criptografia em repouso (AES-256) e em trânsito (TLS 1.3), proibição de cifras obsoletas e custódia de chaves em HSM/KMS.
3. **Prevenção e Detecção de Intrusão:** Sistemas de IDS/IPS e agentes EDR/XDR em 100% dos ativos com telemetria 24x7 no SOC.
4. **Prevenção de Vazamento de Dados (DLP):** Inspeção e bloqueio de exfiltração em e-mails, endpoints (USB, clipboard), nuvem e repositórios.
5. **Proteção contra Softwares Maliciosos:** Antimalware com análise heurística/comportamental, sandbox de anexos e quarentena automatizada.
6. **Rastreabilidade e Trilhas de Auditoria (Logs):** Logs centralizados em SIEM, sincronizados com relógio do Observatório Nacional (NTP stratum 1/2), integridade imutável (WORM/SHA-256) e retenção mínima de 5 anos.
7. **Gestão de Backups e Testes de Restauração:** Padrão 3-2-1, repositórios com retenção imutável (Object Lock) e testes semestrais com validação formal de RTO e RPO.
8. **Avaliação e Correção Contínua de Vulnerabilidades:** Scans periódicos de vulnerabilidade e SLA contratual de correção por severidade (Crítica ≤ 7 dias).
9. **Perfis de Configuração Segura (Hardening):** Adoção de baselines internacionais (CIS Benchmarks ou NIST) e Golden Images auditadas.
10. **Proteção de Redes e Segregação:** Firewalls NGFW, microssegmentação, DMZ e isolamento estrito entre ambientes de Dev, Homologação e Produção.
11. **Gestão do Ciclo de Vida de Certificados Digitais:** Automação de emissão, renovação, inventário, proteção de chaves privadas em HSM e verificação CRL/OCSP.
12. **Ações de Inteligência no Ambiente Cibernético (Threat Intel):** Monitoramento contínuo da internet aberta, Deep Web, Dark Web e canais de mensageria para identificação de credenciais vazadas e planos de ataque.
13. **Segurança na Comunicação na RSFN / PIX / Open Finance:** Conexão homologada com o Banco Central, autenticação mTLS e certificados ICP-Brasil específicos (SPB/PIX).
14. **Segurança em APIs e DevSecOps:** Testes estáticos (SAST) e dinâmicos (DAST) em pipelines CI/CD, rate limiting e perfil de segurança FAPI / OAuth 2.0.

---

### 3.1. Controle de Acesso Baseado em Papéis (RBAC) & Menor Privilégio
O sistema implementa autenticação segura com **PBKDF2-SHA256 (100.000 iterações)**, sessões temporizadas criptográficas e **MFA Mandatório (RFC 6238 TOTP de 6 dígitos)** em consonância com o Controle Mandatório nº 01 da Resolução CMN nº 5.274:

* 👑 **Administrador Geral (`admin_geral`):**
  Acesso irrestrito a todas as instituições financeiras cadastradas. Possui painel exclusivo de **Gestão Centralizada de Usuários (`/api/usuarios`)**, capacidade de alocar perfis institucionais e cadastrar novas empresas avaliadas.
* 🛡️ **Gestor de Compliance / CISO (`gestor`):**
  Gestão total da instituição vinculada. Aprovação de avaliações, edição de dados cadastrais da empresa e Unicad, governança executiva do CSIRT/PARI, gestão de fornecedores de nuvem (Art. 17) e emissão do Relatório Anual (Art. 8º).
* ⚙️ **Analista de Segurança / Operador GRC (`analista`):**
  Operação de conformidade da instituição alocada. Execução e pontuação de avaliações, upload de evidências no cofre, elaboração de planos de ação 5W2H e cadastro de simulados. Bloqueado para edição cadastral da empresa e exclusão de evidências.
* 🔍 **Auditor Interno / Fiscal BACEN (`auditor`):**
  Perfil estritamente **somente leitura (*read-only*)**. Permite inspeção regulatória de conformidade, consulta à integridade probatória de evidências (hashes SHA-256) e exportação de relatórios, sem qualquer privilégio de gravação ou alteração.

#### 🔑 Credenciais Padrão para Demonstração e Homologação
| Perfil | E-mail Institucional | Senha Padrão | Segredo MFA (Base32) |
|:---|:---|:---|:---|
| **👑 Admin Geral** | `admin@bacen.local` | `Admin@Bacen2026!` | `JBSWY3DPEHPK3PXP` |
| **🛡️ Gestor CISO** | `gestor@alphabank.com.br` | `Gestor@2026!` | `JBSWY3DPEHPK3PXQ` |
| **⚙️ Analista GRC** | `analista@alphabank.com.br` | `Analista@2026!` | `JBSWY3DPEHPK3PXR` |
| **🔍 Auditor BACEN** | `auditor@bacen.gov.br` | `Auditor@2026!` | `JBSWY3DPEHPK3PXS` |

> [!TIP]
> A tela de login disponibiliza botões de clique rápido com as credenciais pré-configuradas e assistente de preenchimento do código TOTP gerado em tempo real pelo servidor para validação instantânea sem atrito.

### 3.2. Cadastro da Empresa a ser Avaliada (Multi-Instituição Granular)
* **Sem dados fixos ou pressupostos:** Permite cadastrar a Razão Social, Nome Fantasia, CNPJ e o nome real do **Diretor Estatutário perante o BACEN**.
* **Enquadramento no SFN:** Segmentos S1 a S5 com explicação da regra de proporcionalidade (Resolução CMN nº 4.553).
* **Homologação Unicad:** Registro oficial do Diretor perante o BACEN, cargo, e-mail institucional e contatos.
* **Governança:** Data de aprovação da política pelo Conselho de Administração (Art. 9º), data da última revisão anual (Art. 10) e escopo de atuação.
* **Gestão Multi-Empresa:** Permite cadastrar e alternar entre diferentes instituições financeiras avaliadas de acordo com as permissões do usuário logado.

### 3.3. Dashboard Executivo & KPIs
* **Score Global de Compliance:** Percentual ponderado de aderência aos requisitos regulatórios em tempo real.
* **Contadores por Status:** Atendidos, Parcialmente Atendidos, Em Implementação, Não Atendidos e Não Aplicáveis.
* **Painel Especial Resolução 5.274:** Painel interativo com status e pontuação dos 14 controles técnicos.
* **Maturidade por Domínio:** Gráficos de barras por domínio da norma e indicadores de prontidão do PARI.

### 3.4. Matriz de Compliance GRC
* Visão tabular com os 32 requisitos normativos organizados pelos 7 domínios da norma.
* Filtros dinâmicos por Domínio, Status, Severidade, busca por palavra-chave e filtro rápido para os 14 controles da 5.274.
* **Modal de Auditoria:** Edição interativa do status de conformidade, barra deslizante de aderência (0-100%), justificativa técnica da instituição, prazo de adequação e parecer do auditor.

### 3.5. Módulo Dedicado: Plano de Ação e Resposta a Incidentes (PARI)
Estruturado com base nos **Arts. 6º e 8º da Resolução CMN 4.893/2021**:
* **Governança do CSIRT & Plantão 24x7:** Líder do CSIRT, e-mail, telefone de plantão, membros técnicos multidisciplinares, comitê de crise executivo e canais de comunicação de emergência fora da rede (*out-of-band*).
* **Playbooks Operacionais por Ameaça:** Procedimentos em 5 fases (Detecção, Contenção Imediata, Erradicação, Recuperação e Comunicação ao BACEN) para:
  * *Ataque de Ransomware e Sequestro de Ativos*
  * *Vazamento de Dados Pessoais e Sigilo Bancário (LGPD)*
  * *Ataque DDoS no PIX e Internet Banking*
  * *Indisponibilidade de Nuvem Crítica (DR & Failover)*
  * *Falha de Conectividade na RSFN / SPB*
* **Fluxo e Critérios do SISBACEN:** Critérios objetivos para caracterização de incidente como "Relevante" (indisponibilidade > 2h de serviços essenciais, violação de sigilo bancário em escala) e procedimento de notificação tempestiva no módulo de Risco Operacional do BACEN.
* **Exercícios e Simulados de Mesa (Tabletop Drills):** Registro de simulações periódicas com a Diretoria Executiva, tempo de resposta alcançado (RTO), pontos fortes e ações de melhoria.
* **Registro de Incidentes Reais:** Histórico de eventos de segurança tratados.

### 3.6. Cofre de Evidências Regulatórias (Evidence Vault)
* Upload e vínculo direto de evidências técnicas com os requisitos normativos.
* **Geração Automática de Hash SHA-256:** Garantia de integridade para fins de fiscalização e auditoria externa.
* Classificação por tipo (Políticas, Relatórios de Pentest, Logs de Auditoria, Atas de Reunião, Contratos Cloud).
* Download direto e verificação do status de validação.

### 3.7. Gestão de Contratação de Nuvem (Arts. 11 a 17)
* Cadastro de provedores relevantes de nuvem (AWS, Microsoft Azure, Salesforce, etc.).
* Checklist de aderência às cláusulas obrigatórias do Art. 17:
  * Indicação formal dos países de armazenamento e processamento;
  * Acesso irrestrito do Banco Central e auditores;
  * Segregação lógica de informações de clientes;
  * Notificação prévia ao BACEN com 60 dias de antecedência (Art. 15);
  * Plano de descontinuidade e reversibilidade tecnológica (Art. 20).

### 3.8. Planos de Ação 5W2H
* Mapeamento estruturado para remediação de gaps identificados (O quê, Por quê, Onde, Quem, Quando, Como, Quanto).
* Monitoramento visual de progresso percentual e status de implementação.

### 3.9. Relatório Anual Oficial do Artigo 8º
* Geração do documento oficial anual exigido com data-base em **31 de dezembro**.
* Apresenta o parecer executivo, avaliação dos 14 controles da 5.274, histórico do PARI, testes de invasão e a declaração formal com assinatura do **Diretor Estatutário**.
* Otimizado para impressão direta e exportação em PDF (`window.print()`).

### 3.10. Trilha de Auditoria (Audit Log)
* Registro imutável de todas as ações executadas no sistema (criação de evidências, alterações de status, revisões cadastrais) com data, hora e usuário responsável.

---

## 🚀 4. Guia de Instalação e Execução

### Pré-requisitos
* **Python 3.10 ou superior** (Testado e validado em Linux, Windows e macOS).
* **Nenhum pacote pip externo necessário** (utiliza 100% biblioteca padrão: `http.server`, `sqlite3`, `json`, `hashlib`, `urllib`).

### Passos para Execução Rápida

1. Clone o repositório:
```bash
git clone https://github.com/gustavohsr/bacen-grc-compliance.git
cd bacen-grc-compliance
```

2. Inicialize o banco de dados e a carga inicial dos requisitos normativos:
```bash
python3 db_init.py
python3 seed_data.py
```

3. Inicie a aplicação via CLI unificada:
```bash
# Execução direta no terminal:
./grc.sh run

# Ou execução em segundo plano (daemon):
./grc.sh start
```

4. Abra seu navegador web e acesse:
```
http://localhost:8080
```

### ⚡ Inicialização Automática com o Sistema Operacional Hospedeiro (Linux / Ubuntu)

Para que a aplicação inicialize automaticamente junto com o sistema operacional (systemd / desktop autostart), utilize o instalador integrado:

```bash
# Opção 1: Serviço Systemd de Usuário (Recomendado - não requer sudo):
./grc.sh install --user --start

# Para habilitar o boot da máquina antes mesmo do login do usuário:
sudo loginctl enable-linger $USER

# Opção 2: Serviço Systemd de Sistema (Para servidores dedicados):
sudo ./grc.sh install --system --start

# Opção 3: Inicialização no Login da Interface Gráfica (LXQt / GNOME):
./grc.sh install --desktop
```

Consulte a documentação completa de inicialização em [`docs/autostart.md`](docs/autostart.md).

---

## 📡 5. Referência dos Endpoints da REST API

| Método | Rota | Descrição |
|:---|:---|:---|
| `GET` | `/api/dashboard` | Retorna os KPIs consolidados, aderência geral e status dos 14 controles |
| `GET` | `/api/instituicoes` | Lista todas as empresas cadastradas |
| `GET` | `/api/instituicao/ativa` | Retorna a instituição atualmente em avaliação |
| `POST` | `/api/instituicoes` | Cadastra nova instituição financeira |
| `PUT` | `/api/instituicao` | Atualiza os dados cadastrais da instituição ativa |
| `POST` | `/api/instituicao/{id}/ativar` | Alterna a instituição ativa para avaliação |
| `GET` | `/api/requisitos` / `/api/avaliacoes` | Lista requisitos regulatórios com filtros e avaliações por tenant |
| `PUT` | `/api/avaliacoes/{req_id}` | Atualiza o status e justificativa de conformidade |
| `GET` | `/api/evidencias` | Lista evidências regulatórias vinculadas à empresa ativa |
| `POST` | `/api/evidencias` | Registra evidência com amarração de requisito e geração de hash SHA-256 |
| `DELETE` | `/api/evidencias/{id}` | Exclui evidência do cofre |
| `GET` | `/api/pari` | Retorna o dossiê completo do PARI da instituição (CSIRT, Playbooks, Simulados) |
| `PUT` | `/api/pari/governanca` | Atualiza governança do CSIRT e critérios SISBACEN |
| `POST` | `/api/pari/playbooks` | Cadastra novo playbook operacional de resposta |
| `POST` | `/api/pari/simulados` | Registra simulação de crise / tabletop drill |
| `GET` | `/api/auditorias_fragilidades` | Lista apontamentos de Pentests e vulnerabilidades do tenant |
| `POST` | `/api/auditorias_fragilidades` | Registra vulnerabilidade e plano de remediação |
| `GET` | `/api/relatorio_anual` | Dossiê consolidado com as 8 seções mandatórias do Art. 8º da Res. CMN 4.893 |
| `POST` | `/api/relatorio_anual/parecer` | Assinatura eletrônica e parecer conclusivo do Diretor Estatutário |
| `GET` | `/api/relatorio_anual/export/json` | Exportação oficial em JSON com hash SHA-256 de integridade |
| `GET` | `/api/export/csv` | Exporta a matriz de compliance para CSV (Excel) |
| `GET` | `/api/export/json` | Exporta a base completa em JSON |

---

## 🧪 6. Testes Automatizados de Isolamento Multi-tenant e Art. 8º

A suíte de testes de integração valida de ponta a ponta:
- Autenticação com PBKDF2-SHA256 e MFA TOTP (RFC 6238) para todos os perfis RBAC.
- Segregação estrita de dados e consultas via cabeçalho `X-Company-ID`.
- Princípio do Menor Privilégio (usuários sem autorização explícita para o tenant recebem `403 Forbidden`).
- Vinculação íntegra de evidências à empresa e ao requisito regulatório (ex: Controle 11/14 da Res. 5.274).
- Métrica de incidentes (MTTD e MTTR) e trilha de auditoria isolada.
- Emissão oficial do Relatório Anual (Art. 8º) com todas as 8 seções e assinatura eletrônica com hash SHA-256.

Para rodar os testes:
```bash
python3 -m unittest tests/test_multitenancy_and_art8.py -v
```

---

## 📂 7. Estrutura do Repositório

```
bacen-grc-compliance/
├── grc.sh                              # Utilitário CLI de ciclo de vida (start, stop, status, test, install)
├── auth.py                             # Motor de Autenticação PBKDF2, RBAC e MFA TOTP (RFC 6238)
├── data/
│   └── compliance.db                   # Banco de dados relacional SQLite multi-tenant
├── docs/
│   ├── ARQUITETURA_E_CONFORMIDADE.md   # Arquitetura técnica e DER
│   ├── MATRIZ_REQUISITOS_BACEN_4893_5274.md # Mapeamento legal exaustivo
│   └── autostart.md                    # Guia de inicialização automática no host (systemd/desktop)
├── logs/
│   ├── server.log                      # Registro de logs operacionais
│   └── server.pid                      # PID do processo em background
├── scripts/
│   ├── start.sh                        # Inicialização resiliente (verificação de porta e DB)
│   ├── stop.sh                         # Encerramento seguro com SIGTERM/SIGKILL
│   ├── status.sh                       # Diagnóstico instantâneo de saúde e integridade
│   ├── install_service.sh              # Instalador multi-modal (systemd user/system, desktop, cron)
│   ├── uninstall_service.sh            # Desinstalador limpo de autostart
│   ├── bacen-grc.service.template      # Template systemd de sistema
│   ├── bacen-grc-user.service.template # Template systemd de usuário
│   └── bacen-grc.desktop.template      # Template XDG autostart de desktop
├── static/
│   └── index.html                      # Interface SPA com CompanyContextSelector e Relatório Art. 8º
├── tests/
│   └── test_multitenancy_and_art8.py   # Suíte de integração (Multi-tenancy e Art. 8º)
├── uploads/
│   └── .gitkeep                        # Diretório para armazenamento de evidências
├── .gitignore                          # Configurações de exclusão do git
├── db_init.py                          # DDL e criação do esquema de banco de dados
├── LICENSE                             # Licença MIT
├── README.md                           # Documentação técnica e regulatória principal
├── seed_data.py                        # Carga inicial multi-tenant (Alpha Bank S3 e Torra SCD S4)
└── server.py                           # Servidor HTTP e REST API em Python nativo
```

---

## 📜 8. Licença

Este projeto é distribuído sob a licença **MIT**. Consulte o arquivo [LICENSE](LICENSE) para mais informações.

Desenvolvido por **[gustavohsr](https://github.com/gustavohsr)**.
