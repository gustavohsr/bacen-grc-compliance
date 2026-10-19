# Matriz Regulatória: Resolução CMN nº 4.893/2021 & CMN nº 5.274/2025

Este documento consolida o mapeamento analítico e técnico de todos os requisitos regulamentares exigidos pelo Banco Central do Brasil (BACEN) e Conselho Monetário Nacional (CMN) para a Política de Segurança Cibernética e Contratação de Serviços de Processamento, Armazenamento de Dados e Computação em Nuvem pelas instituições financeiras do Sistema Financeiro Nacional (SFN).

---

## 1. Visão Geral da Legislação Aplicável

* **Resolução CMN nº 4.893/2021:** Dispõe sobre a política de segurança cibernética e sobre os requisitos para a contratação de serviços de processamento e armazenamento de dados e de computação em nuvem a serem observados pelas instituições autorizadas a funcionar pelo Banco Central do Brasil.
* **Resolução CMN nº 5.274/2025 (Publicada em 18/12/2025):** Altera diretamente a Resolução CMN nº 4.893/2021, tornando prescritivos e compulsórios **14 controles técnicos mínimos auditáveis** no Artigo 3º, com prazo improrrogável de adequação até **1º de março de 2026**.
* **Resolução BCB nº 538/2025:** Norma correlata do Banco Central do Brasil aplicando os mesmos requisitos técnicos a instituições de pagamento, corretoras e distribuidoras de títulos e valores mobiliários (alterando a Resolução BCB nº 85/2021).
* **Resolução CMN nº 4.553/2017:** Estabelece o enquadramento por segmentos (**S1 a S5**) para aplicação proporcional da regulação prudencial e de gerenciamento de riscos.

---

## 2. Os 14 Controles Mínimos Mandatórios da Resolução CMN nº 5.274/2025

Inseridos no **Art. 3º, § 2º** da Resolução CMN nº 4.893/2021:

| Nº | Controle | Requisito Legal & Técnico | Evidências Mínimas em Auditoria |
|:---|:---------|:--------------------------|:--------------------------------|
| **01** | **Autenticação Robusta (MFA)** | Implementação compulsória de múltiplos fatores independentes de autenticação (MFA) para todas as contas de acesso privilegiado, conexões externas, canais de clientes e interfaces com a RSFN. Mitigação contra fadiga de MFA e força bruta. | Relatórios de configuração IAM (Identity & Access Management), logs de autenticação MFA (FIDO2, TOTP), inventário de contas administrativas. |
| **02** | **Criptografia Avançada** | Adoção de criptografia forte tanto para dados em repouso (volumes de storage, instâncias de banco de dados e backups) quanto para dados em trânsito (redes internas, RSFN e internet). Algoritmos modernos (AES-256, TLS 1.3) e custódia segura de chaves em HSM/KMS. | Certificados de conformidade TLS, inventário de chaves em HSM/KMS, comprovantes de Transparent Data Encryption (TDE). |
| **03** | **Prevenção e Detecção de Intrusão** | Mecanismos contínuos de IDS/IPS e agentes de EDR/XDR cobrindo 100% dos servidores e estações de trabalho corporativas, com telemetria e monitoramento ativo 24x7 pelo Security Operations Center (SOC). | Telas e relatórios de agentes EDR ativos, alertas do SIEM investigados e tratados, regras de firewall e IPS vigentes. |
| **04** | **Prevenção de Vazamento de Dados (DLP)** | Controles para prevenir, identificar e bloquear a exfiltração de dados sensíveis de clientes e segredo bancário em e-mails, endpoints (USB, clipboard, impressoras), nuvem pública e repositórios de código. | Regras ativas na solução de Data Loss Prevention, relatórios de bloqueio de incidentes de exfiltração, matriz de classificação da informação. |
| **05** | **Proteção contra Malwares** | Soluções avançadas de antimalware com inteligência heurística e análise comportamental, proteção em tempo real contra ransomwares, sandbox de anexos e quarentena automatizada. | Relatórios de atualização das bases de assinaturas em tempo real, evidência de cobertura de 100% dos ativos de TI inventariados. |
| **06** | **Rastreabilidade e Trilhas de Auditoria (Logs)** | Centralização de logs de auditoria em SIEM, sincronização temporal compulsória com relógio do Observatório Nacional (NTP stratum 1/2), integridade imutável (WORM/hash SHA-256) e retenção mínima de 5 anos. | Laudo de sincronismo NTP oficial, arquitetura de retenção de logs com carimbo de tempo inviolável, políticas de guarda e descarte seguro. |
| **07** | **Gestão e Testes de Cópias de Segurança (Backups)** | Cópias de segurança regulares seguindo o padrão 3-2-1, armazenamento em locais geograficamente segregados com proteção contra deleção ou criptografia por ransomware (Object Lock) e testes semestrais de restore. | Relatórios técnicos e atas de execução de testes de restauração em produção com métricas validadas de RPO (Recovery Point Objective) e RTO (Recovery Time Objective). |
| **08** | **Avaliação e Correção Contínua de Vulnerabilidades** | Processo contínuo e estruturado de identificação, priorização por risco e remediação tempestiva de vulnerabilidades em sistemas operacionais, aplicações e infraestrutura, com SLA formal de correção (ex: Crítica ≤ 7 dias). | Relatórios de varreduras técnicas periódicas de vulnerabilidade (scans internos e externos), tickets Jira de remediação concluídos dentro do SLA. |
| **09** | **Perfis de Configuração Segura (Hardening)** | Definição, aplicação e auditoria de perfis de configuração segura (hardening) baseados em baselines internacionais reconhecidos (CIS Benchmarks ou NIST) para sistemas operacionais, contêineres, bancos de dados e redes. | Documento formal de diretrizes de hardening, relatórios de auditoria automatizada de conformidade de configuração, Golden Images validadas. |
| **10** | **Proteção de Redes e Segregação de Ambientes** | Firewalls de nova geração (NGFW), microssegmentação de rede, zonas desmilitarizadas (DMZ) e estrita segregação lógica e física entre ambientes de Desenvolvimento/Homologação e Produção. Web Application Firewall (WAF) ativo. | Topologia de rede lógica e física atualizada e assinada, matriz de regras de firewall revisada semestralmente, configurações de WAF em produção. |
| **11** | **Gestão do Ciclo de Vida de Certificados Digitais** | Inventário centralizado e automatizado de certificados digitais (SSL/TLS, SPB, mTLS), monitoramento de vencimento, guarda inviolável de chaves privadas em módulos de segurança (HSM) e checagem de revogação CRL/OCSP. | Inventário de certificados digitais em uso, alertas proativos de expiração configurados, laudo de armazenamento de chaves privadas em HSM. |
| **12** | **Ações de Inteligência no Ambiente Cibernético (Threat Intel)** | Monitoramento proativo da internet aberta, Deep Web, Dark Web e grupos de mensageria privados visando identificar vazamentos de credenciais, menções de marca, criação de domínios maliciosos (typosquatting) e planos de ataque. | Contrato de prestação de serviços de Cyber Threat Intelligence, relatórios executivos de inteligência recebidos, ações de takedown comprovadas. |
| **13** | **Segurança na RSFN / PIX / Open Finance** | Requisitos adicionais e salvaguardas rigorosas para tráfego eletrônico de dados na Rede do Sistema Financeiro Nacional (RSFN), com autenticação mTLS bidirecional, certificados digitais ICP-Brasil SPB e redundância física. | Certidão de homologação de conectividade emitida pelo Banco Central, arquitetura de mensageria PIX e Open Finance auditada e sem apontamentos. |
| **14** | **Segurança em APIs e Ciclo de Desenvolvimento Seguro (DevSecOps)** | Controles de segurança integrados ao pipeline CI/CD (testes SAST, DAST e SCA), autenticação OAuth 2.0 / FAPI para APIs abertas, limitação de taxa (rate limiting) e validação estrita de esquemas de dados. | Relatórios de gates de segurança na esteira CI/CD, testes SAST/DAST executados antes de cada release, políticas ativas no API Gateway. |

---

## 3. Matriz dos Capítulos e Artigos da Resolução CMN nº 4.893/2021

### Capítulo I — Objeto e Âmbito de Aplicação (Art. 1º)
* Aplica-se às instituições autorizadas a funcionar pelo Banco Central do Brasil.
* Exclui administradoras de consórcio e instituições de pagamento que observam norma correlata do BCB (Resolução BCB nº 85/2021 e nº 538/2025).

### Capítulo II — Política de Segurança Cibernética (Arts. 2º a 10)
* **Art. 2º:** Implementação e manutenção de política compatível com o modelo de negócio e proporcionalidade do segmento SFN.
* **Art. 3º:** Objetivos e os 14 controles técnicos mandatórios (alterado pela Resolução 5.274/2025).
* **Art. 4º e 5º:** Divulgação interna em linguagem acessível e resumo executivo público divulgado na internet.
* **Art. 6º:** Plano de Ação e de Resposta a Incidentes (PARI), playbooks de crise, comunicação ao BACEN via Sisbacen e compartilhamento com o mercado.
* **Art. 7º:** Designação formal de Diretor Estatutário perante o BACEN homologado no Unicad.
* **Art. 8º:** Relatório Anual sobre a Efetividade do Plano (Data-base 31/12), submetido à Diretoria e Conselho até 31 de março.
* **Art. 9º e 10:** Alçada decisória do Conselho de Administração e revisão periódica mínima anual.

### Capítulo III — Contratação de Serviços de Nuvem e Processamento (Arts. 11 a 20)
* **Arts. 11 e 12:** Due diligence prévia de segurança, solvência e conformidade regulatória do prestador de serviços.
* **Art. 13:** Abrangência da computação em nuvem (IaaS, PaaS, SaaS).
* **Art. 14:** Responsabilidade integral e intransferível da instituição financeira contratante.
* **Art. 15:** Comunicação formal prévia ao Banco Central com **no mínimo 60 dias de antecedência**.
* **Art. 16:** Prestação de serviços no exterior condicionada a convênio de cooperação entre o BACEN e autoridade supervisora estrangeira.
* **Art. 17:** Cláusulas contratuais compulsórias (países de custódia, acesso irrestrito do BACEN, segregação de dados, dever de notificação de incidentes pelo provedor, continuidade).
* **Arts. 18 e 19:** Gestão de continuidade e planos de contingência para falhas de provedores em nuvem.
* **Art. 20:** Plano de descontinuidade e reversibilidade tecnológica (*Exit Strategy*).

### Capítulo IV — Disposições Finais e Transitórias (Arts. 21 a 23)
* **Art. 21:** Guarda mandatória de todas as evidências, relatórios, atas e contratos por **no mínimo 5 anos** à disposição da fiscalização do BACEN.
* **Art. 23:** Revogação da Resolução CMN nº 4.658/2018.
