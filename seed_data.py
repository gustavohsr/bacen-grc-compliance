"""
Seed data script for BACEN CMN 4.893 and CMN 5.274 GRC Compliance System.
Configurable institutional data and complete PARI module data.
"""
import sqlite3
import os
from datetime import datetime, date

DB_PATH = "/home/gustavo/.gemini/antigravity/scratch/bacen-grc-compliance/data/compliance.db"

def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Clear existing
    cursor.execute("DELETE FROM auditoria_log;")
    cursor.execute("DELETE FROM incidentes;")
    cursor.execute("DELETE FROM pari_simulados;")
    cursor.execute("DELETE FROM pari_playbooks;")
    cursor.execute("DELETE FROM pari_governanca;")
    cursor.execute("DELETE FROM fornecedores_nuvem;")
    cursor.execute("DELETE FROM planos_acao;")
    cursor.execute("DELETE FROM evidencias;")
    cursor.execute("DELETE FROM avaliacoes;")
    cursor.execute("DELETE FROM requisitos;")
    cursor.execute("DELETE FROM dominios;")
    cursor.execute("DELETE FROM instituicao;")

    # 1. Instituição Financeira Avaliada (Configurável)
    cursor.execute("""
    INSERT INTO instituicao (
        id, razao_social, nome_fantasia, cnpj, segmento, tipo_instituicao, registro_unicad,
        diretor_responsavel, cargo_diretor, email_diretor, telefone_diretor,
        data_aprovacao_politica, data_ultima_revisao, versao_politica, escopo_operacional, is_ativa
    ) VALUES (
        1,
        'Instituição Financeira Alpha S.A. - Banco Múltiplo',
        'Alpha Bank',
        '00.123.456/0001-78',
        'S3',
        'Banco Múltiplo',
        'BACEN-UNICAD-9821',
        'Roberto Silveira Mello',
        'Diretor Estatutário de Riscos e Segurança Cibernética (Art. 7º BACEN)',
        'roberto.mello@alphabank.com.br',
        '(11) 3244-8000',
        '2025-11-25',
        '2026-02-15',
        '3.2',
        'Instituição autorizada a funcionar pelo Banco Central do Brasil no segmento S3, operando contas de pagamento, crédito comercial, mensageria SPB, PIX e Open Finance.',
        1
    );
    """)

    # 2. Domínios Regulatórios
    dominios = [
        ('DOM-01', 'Governança & Política de Segurança Cibernética', 'Estrutura de governança corporativa, aprovação por Conselho e diretoria estatutária perante o BACEN.', 'Arts. 1º, 2º, 7º, 9º e 10', 'shield-check', 1),
        ('DOM-02', '14 Controles Mínimos Mandatórios (Resolução CMN 5.274)', 'Controles técnicos obrigatórios, prescritivos e auditáveis inseridos pela Resolução CMN 5.274 no Art. 3º.', 'Art. 3º (Res. CMN 5.274/2025)', 'lock', 2),
        ('DOM-03', 'Gestão, Resposta a Incidentes (PARI) & Compartilhamento', 'Plano de Ação e de Resposta a Incidentes, contenção, mitigação e comunicação ao Banco Central.', 'Arts. 4º, 5º, 6º e 8º', 'alert-triangle', 3),
        ('DOM-04', 'Testes de Intrusão, Pentests & Gestão de Vulnerabilidades', 'Rotinas periódicas de varreduras técnicas, testes de intrusão independentes e remediação.', 'Arts. 3º, 6º e 8º', 'target', 4),
        ('DOM-05', 'Contratação de Nuvem, Processamento & Notificação BACEN', 'Requisitos para contratação de serviços relevantes de TI/Nuvem no Brasil e exterior e cláusulas do Art. 17.', 'Arts. 11 a 17', 'cloud', 5),
        ('DOM-06', 'Continuidade de Negócios, Contingência & Reversibilidade', 'Planos de contingência, resiliência operacional, testes de desastre e planos de saída (exit strategy).', 'Arts. 18 a 20', 'activity', 6),
        ('DOM-07', 'Relatório Anual do PARI, Trilha de Auditoria & Fiscalização', 'Elaboração do relatório anual com data-base 31/12, submissão à governança e guarda de evidências.', 'Arts. 8º, 21 e 22', 'file-text', 7)
    ]

    for d in dominios:
        cursor.execute("""
        INSERT INTO dominios (codigo, nome, descricao, artigo_referencia, icone, ordem)
        VALUES (?, ?, ?, ?, ?, ?);
        """, d)

    conn.commit()

    cursor.execute("SELECT id, codigo FROM dominios;")
    dom_map = {row['codigo']: row['id'] for row in cursor.fetchall()}

    # 3. Requisitos Normativos (Todos os 32 requisitos)
    requisitos = [
        # DOM-01: Governança & Política
        (
            'REQ-01', dom_map['DOM-01'], 'Art. 2º',
            'Implementação e Manutenção da Política de Segurança Cibernética',
            'A instituição deve implementar e manter política de segurança cibernética compatível com o modelo de negócio, natureza, complexidade dos produtos e relevância de risco.',
            'A Política deve abranger formalmente objetivos, procedimentos de controle, tratamento de incidentes, retenção de dados, testes de continuidade e critérios de classificação da informação.',
            0, None, 'Critica', 'Todos',
            'Documento formal da Política de Segurança Cibernética; Matriz de Classificação de Informação; Resoluções de Diretoria.'
        ),
        (
            'REQ-02', dom_map['DOM-01'], 'Art. 7º',
            'Designação Formal de Diretor Estatutário Responsável perante o BACEN',
            'A instituição deve designar diretor responsável pela política de segurança cibernética e pela execução do plano de ação e de resposta a incidentes.',
            'O diretor estatutário deve estar formalmente homologado no sistema Unicad do Banco Central do Brasil, possuindo alçada e autoridade operacional sobre a segurança cibernética.',
            0, None, 'Critica', 'Todos',
            'Ata de eleição de diretoria; Registro homologado no BACEN Unicad; Termo de Posse e responsabilidade estatutária.'
        ),
        (
            'REQ-03', dom_map['DOM-01'], 'Art. 9º',
            'Aprovação pelo Conselho de Administração ou Diretoria',
            'A política de segurança cibernética e o plano de ação e de resposta a incidentes devem ser aprovados pelo conselho de administração ou pela diretoria da instituição.',
            'Aprovação formal com registro em ata lavrada de reunião ordinária do Conselho de Administração ou Diretoria Colegiada.',
            0, None, 'Alta', 'Todos',
            'Ata de Reunião do Conselho de Administração (ou Diretoria); Parecer do Comitê de Riscos e Cibersegurança.'
        ),
        (
            'REQ-04', dom_map['DOM-01'], 'Art. 10',
            'Revisão Anual Documentada da Política e do Plano',
            'A política de segurança cibernética e o plano de ação e de resposta a incidentes devem ser documentados e revisados com periodicidade mínima anual.',
            'Processo cíclico de revisão anual com controle de versões, pareceres técnicos e revalidação pela governança estatutária.',
            0, None, 'Alta', 'Todos',
            'Histórico de versionamento; Ata de aprovação da revisão anual; Relatório de alterações e melhorias normativas.'
        ),
        (
            'REQ-05', dom_map['DOM-01'], 'Arts. 4º e 5º',
            'Divulgação Interna e Publicação de Resumo ao Público',
            'Divulgação aos funcionários e prestadores de serviços terceirizados em linguagem acessível e publicação na internet de resumo contendo as linhas gerais da política.',
            'Programa formal de conscientização interna e página pública institucional acessível com o resumo executivo da Política de Cibersegurança.',
            0, None, 'Media', 'Todos',
            'URL pública da página de cibersegurança da instituição; Registros de aceite em intranet; Relatórios de campanhas de segurança.'
        ),

        # DOM-02: Os 14 Controles Mínimos Mandatórios da Resolução CMN nº 5.274/2025
        (
            'REQ-5274-01', dom_map['DOM-02'], 'Art. 3º, §2º, I (Res. 5.274)',
            'Controle 01/14: Autenticação Robusta e Múltiplos Fatores (MFA)',
            'Implementação de mecanismos de autenticação robusta, com autenticação multifator (MFA) obrigatória para acessos privilegiados, sistemas críticos e canais externos.',
            'MFA baseado em fatores independentes (conhecimento, posse, inerência), mitigação de bypass, revogação automática de sessões e proteção contra ataques de força bruta e fadiga de MFA.',
            1, 1, 'Critica', 'Todos',
            'Políticas de Identity & Access Management (IAM); Logs de MFA; Relatório de auditoria de acessos administrativos.'
        ),
        (
            'REQ-5274-02', dom_map['DOM-02'], 'Art. 3º, §2º, II (Res. 5.274)',
            'Controle 02/14: Mecanismos Avançados de Criptografia',
            'Adoção de criptografia forte tanto para dados em repouso (storage, banco de dados, backups) quanto em trânsito (redes internas, RSFN e internet).',
            'Algoritmos criptográficos modernos (AES-256, TLS 1.3), proibição de cifras obsoletas (SSL, TLS < 1.2, DES, SHA-1 fraco) e custódia segura de chaves em HSM/KMS.',
            1, 2, 'Critica', 'Todos',
            'Política de Gestão Criptográfica; Configurações de TLS nos load balancers; Evidências de TDE nos bancos de dados; Inventário de KMS/HSM.'
        ),
        (
            'REQ-5274-03', dom_map['DOM-02'], 'Art. 3º, §2º, III (Res. 5.274)',
            'Controle 03/14: Prevenção e Detecção de Intrusão (IPS / IDS / EDR)',
            'Mecanismos contínuos de prevenção e detecção de acessos não autorizados e intrusões em nível de rede, perímetro, endpoints e ambientes de nuvem.',
            'Implantação de sistemas de IDS/IPS com atualização automática de assinaturas, EDR/XDR com capacidade de contenção imediata de endpoints e telemetria para o SOC.',
            1, 3, 'Critica', 'Todos',
            'Dashboard e relatórios do SIEM/SOC; Evidências de agentes EDR cobrindo 100% dos servidores e estações; Regras ativas de IPS/IDS.'
        ),
        (
            'REQ-5274-04', dom_map['DOM-02'], 'Art. 3º, §2º, IV (Res. 5.274)',
            'Controle 04/14: Prevenção de Vazamento de Informações (DLP)',
            'Mecanismos para prevenir, identificar e bloquear a exfiltração ou vazamento de dados corporativos e informações sensíveis de clientes.',
            'Solução de DLP abrangendo canais de saída: e-mail institucional, endpoints (USB, prints, clipboard), upload para navegadores/nuvem pública e APIs de dados.',
            1, 4, 'Alta', 'Todos',
            'Configurações da ferramenta de DLP corporativa; Relatórios de bloqueios de exfiltração; Matriz de dados sensíveis (LGPD e sigilo bancário).'
        ),
        (
            'REQ-5274-05', dom_map['DOM-02'], 'Art. 3º, §2º, V (Res. 5.274)',
            'Controle 05/14: Proteção contra Softwares Maliciosos (Antimalware)',
            'Mecanismos avançados de proteção contra vírus, malwares, spywares e ransomwares em todos os recursos computacionais da instituição.',
            'Proteção antimalware com inteligência comportamental (machine learning/heurística), análise de sandbox para anexos e quarentena automatizada de ameaças.',
            1, 5, 'Alta', 'Todos',
            'Relatório de conformidade da base instalada de antimalware; Atualizações de assinaturas e definições em tempo real; Testes de eficácia contra ransomwares.'
        ),
        (
            'REQ-5274-06', dom_map['DOM-02'], 'Art. 3º, §2º, VI (Res. 5.274)',
            'Controle 06/14: Rastreabilidade e Trilhas de Auditoria (Logs)',
            'Garantia de rastreabilidade completa das ações de usuários, operadores e sistemas com geração, proteção e retenção inviolável de logs de auditoria.',
            'Centralização em SIEM, sincronização de relógio via NTP oficial auditado, integridade de logs com hash criptográfico, retenção mínima de 5 anos para logs críticos e proibição de edição por administradores.',
            1, 6, 'Critica', 'Todos',
            'Arquitetura de centralização de logs (SIEM / WORM storage); Comprovante de sincronização NTP stratum 1/2; Política de retenção de logs.'
        ),
        (
            'REQ-5274-07', dom_map['DOM-02'], 'Art. 3º, §2º, VII (Res. 5.274)',
            'Controle 07/14: Gestão e Testes de Cópias de Segurança (Backups)',
            'Rotina rigorosa de geração de cópias de segurança (backups), armazenamento em locais segregados, proteção contra deleção/ransomware e testes de restauração.',
            'Backups com princípio 3-2-1, suporte a repositórios imutáveis (Write Once Read Many), testes periódicos documentados de restore com RPO e RTO validados.',
            1, 7, 'Critica', 'Todos',
            'Relatórios semestrais de testes de restauração de backup; Configuração de retenção imutável na nuvem/fita; Política formal de Backup.'
        ),
        (
            'REQ-5274-08', dom_map['DOM-02'], 'Art. 3º, §2º, VIII (Res. 5.274)',
            'Controle 08/14: Avaliação e Correção Contínua de Vulnerabilidades',
            'Processo contínuo de identificação, priorização por risco e remediação tempestiva de vulnerabilidades em sistemas operacionais, aplicações e infraestrutura.',
            'Varreduras semanais/mensais automatizadas de vulnerabilidades (scans internos e externos), SLA formal de correção por criticidade (ex: Crítica ≤ 7 dias, Alta ≤ 15 dias).',
            1, 8, 'Alta', 'Todos',
            'Relatórios de Vulnerability Assessment; Matriz de SLA de correção; Registro de tickets de remediação concluídos.'
        ),
        (
            'REQ-5274-09', dom_map['DOM-02'], 'Art. 3º, §2º, IX (Res. 5.274)',
            'Controle 09/14: Perfis de Configuração Segura (Hardening)',
            'Estabelecimento, aplicação e monitoramento de perfis de configuração segura (hardening) para sistemas operacionais, contêineres, bancos de dados e ativos de rede.',
            'Adoção de baselines reconhecidos internacionalmente (CIS Benchmarks ou NIST), desativação de serviços desnecessários, remoção de contas default e auditoria de compliance de configuração.',
            1, 9, 'Alta', 'Todos',
            'Diretrizes de Hardening documentadas; Relatórios de checagem automatizada de CIS Benchmarks; Imagens padronizadas e validadas (Golden Images).'
        ),
        (
            'REQ-5274-10', dom_map['DOM-02'], 'Art. 3º, §2º, X (Res. 5.274)',
            'Controle 10/14: Proteção de Redes e Segregação de Ambientes',
            'Controles de filtragem de tráfego, firewalls de nova geração, microssegmentação e estrita segregação física ou lógica entre redes corporativas, DMZ e ambientes produtivos.',
            'Firewalls com inspeção profunda de pacotes (NGFW), isolamento estrito entre ambientes de Desenvolvimento/Homologação e Produção, controle de tráfego leste-oeste e WAF para aplicações web.',
            1, 10, 'Critica', 'Todos',
            'Topologia de rede atualizada e assinada; Regras de firewalls e revisão semestral de portas liberadas; Configurações ativas de Web Application Firewall (WAF).'
        ),
        (
            'REQ-5274-11', dom_map['DOM-02'], 'Art. 3º, §2º, XI (Res. 5.274)',
            'Controle 11/14: Gestão do Ciclo de Vida de Certificados Digitais',
            'Gestão rigorosa do inventário, emissão, renovação, proteção de chaves privadas e verificação de revogação de certificados digitais utilizados pela instituição.',
            'Inventário automatizado de certificados (SSL/TLS, SPB, mTLS), monitoramento de vencimento para evitar interrupções de serviço, proteção de chaves privadas em HSM e verificação de CRL/OCSP.',
            1, 11, 'Alta', 'Todos',
            'Inventário consolidado de certificados digitais; Alertas de expiração prévia; Auditoria de guarda de chaves criptográficas em módulos de segurança (HSM).'
        ),
        (
            'REQ-5274-12', dom_map['DOM-02'], 'Art. 3º, §2º, XII (Res. 5.274)',
            'Controle 12/14: Ações de Inteligência no Ambiente Cibernético (Threat Intel)',
            'Monitoramento proativo e inteligência sobre ameaças direcionadas à instituição na internet aberta, Deep Web, Dark Web e grupos de comunicação privados.',
            'Contratação ou estruturação de capacidade de Cyber Threat Intelligence (CTI) para detecção de credenciais vazadas de colaboradores/clientes, menções da marca, criação de domínios maliciosos e planos de ataque.',
            1, 12, 'Alta', 'Todos',
            'Contrato/Relatórios da ferramenta de Threat Intelligence; Alertas de monitoramento de Dark Web tratados; Processos de takedown de sites falsos/phishing.'
        ),
        (
            'REQ-5274-13', dom_map['DOM-02'], 'Art. 3º, §2º, XIII (Res. 5.274)',
            'Controle 13/14: Segurança na Comunicação de Dados na RSFN / Open Finance / Pix',
            'Requisitos adicionais e salvaguardas rigorosas para tráfego eletrônico de dados na Rede do Sistema Financeiro Nacional (RSFN) e ecossistemas abertos.',
            'Autenticação mTLS bidirecional, certificados ICP-Brasil específicos para SPB/PIX/Open Finance, canais criptografados dedicados e validação contínua de integridade das mensagens financeiras.',
            1, 13, 'Critica', 'Todos',
            'Homologação de conectividade RSFN / Banco Central; Certificados SPB/ICP-Brasil ativos; Arquitetura de mensageria PIX e Open Finance auditada.'
        ),
        (
            'REQ-5274-14', dom_map['DOM-02'], 'Art. 3º, §2º, XIV (Res. 5.274)',
            'Controle 14/14: Segurança em APIs e Ciclo de Desenvolvimento Seguro (DevSecOps)',
            'Aplicação de controles de segurança no ciclo de vida de desenvolvimento de software e proteção robusta das interfaces de programação de aplicações (APIs).',
            'Integração de testes estáticos (SAST) e dinâmicos (DAST) no pipeline CI/CD, gestão de dependências de código aberto (SCA), API Gateway com rate limiting, validação de schemas e autenticação OAuth 2.0 / FAPI.',
            1, 14, 'Alta', 'Todos',
            'Relatórios de esteira CI/CD com gates de segurança; Relatórios SAST/DAST; Políticas de segurança do API Gateway (Fapi-compliant).'
        ),

        # DOM-03: Plano de Ação e de Resposta a Incidentes (PARI)
        (
            'REQ-PARI-01', dom_map['DOM-03'], 'Art. 6º',
            'Plano de Ação e de Resposta a Incidentes (PARI) Estruturado',
            'A instituição deve estabelecer formalmente plano de ação e de resposta a incidentes contendo ações para prevenção, identificação, contenção, mitigação dos efeitos e recuperação.',
            'Equipe de resposta (CSIRT/CERT) com papéis definidos, matriz de severidade de incidentes, playbooks para ransomware, vazamento de dados e negação de serviço distribuída (DDoS).',
            0, None, 'Critica', 'Todos',
            'Documento formal do PARI aprovado; Playbooks de Resposta a Incidentes por cenário; Matriz de acionamento do Comitê de Crise.'
        ),
        (
            'REQ-PARI-02', dom_map['DOM-03'], 'Art. 6º, §2º',
            'Comunicação de Incidentes Relevantes ao Banco Central do Brasil',
            'A instituição deve comunicar tempestivamente ao Banco Central do Brasil a ocorrência de incidentes cibernéticos relevantes que possam impactar as operações ou a reputação.',
            'Fluxo documentado de notificação regulatória no sistema BCB (SISBACEN / Risco Operacional), prazos de escalonamento e definição dos critérios objetivos de relevância do incidente.',
            0, None, 'Critica', 'Todos',
            'Procedimento operacional padrão (POP) de comunicação ao BACEN; Histórico de notificações no SISBACEN ou termo de inexistência de eventos relevantes no período.'
        ),
        (
            'REQ-PARI-03', dom_map['DOM-03'], 'Art. 6º, §3º',
            'Compartilhamento de Informações sobre Incidentes Relevantes',
            'Mecanismos para compartilhamento de informações sobre incidentes relevantes com as demais instituições autorizadas a funcionar pelo Banco Central do Brasil.',
            'Participação em fóruns ou redes setoriais de compartilhamento de inteligência cibernética (como Febraban Cyber Hub, Anbima ou similar), preservando sigilo bancário.',
            0, None, 'Media', 'Todos',
            'Comprovante de associação ou integração à rede de compartilhamento do SFN; Registros de indicadores de comprometimento (IoCs) compartilhados/recebidos.'
        ),

        # DOM-04: Testes de Intrusão & Pentests
        (
            'REQ-TEST-01', dom_map['DOM-04'], 'Arts. 3º e 6º',
            'Testes de Intrusão (Pentest) Periódicos por Terceiros Independentes',
            'Realização periódica de testes de intrusão nos sistemas de informação, redes, aplicações móveis e ambientes de nuvem da instituição.',
            'Pentests executados no mínimo anualmente por consultoria externa especializada e independente, abrangendo abordagens Black Box e Gray Box em sistemas críticos (PIX, Core Banking, Canais Digitais).',
            0, None, 'Critica', 'Todos',
            'Relatório Executivo e Técnico do último Teste de Intrusão; Termo de Independência da empresa avaliadora; Plano de Remediação das vulnerabilidades encontradas.'
        ),
        (
            'REQ-TEST-02', dom_map['DOM-04'], 'Art. 8º',
            'Comprovação da Efetividade e Remediação dos Testes de Segurança',
            'Documentação do acompanhamento da remediação das falhas identificadas nos testes de intrusão e testes de vulnerabilidade.',
            'Testes de revalidação (Retest) para todas as vulnerabilidades Críticas e Altas apontadas no relatório de intrusão, com assinatura de encerramento pelo CISO.',
            0, None, 'Alta', 'Todos',
            'Relatório de Reteste de Intrusão comprovando mitigação; Planilha de acompanhamento com datas e responsáveis.'
        ),

        # DOM-05: Contratação de Serviços de Processamento, Armazenamento e Nuvem
        (
            'REQ-CLOUD-01', dom_map['DOM-05'], 'Arts. 11 e 12',
            'Governança e Due Diligence Prévia para Contratação de Serviços Relevantes',
            'Processo formal de análise prévia e due diligence de governança, capacidade técnica, solvência financeira e conformidade regulatória antes da contratação de serviços de nuvem.',
            'Relatório de risco de terceiros (TPRM), avaliação de certificações internacionais de segurança do provedor (ISO 27001, SOC 2 Type II, PCI-DSS) e aprovação da contratação.',
            0, None, 'Alta', 'Todos',
            'Dossiê de Due Diligence do fornecedor de nuvem; Parecer técnico e jurídico prévio à assinatura contratual.'
        ),
        (
            'REQ-CLOUD-02', dom_map['DOM-05'], 'Art. 15',
            'Comunicação Prévia ao Banco Central com 60 Dias de Antecedência',
            'A instituição deve comunicar formalmente ao Banco Central do Brasil a contratação ou alteração relevante de serviços de processamento, armazenamento e nuvem, no prazo mínimo de 60 dias antes da vigência.',
            'Protocolo no sistema do Banco Central contendo descrição detalhada do serviço contratado, identificação da infraestrutura, país de processamento e justificativa operacional.',
            0, None, 'Critica', 'Todos',
            'Comprovante do protocolo de comunicação enviado ao BACEN via SISBACEN/Protocolo Digital; Documentação técnica anexada.'
        ),
        (
            'REQ-CLOUD-03', dom_map['DOM-05'], 'Art. 16',
            'Requisitos Específicos para Contratação de Serviços no Exterior',
            'Quando a prestação do serviço for no exterior, deve haver convênio para troca de informações entre o Banco Central do Brasil e a autoridade supervisora do país do prestador.',
            'Verificação formal da lista de países com convênio celebrado com o BACEN ou obtenção de autorização específica do regulador, garantindo salvaguardas extraterritoriais.',
            0, None, 'Critica', 'Todos',
            'Nota técnica jurídica sobre a existência de convênio entre BACEN e autoridade estrangeira (ex: EUA/FED, UE); Consulta oficial BACEN.'
        ),
        (
            'REQ-CLOUD-04', dom_map['DOM-05'], 'Art. 17',
            'Cláusulas Contratuais Obrigatórias na Prestação de Serviços Relevantes',
            'Os contratos com provedores de nuvem e serviços relevantes devem conter expressamente as cláusulas obrigatórias exigidas pelo Art. 17.',
            'Cláusulas mandatórias: (I) indicação dos países de armazenamento e processamento; (II) acesso irrestrito aos dados e sistemas pelo BACEN e auditores; (III) notificação imediata de incidentes; (IV) segregação lógica de dados de clientes; (V) compromissos de transferência segura e continuidade operacional.',
            0, None, 'Critica', 'Todos',
            'Contratos assinados e aditivos com matriz de aderência às cláusulas do Art. 17 da Resolução CMN nº 4.893/2021; Parecer jurídico.'
        ),

        # DOM-06: Continuidade de Negócios & Reversibilidade
        (
            'REQ-CONT-01', dom_map['DOM-06'], 'Arts. 18 e 19',
            'Plano de Continuidade de Negócios e Contingência para Serviços de Nuvem',
            'A instituição deve dispor de estratégias e planos de contingência de negócios específicos para mitigar eventuais interrupções operacionais dos serviços contratados em nuvem.',
            'Plano de Continuidade de Negócios (PCN) e Disaster Recovery (DR) com testes periódicos de chaveamento de infraestrutura, definição de RTO (Recovery Time Objective) e RPO (Recovery Point Objective) compatíveis com o apetite a risco.',
            0, None, 'Critica', 'Todos',
            'Plano de Recuperação de Desastres (DRP); Ata de execução do último exercício simulado de crise/DR; Métricas de RTO e RPO validadas.'
        ),
        (
            'REQ-CONT-02', dom_map['DOM-06'], 'Art. 20',
            'Plano de Descontinuidade de Serviços e Estratégia de Saída (Exit Strategy)',
            'A instituição deve estabelecer e manter plano de contingência para o encerramento do contrato de serviços relevantes de processamento, armazenamento e computação em nuvem.',
            'Plano de saída documentando procedimentos para migração segura de dados e sistemas para outra nuvem ou ambiente on-premise, sem interrupção dos serviços bancários e sem perda de dados (anti-lock-in).',
            0, None, 'Alta', 'Todos',
            'Documento formal do Plano de Descontinuidade e Reversibilidade Tecnológica; Estimativa de cronograma e custos de portabilidade.'
        ),

        # DOM-07: Relatório Anual do Diretor Responsável & Guarda de Documentos
        (
            'REQ-AUD-01', dom_map['DOM-07'], 'Art. 8º',
            'Elaboração de Relatório Anual sobre a Efetividade do Plano (Data-base 31/12)',
            'Elaboração anual de relatório detalhado sobre a implementação da política de segurança cibernética e do plano de ação e de resposta a incidentes, com data-base em 31 de dezembro.',
            'Submissão do relatório ao comitê de auditoria e ao conselho de administração até 31 de março do exercício seguinte, contendo estatísticas de incidentes, efetividade dos controles e resultados de testes.',
            0, None, 'Critica', 'Todos',
            'Relatório Anual de Cibersegurança e Efetividade dos Controles assinado pelo Diretor Estatutário; Ata de apresentação ao Conselho de Administração.'
        ),
        (
            'REQ-AUD-02', dom_map['DOM-07'], 'Art. 21',
            'Manutenção e Disponibilização de Evidências ao Banco Central por 5 Anos',
            'A instituição deve manter à disposição do Banco Central do Brasil, pelo prazo mínimo de 5 (cinco) anos, todos os documentos, relatórios, atas e evidências de cumprimento da resolução.',
            'Arquivo digital estruturado com controle de integridade, histórico de versionamento e trilhas de auditoria das decisões colegiadas e laudos técnicos prontos para inspeção do BACEN.',
            0, None, 'Alta', 'Todos',
            'Repositório de Compliance GRC (Evidence Vault) com controle de retenção de 5 anos; Trilha de auditoria das avaliações e evidências.'
        )
    ]

    for req in requisitos:
        cursor.execute("""
        INSERT INTO requisitos (
            codigo, dominio_id, artigo, titulo, descricao_legal, especificacao_tecnica,
            is_cmn_5274_obrigatorio, numero_controle_5274, severidade, segmento_aplicavel, evidencias_sugeridas
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, req)

    conn.commit()

    cursor.execute("SELECT id, codigo FROM requisitos;")
    req_map = {row['codigo']: row['id'] for row in cursor.fetchall()}

    # 4. Avaliações Iniciais de Compliance (vinculadas à instituicao_id = 1)
    avaliacoes = [
        (1, req_map['REQ-01'], 'atendido', 100, 'Política de Cibersegurança revisada e aprovada pelo Conselho de Administração.', 'Governança Corporativa', '2025-11-25', '2026-02-10', 'Auditoria Interna', 'Total conformidade com o Art. 2º.'),
        (1, req_map['REQ-02'], 'atendido', 100, 'Diretor Estatutário homologado formalmente no Unicad BACEN sob número de processo regulatório ativo.', 'Jurídico Corporativo', '2025-05-10', '2026-01-15', 'Compliance & Risco', 'Registro checado no Sisbacen.'),
        (1, req_map['REQ-03'], 'atendido', 100, 'Aprovação unânime em reunião ordinária do Conselho de Administração.', 'Secretaria de Governança', '2025-11-25', '2026-02-10', 'Auditoria Interna', 'Ata arquivada e registrada.'),
        (1, req_map['REQ-04'], 'atendido', 100, 'Revisão anual ciclo 2025/2026 finalizada e documentada.', 'CISO Office', '2026-02-15', '2026-02-15', 'Auditoria Interna', 'Próxima revisão agendada para fev/2027.'),
        (1, req_map['REQ-05'], 'atendido', 100, 'Resumo executivo publicado no portal web oficial e campanhas de segurança realizadas aos colaboradores.', 'Comunicação & CISO', '2025-12-01', '2026-02-10', 'Compliance', 'Página web ativa.'),

        # DOM-02 (Controles 5.274)
        (1, req_map['REQ-5274-01'], 'atendido', 100, 'MFA baseado em FIDO2 e aplicativo autenticador habilitado para 100% dos colaboradores e sistemas administrativos.', 'Equipe de IAM', '2026-01-10', '2026-02-20', 'Auditoria Externa TI', 'MFA mandatório em Active Directory e AWS SSO.'),
        (1, req_map['REQ-5274-02'], 'atendido', 100, 'Criptografia AES-256 habilitada em repouso nos bancos RDS/S3 e TLS 1.3 obrigatório para todas as comunicações.', 'Infraestrutura Cloud', '2025-10-15', '2026-02-18', 'Auditoria Externa TI', 'Chaves gerenciadas em AWS KMS e HSM On-premise.'),
        (1, req_map['REQ-5274-03'], 'atendido', 100, 'Solução EDR instalada em 100% dos endpoints e servidores; Firewall NGFW ativo.', 'SOC & Operações de Segurança', '2025-09-30', '2026-02-12', 'Auditoria Interna', 'Alertas monitorados 24x7 pelo SOC parceiro.'),
        (1, req_map['REQ-5274-04'], 'parcialmente_atendido', 65, 'DLP implementado para e-mails institucionais e endpoints. Falta extensão completa para inspeção de repositórios Git corporativos.', 'Segurança da Informação', '2026-03-31', '2026-02-05', 'Auditoria Interna', 'Plano de ação em andamento para cobrir código-fonte.'),
        (1, req_map['REQ-5274-05'], 'atendido', 100, 'Solução de antimalware avançado com motor heurístico e isolamento automático de ameaças.', 'Operações de TI', '2025-08-20', '2026-01-20', 'Auditoria Interna', 'Taxa de cobertura de 100% nos ativos catalogados.'),
        (1, req_map['REQ-5274-06'], 'atendido', 100, 'Centralização de logs no SIEM com NTP sincronizado ao Observatório Nacional (ON) e bucket imutável WORM.', 'Engenharia de Segurança', '2025-11-05', '2026-02-14', 'Auditoria Externa TI', 'Retenção configurada para 5 anos com hash SHA-256.'),
        (1, req_map['REQ-5274-07'], 'atendido', 100, 'Backups diários com repositórios imutáveis (Object Lock). Último teste de restore integral executado em 15/01/2026.', 'Infraestrutura & DBA', '2026-01-15', '2026-02-15', 'Auditoria Interna', 'RTO obtido: 2h35m (meta: 4h); RPO obtido: 12 min (meta: 1h).'),
        (1, req_map['REQ-5274-08'], 'parcialmente_atendido', 75, 'Scans semanais de vulnerabilidades ativos. SLA de correção de falhas críticas em 7 dias cumprido em 92% dos casos.', 'Vulnerability Management', '2026-03-15', '2026-02-10', 'Auditoria Interna', 'Alguns sistemas legados necessitam de janela de homologação.'),
        (1, req_map['REQ-5274-09'], 'atendido', 100, 'Hardening baseado no CIS Benchmark Level 1 aplicado em todas as Golden Images Linux e Windows.', 'DevSecOps', '2025-12-10', '2026-02-08', 'Auditoria Interna', 'Conformidade de configuração aferida em 98.4%.'),
        (1, req_map['REQ-5274-10'], 'atendido', 100, 'Microssegmentação via VPC e Security Groups; DMZ para serviços expostos e WAF ativo.', 'Redes e Segurança', '2025-10-01', '2026-01-30', 'Auditoria Externa TI', 'Tráfego leste-oeste estritamente restrito por zero trust.'),
        (1, req_map['REQ-5274-11'], 'em_implementacao', 50, 'Inventário de certificados criado, porém processo de renovação ainda possui etapas manuais que estão sendo automatizadas via Cert-Manager.', 'Infraestrutura Cloud', '2026-03-31', '2026-02-01', 'Auditoria Interna', 'Exigência da Resolução 5.274 em fase final de automação.'),
        (1, req_map['REQ-5274-12'], 'em_implementacao', 40, 'Processo de contratação de provedor especializado de Threat Intelligence (Dark Web e Deep Web) em homologação contratual.', 'CISO Office', '2026-04-15', '2026-02-05', 'Auditoria Interna', 'Novo requisito formal da Resolução CMN 5.274/2025.'),
        (1, req_map['REQ-5274-13'], 'atendido', 100, 'Comunicação na RSFN operando com mTLS e certificados ICP-Brasil específicos (SPB/PIX). Redundância com dois roteadores dedicados.', 'Telecom & Conectividade BACEN', '2025-07-22', '2026-02-11', 'BACEN Fiscalização', 'Homologação oficial BACEN para PIX e SPB regular.'),
        (1, req_map['REQ-5274-14'], 'parcialmente_atendido', 70, 'SAST e SCA integrados no pipeline GitLab CI. Cobertura de DAST em fase de expansão para as APIs legadas.', 'DevSecOps', '2026-03-30', '2026-02-09', 'Auditoria Interna', 'APIs do Open Finance 100% aderentes ao perfil FAPI 1.0 Advanced.'),

        # DOM-03
        (1, req_map['REQ-PARI-01'], 'atendido', 100, 'PARI formalizado contendo playbooks operacionais e CSIRT estruturado com plantão de prontidão.', 'CSIRT Lead', '2025-11-15', '2026-02-10', 'Auditoria Interna', 'Simulado de mesa realizado em nov/2025.'),
        (1, req_map['REQ-PARI-02'], 'atendido', 100, 'Procedimento operacional padrão estabelecendo fluxo e prazos para comunicação ao BACEN via Sisbacen.', 'Compliance Regulatório', '2025-10-10', '2026-01-20', 'Compliance', 'Nenhum incidente crítico demandou notificação no último ano.'),
        (1, req_map['REQ-PARI-03'], 'atendido', 100, 'Instituição filiada ao Cyber Hub Febraban com compartilhamento de IoCs e alertas de inteligência de fraude.', 'Threat Intelligence', '2025-06-01', '2026-02-01', 'Auditoria Interna', 'Feed de IoCs integrado diretamente ao firewall/SIEM.'),

        # DOM-04
        (1, req_map['REQ-TEST-01'], 'atendido', 100, 'Pentest executado por empresa independente cobrindo Mobile Banking, Web e APIs PIX.', 'CISO Office', '2025-10-30', '2026-01-10', 'Auditoria Externa', 'Relatório técnico e atestado de independência emitidos.'),
        (1, req_map['REQ-TEST-02'], 'atendido', 100, 'Reteste realizado confirmando que todas as 2 vulnerabilidades críticas apontadas foram totalmente mitigadas.', 'Equipe de Aplicações', '2025-12-15', '2026-01-15', 'Auditoria Externa', 'Termo de encerramento emitido pela consultoria externa.'),

        # DOM-05
        (1, req_map['REQ-CLOUD-01'], 'atendido', 100, 'Due Diligence anual concluída para AWS e Microsoft Azure com avaliação dos relatórios SOC 2 Type II e ISO 27001.', 'Gestão de Terceiros (TPRM)', '2025-09-15', '2026-02-12', 'Auditoria Interna', 'Fornecedores classificados com risco residual baixo.'),
        (1, req_map['REQ-CLOUD-02'], 'atendido', 100, 'Todas as contratações e aditivos relevantes em nuvem comunicados ao BACEN com 60 dias de antecedência mínima.', 'Regulatório & Jurídico', '2025-08-01', '2026-01-18', 'Auditoria Interna', 'Protocolos do Sisbacen arquivados e válidos.'),
        (1, req_map['REQ-CLOUD-03'], 'atendido', 100, 'Dados armazenados em regiões nos EUA e Brasil. Convênio formal BACEN-FED verificado.', 'Jurídico Regulatório', '2025-08-01', '2026-01-18', 'Auditoria Interna', 'Parecer jurídico atestando existência de convênio multilateral.'),
        (1, req_map['REQ-CLOUD-04'], 'atendido', 100, 'Todos os contratos de prestação de serviços relevantes contêm as cláusulas obrigatórias dos incisos I a V do Art. 17.', 'Jurídico Contratos', '2025-10-20', '2026-02-10', 'Auditoria Externa', 'Cláusulas de acesso BACEN e segregação lógica checadas.'),

        # DOM-06
        (1, req_map['REQ-CONT-01'], 'atendido', 100, 'Plano de Continuidade e DR testado com sucesso com failover simulado da região principal para secundária.', 'Continuidade de Negócios (BCM)', '2025-11-28', '2026-02-15', 'Auditoria Interna', 'Tempo total de recuperação de sistemas críticos: 48 minutos.'),
        (1, req_map['REQ-CONT-02'], 'parcialmente_atendido', 60, 'Plano de saída documentado para serviços IaaS. Falta detalhamento do procedimento de migração de dados do SaaS de CRM.', 'Arquitetura Corporativa', '2026-04-30', '2026-01-25', 'Auditoria Interna', 'Gap apontado pela auditoria interna em fase de plano de ação.'),

        # DOM-07
        (1, req_map['REQ-AUD-01'], 'atendido', 100, 'Relatório anual com data-base 31/12/2025 elaborado e aprovado pelo Comitê de Auditoria e Conselho.', 'Diretor Estatutário CISO', '2026-02-15', '2026-02-18', 'Conselho de Administração', 'Relatório completo disponível no sistema para fiscalização BACEN.'),
        (1, req_map['REQ-AUD-02'], 'atendido', 100, 'Repositório digital estruturado com controle de acesso, backup imutável e trilha de auditoria para retenção de 5 anos.', 'Compliance & Arquivo', '2026-02-15', '2026-02-18', 'Auditoria Interna', 'Evidências catalogadas e auditadas.')
    ]

    for a in avaliacoes:
        cursor.execute("""
        INSERT INTO avaliacoes (
            instituicao_id, requisito_id, status, percentual_aderencia, justificativa, responsavel,
            prazo_adequacao, ultima_auditoria, avaliador, observacoes_auditor
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, a)

    conn.commit()

    # 5. MÓDULO PARI: Governança do CSIRT & Comunicação BACEN (Art. 6º)
    cursor.execute("""
    INSERT INTO pari_governanca (
        instituicao_id, lider_csirt, email_csirt, telefone_plantao_247, membros_csirt,
        comite_crise, canais_emergencia, criterios_relevancia_bacen, procedimento_sisbacen,
        data_ultima_revisao_pari, versao_pari
    ) VALUES (
        1,
        'Eng. Marcos Vinícius Ferreira',
        'csirt@alphabank.com.br',
        '(11) 98765-4321 (Plantão 24x7)',
        'Líder CSIRT (Coordenação), Analista Sênior SOC (Triagem), Engenheiro de Redes & Firewall (Contenção), Especialista Forense Computacional, DBA Líder (Dados), Encarregado DPO (LGPD).',
        'Diretor Estatutário Responsável (Art. 7º), Diretor Presidente (CEO), CISO Corporativo, Diretor Jurídico / DPO e Assessor Chefe de Relações Institucionais.',
        'Canal de voz criptografado dedicado (out-of-band), sala de guerra física isolada e e-mails de contingência fora da infraestrutura corporativa.',
        'São classificados como RELEVANTES para notificação obrigatória ao BACEN: (1) Indisponibilidade de serviços bancários essenciais (PIX, TED, Internet Banking) por mais de 2 horas; (2) Exfiltração ou vazamento confirmado de dados protegidos por sigilo bancário ou dados cadastrais sensíveis; (3) Fraudes cibernéticas com impacto financeiro relevante ou potencial contaminação sistêmica; (4) Incidentes com ampla exposição na mídia que afetem a reputação da instituição.',
        'Notificação compulsória em até 24 horas após a caracterização do incidente como relevante, realizada via módulo de Risco Operacional no Sisbacen / Protocolo Digital do Banco Central do Brasil, acompanhada de relatório preliminar e plano de mitigação.',
        '2026-02-15',
        '2.4'
    );
    """)

    # 6. MÓDULO PARI: Playbooks Operacionais (Art. 6º)
    playbooks = [
        (
            1, 'PB-01', 'Ataque de Ransomware e Sequestro de Ativos', 'Ransomware',
            'Identificação de telemetria anômala no EDR (criptografia em massa de arquivos, chamadas vssadmin delete shadows). Alertas imediatos no SOC com nível P1.',
            'Isolamento imediato de rede das máquinas afetadas via console EDR; desconexão de túneis VPN e bloqueio de portas SMB nas VLANs corporativas.',
            'Identificação do vetor inicial (phishing, RDP exposto); quarentena de contas de serviço comprometidas; revogação de tokens de autenticação.',
            'Validação de integridade dos backups imutáveis; restauração de servidores a partir de repositório seguro WORM; revalidação de regras de firewall.',
            'Se houver indisponibilidade superior a 2 horas ou vazamento de dados, acionamento do Diretor Estatutário para comunicação imediata no SISBACEN.',
            'Contenção em até 15 minutos; Restauração completa em até 4 horas (RTO).'
        ),
        (
            1, 'PB-02', 'Vazamento ou Exfiltração de Dados Bancários e Pessoais (LGPD)', 'Vazamento de Dados',
            'Disparo de alertas de DLP corporativo indicando transferência volumosa atípica de dados sigilosos; alertas da plataforma de Threat Intelligence de dados à venda na Dark Web.',
            'Revogação imediata de credenciais de acesso do usuário/serviço suspeito; bloqueio de IPs de destino e encerramento forçado de sessões ativas.',
            'Análise forense das trilhas de auditoria e logs do SIEM para determinar o escopo exato dos dados acessados e identificar a falha de autorização.',
            'Correção e fechamento da brecha técnica ou vulnerabilidade de API explorada; reemissão forçada de senhas e credenciais afetadas.',
            'Notificação simultânea ao Banco Central do Brasil (SISBACEN) e à Autoridade Nacional de Proteção de Dados (ANPD) em até 24h úteis.',
            'Identificação do escopo em 2 horas; Parecer executivo preliminar em 12 horas.'
        ),
        (
            1, 'PB-03', 'Ataque de Negação de Serviço Distribuída (DDoS) no PIX e Internet Banking', 'DDoS',
            'Monitoramento de saturação de banda e aumento exponencial de requisições HTTP/SYN flood na borda da rede; degradação de latência do PIX.',
            'Ativação imediata de proteção de mitigação DDoS em nuvem (Cloudflare Magic Transit / AWS Shield Advanced); redirecionamento de DNS e desafio de mitigação.',
            'Análise das assinaturas do tráfego malicioso e criação de regras de rate limiting e bloqueio geográfico de tráfego de origem anômala no WAF.',
            'Rebalanceamento de carga e retorno gradual do tráfego corporativo limpo; monitoramento contínuo de estabilidade das transações PIX.',
            'Comunicação ao Departamento de Operações Bancárias e de Sistema de Pagamentos (Deban/BACEN) se houver oscilação de conectividade no canal do PIX.',
            'Ativação de mitigação em menos de 5 minutos; Estabilização em até 20 minutos.'
        ),
        (
            1, 'PB-04', 'Indisponibilidade ou Falha em Nuvem Crítica (Failover & DR)', 'Nuvem',
            'Alerta automático do sistema de observabilidade apontando interrupção total na região primária da AWS (us-east-1 ou sa-east-1).',
            'Acionamento do procedimento de Disaster Recovery (DR); congelamento de transações em trânsito no banco primário.',
            'Chaveamento de tráfego (failover DNS via Route 53) para a região secundária na Microsoft Azure / AWS sa-east-1.',
            'Restauração das esteiras de microsserviços na região de contingência; checagem de consistência de saldos e mensageria.',
            'Notificação formal ao BACEN sobre acionamento de contingência em nuvem conforme previsto no plano de continuidade do Art. 19.',
            'RTO operacional de chaveamento: até 45 minutos; RPO de dados: até 15 minutos.'
        ),
        (
            1, 'PB-05', 'Indisponibilidade ou Falha de Conectividade na RSFN / SPB', 'RSFN',
            'Perda de sincronismo no roteador principal da Rede do Sistema Financeiro Nacional (RSFN); falha no envio de mensagens de liquidação STR/PIX.',
            'Chaveamento automático para o canal redundante e circuito secundário de telecomunicação da RSFN.',
            'Diagnóstico físico e lógico da interface serial/fibra com a operadora de telecomunicações credenciada.',
            'Reenvio seguro das mensagens pendentes com validação de certificados ICP-Brasil SPB e conferência de protocolo.',
            'Contato imediato com o suporte operacional da RSFN / Banco Central do Brasil para sincronização dos lotes de pagamento.',
            'Chaveamento para canal redundante em até 2 minutos.'
        )
    ]

    for pb in playbooks:
        cursor.execute("""
        INSERT INTO pari_playbooks (
            instituicao_id, codigo, titulo_cenario, categoria, etapa_deteccao,
            etapa_contencao, etapa_erradicacao, etapa_recuperacao, etapa_comunicacao_bacen, tempo_estimado_resposta
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, pb)

    conn.commit()

    # 7. MÓDULO PARI: Exercícios e Simulados de Crise (Tabletop Drills)
    simulados = [
        (
            1,
            'Simulado de Mesa 2025: Cenário de Ransomware com Tentativa de Dupla Extorsão',
            '2025-11-20',
            'Simulação de infecção por ransomware atingindo servidores de arquivos e tentativa de exfiltração de dados cadastrais de clientes, com teste de tomada de decisão da Diretoria.',
            'Diretor Estatutário de Cibersegurança, CISO, Líder CSIRT, Diretora Jurídica, Encarregada DPO, Gerente de Comunicação e Especialistas de Infraestrutura.',
            'Tempo de ativação do comitê de crise: 22 minutos; Decisão de contenção: 35 minutos.',
            'Excelente coordenação entre as áreas técnica e jurídica; clareza na aplicação dos critérios de não pagamento de resgate e acionamento de backups imutáveis.',
            'Necessidade de agilizar a redação do comunicado ao BACEN e aprimorar a lista de telefones de emergência dos membros do comitê.',
            'Elaboração de minutas pré-aprovadas para notificação regulatória no Sisbacen e aquisição de canal de mensageria criptografada redundante fora da rede.',
            'Concluido'
        ),
        (
            1,
            'Simulado Técnico: Chaveamento de Nuvem e Continuidade Operacional do PIX',
            '2025-08-14',
            'Simulação de falha catastrófica no datacenter principal de nuvem e failover para região de contingência secundária.',
            'Equipes de SRE, Cloud Sec, Banco de Dados e Suporte a Sistemas Financeiros.',
            'Tempo de failover alcançado: 38 minutos (meta do RTO era 45 minutos).',
            'Automação de chaveamento de DNS e réplica do banco de dados relacional operaram com integridade de dados 100%.',
            'Pequena latência temporária de sincronismo na fila de mensageria de contingência.',
            'Ajuste das variáveis de alocação de capacidade sob demanda na região secundária.',
            'Concluido'
        )
    ]

    for s in simulados:
        cursor.execute("""
        INSERT INTO pari_simulados (
            instituicao_id, titulo_simulado, data_realizacao, cenario_testado, participantes,
            tempo_resposta_alcancado, pontos_fortes, gargalos_identificados, acoes_melhoria, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, s)

    conn.commit()

    # 8. Evidências Iniciais
    evidencias = [
        (
            1, req_map['REQ-01'],
            'Política Corporativa de Segurança Cibernética v3.2',
            'Politica',
            'Documento normativo aprovado pelo Conselho de Administração detalhando todos os pilares e diretrizes de cibersegurança conforme CMN 4.893 e 5.274.',
            'Politica_Ciberseguranca_v3.2.pdf',
            '/uploads/Politica_Ciberseguranca_v3.2.pdf',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            1458290, 'application/pdf', 'https://intranet.alphabank.com.br/politicas',
            'Mariana Lima', '2026-02-15', 'Validada'
        ),
        (
            1, req_map['REQ-02'],
            'Certidão de Registro Unicad - Diretor Estatutário perante o BACEN',
            'Ata de Diretoria',
            'Comprovante formal emitido pelo Sistema de Informações sobre Entidades de Interesse do Banco Central (Unicad) com homologação do Diretor Estatutário.',
            'Certidao_Unicad_Diretor_Ciberseguranca.pdf',
            '/uploads/Certidao_Unicad_Diretor_Ciberseguranca.pdf',
            'a8f5f167f44f4964e6c998dee827110c034293f7da20194098939634d0b2848b',
            524100, 'application/pdf', None,
            'Secretaria Geral', '2025-06-01', 'Validada'
        ),
        (
            1, req_map['REQ-5274-01'],
            'Relatório de Conformidade MFA - Active Directory & Nuvem',
            'Log/Auditoria',
            'Extração do painel de controle comprovando aplicação de MFA por hardware token (FIDO2) ou app TOTP para 100% dos usuários corporativos.',
            'Relatorio_Auditoria_MFA_Q1_2026.pdf',
            '/uploads/Relatorio_Auditoria_MFA_Q1_2026.pdf',
            'c2755e100f8981f964095a8286a117b355d0124355ddccb7cf4cb7f0d0698160',
            892300, 'application/pdf', None,
            'Equipe de IAM', '2026-02-18', 'Validada'
        ),
        (
            1, req_map['REQ-PARI-01'],
            'Plano de Ação e de Resposta a Incidentes (PARI) Formalizado v2.4',
            'Politica',
            'Documento estruturado do PARI contendo playbooks operacionais de resposta, matriz de criticidade e acionamento do CSIRT.',
            'PARI_Documento_Oficial_v2.4.pdf',
            '/uploads/PARI_Documento_Oficial_v2.4.pdf',
            '4a7d1ed414474e4033ac29ccb8653d9b0021c33a92b2d6a5e1286c8f498c5667',
            2150000, 'application/pdf', None,
            'Eng. Marcos Vinícius Ferreira', '2026-02-15', 'Validada'
        ),
        (
            1, req_map['REQ-TEST-01'],
            'Relatório Técnico de Teste de Intrusão Independente 2025',
            'Relatório Pentest',
            'Relatório emitido por consultoria independente avaliando o aplicativo móvel, APIs do PIX e infraestrutura perimetral.',
            'Relatorio_Pentest_Independente_2025.pdf',
            '/uploads/Relatorio_Pentest_Independente_2025.pdf',
            '1b238245100edc64b7324c47f7d1b33368291f435031b268019e0780f2d87e14',
            3450000, 'application/pdf', None,
            'Consultoria Externa', '2025-11-01', 'Validada'
        ),
        (
            1, req_map['REQ-CLOUD-04'],
            'Matriz de Aderência Contratual Art. 17 - Contrato Cloud Relevante',
            'Contrato Cloud',
            'Análise jurídica detalhando as cláusulas de fiscalização irrestrita pelo BACEN, segregação lógica e plano de continuidade do contrato de nuvem.',
            'Matriz_Clausulas_Art17_BACEN_Cloud.pdf',
            '/uploads/Matriz_Clausulas_Art17_BACEN_Cloud.pdf',
            '8f4a34b29b61d3e8a2a47ff769d32d0c27384918e97669d021884e9b8915c71b',
            650200, 'application/pdf', None,
            'Jurídico de TI', '2025-10-25', 'Validada'
        ),
        (
            1, req_map['REQ-AUD-01'],
            'Relatório Anual do Art. 8º - Data-base 31/12/2025',
            'Politica',
            'Relatório consolidado assinado pelo Diretor Estatutário para prestação de contas ao BACEN, contendo métricas, incidentes, testes e controles.',
            'Relatorio_Anual_Art8_BACEN_2025.pdf',
            '/uploads/Relatorio_Anual_Art8_BACEN_2025.pdf',
            '9b74c9897bac770ffc029102a200c5deac54f2c5fa5b516810743f58d93d4a9e',
            2890000, 'application/pdf', None,
            'Diretor Estatutário CISO', '2026-02-15', 'Validada'
        )
    ]

    for ev in evidencias:
        cursor.execute("""
        INSERT INTO evidencias (
            instituicao_id, requisito_id, titulo, tipo, descricao, nome_arquivo, caminho_arquivo,
            hash_sha256, tamanho_bytes, mime_type, link_externo, coletor, data_coleta, status_validacao
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, ev)

    conn.commit()

    # 9. Planos de Ação (5W2H)
    planos = [
        (
            1, req_map['REQ-5274-04'],
            'Expansão da Proteção DLP para Repositórios Git e Ferramentas SaaS',
            'Implementar solução de Secret Scanning e DLP em código nos repositórios GitHub Enterprise e Slack corporativo.',
            'Evitar exposição acidental de credenciais bancárias, tokens de API e dados sensíveis de clientes por desenvolvedores.',
            'Ambiente de Desenvolvimento, DevOps e Nuvem',
            'Felipe Albuquerque (SecOps Lead)',
            '2026-03-31',
            'Configurar GitHub Advanced Security com secret scanning automático e pre-commit hooks de bloqueio.',
            45000.0, 'Em_Andamento', 60, None
        ),
        (
            1, req_map['REQ-5274-11'],
            'Automação Integral do Ciclo de Vida de Certificados Digitais',
            'Substituir processos manuais de renovação de certificados por pipeline automatizado com Let''s Encrypt / DigiCert via Cert-Manager.',
            'Eliminar risco de expiração inesperada de certificados SSL/mTLS de APIs e serviços do Open Finance.',
            'Clusters Kubernetes EKS e Load Balancers',
            'Juliana Ramos (Cloud SRE)',
            '2026-03-31',
            'Implantar Cert-Manager com ACME issuer automatizado e alertas com 30 dias de antecedência no PagerDuty.',
            28000.0, 'Em_Andamento', 50, None
        ),
        (
            1, req_map['REQ-5274-12'],
            'Contratação e Implantação de Plataforma de Cyber Threat Intelligence (Dark Web)',
            'Contratar serviço especializado de Threat Intel para monitoramento contínuo de vazamentos na Deep/Dark Web e canais Telegram.',
            'Atender expressamente à exigência prescritiva introduzida pela Resolução CMN nº 5.274 no Art. 3º.',
            'Plataforma Externa & Integração com SOC',
            'Diretoria de Cibersegurança',
            '2026-04-15',
            'Concluir processo de RFP, selecionar fornecedor líder de mercado e integrar feed de ameaças.',
            120000.0, 'Em_Andamento', 40, None
        ),
        (
            1, req_map['REQ-CONT-02'],
            'Elaboração de Procedimento de Migração e Saída do SaaS CRM',
            'Mapear e documentar a rotina técnica de extração integral e reversibilidade dos dados de clientes hospedados no CRM em nuvem.',
            'Atender ao Artigo 20 da Resolução CMN nº 4.893 (plano de descontinuidade com garantia de portabilidade total).',
            'Ambiente Corporativo de Relacionamento',
            'Rodrigo Prado (Arquiteto Corporativo)',
            '2026-04-30',
            'Construir script de exportação diária via API para data lake corporativo no formato Parquet aberto e testar carga em base independente.',
            35000.0, 'Em_Andamento', 35, None
        )
    ]

    for p in planos:
        cursor.execute("""
        INSERT INTO planos_acao (
            instituicao_id, requisito_id, titulo, o_que, por_que, onde, quem, quando, como, quanto,
            status, progresso_pct, data_conclusao
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, p)

    conn.commit()

    # 10. Fornecedores de Nuvem
    fornecedores = [
        (
            1, 'Amazon Web Services (AWS)',
            'Hospedagem de infraestrutura core banking, microsserviços, data lake e bancos de dados relacionais',
            'IaaS', 'Brasil (São Paulo sa-east-1) e Estados Unidos (N. Virginia us-east-1)',
            1, 1, '2023-04-15', 1, 1, 1, 1, 1,
            '2025-11-28', 'Baixo',
            'Contrato Enterprise assinado com aditivo específico contemplando todos os incisos do Art. 17 da Resolução 4.893. Comunicação ao BACEN formalizada.'
        ),
        (
            1, 'Microsoft Azure',
            'Ambiente de contingência a desastres (DR secundário) e esteiras analíticas de IA/ML',
            'PaaS', 'Brasil (Brazil South - SP) e Estados Unidos (East US)',
            1, 1, '2024-01-20', 1, 1, 1, 1, 1,
            '2025-10-14', 'Baixo',
            'Notificado ao BACEN com 60 dias de antecedência. Due Diligence renovada sem apontamentos de risco crítico.'
        ),
        (
            1, 'Salesforce.com',
            'Plataforma de CRM, onboarding de clientes e atendimento ao consumidor',
            'SaaS', 'Estados Unidos e Alemanha',
            1, 1, '2023-09-10', 1, 1, 1, 1, 0,
            '2025-08-10', 'Medio',
            'Plano de reversibilidade/saída em fase de detalhamento técnico para total aderência ao Art. 20.'
        )
    ]

    for f in fornecedores:
        cursor.execute("""
        INSERT INTO fornecedores_nuvem (
            instituicao_id, nome_provedor, servico_prestado, tipo_nuvem, pais_armazenamento, servico_relevante,
            notificado_bacen, data_notificacao_bacen, convenio_bacen_pais, clausula_acesso_bacen,
            clausula_segregacao_dados, clausula_continuidade, clausula_reversibilidade,
            data_ultimo_teste_contingencia, nivel_risco, observacoes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, f)

    conn.commit()

    # 11. Incidentes
    incidentes = [
        (
            1, 'INC-2025-0042',
            'Tentativa de Credential Stuffing em API de Autenticação Móvel',
            '2025-09-14 03:22:00', '2025-09-14 03:24:15',
            'Intrusão', 'Média', 'API Gateway Móvel',
            'Nenhuma conta comprometida. Bloqueio automático de 1.450 IPs maliciosos pelo WAF e rate-limiting.',
            'Encerrado', 0, None,
            'Ataque de força bruta distribuído originado de botnet internacional utilizando vazamentos públicos.',
            'Ajuste das regras de rate-limiting e inclusão de desafio de prova de trabalho (PoW) no app.'
        ),
        (
            1, 'INC-2025-0089',
            'E-mail de Phishing Temático Simulando Comunicado de RH com Link Malicioso',
            '2025-11-03 10:15:00', '2025-11-03 10:18:30',
            'Phishing', 'Baixa', 'Serviço de Correio Eletrônico Corporativo',
            'Mensagem capturada pelo filtro anti-phishing. Três colaboradores clicaram, mas o sandbox bloqueou a execução da macro.',
            'Encerrado', 0, None,
            'Phishing direcionado de spear-phishing usando domínio falso similar.',
            'Campanha de reforço em conscientização e inclusão do domínio na lista negra do DNS corporativo.'
        ),
        (
            1, 'INC-2026-0005',
            'Indisponibilidade Momentânea em Conector Secundário da RSFN durante Manutenção',
            '2026-01-22 01:10:00', '2026-01-22 01:11:00',
            'Indisponibilidade', 'Baixa', 'Roteador RSFN 02 (Secundário)',
            'Sem impacto nas operações ou transferências PIX, pois o conector primário absorveu o tráfego de imediato.',
            'Encerrado', 0, None,
            'Falha em placa de rede durante atualização programada de firmware.',
            'Substituição da placa defeituosa e rehomologação dos testes de chaveamento redundante.'
        )
    ]

    for inc in incidentes:
        cursor.execute("""
        INSERT INTO incidentes (
            instituicao_id, protocolo, titulo, data_ocorrencia, data_deteccao, categoria, criticidade,
            sistemas_afetados, impacto_operacional, status, notificado_bacen, data_notificacao_bacen,
            causa_raiz, acoes_corretivas
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, inc)

    conn.commit()

    # 12. Trilha de Auditoria
    audit_logs = [
        ('2026-02-15 09:30:00', 'auditoria.grc', 'SISTEMA_INICIALIZADO', 'instituicao', 1, 'Sistema GRC carregado com sucesso para a instituição configurada.'),
        ('2026-02-15 10:15:00', 'auditor.ciso', 'AUDITAR_REQUISITO', 'avaliacoes', req_map['REQ-5274-01'], 'Avaliação do controle 01 da Resolução CMN 5.274 confirmada como Atendido (MFA).'),
        ('2026-02-15 11:20:00', 'csirt.lead', 'REVISAR_PARI', 'pari_governanca', 1, 'Revisão das rotinas do PARI e playbooks operacionais de resposta a incidentes.'),
        ('2026-02-18 14:00:00', 'diretor.estatutario', 'EMITIR_RELATORIO', 'instituicao', 1, 'Geração do Relatório Anual do Art. 8º da Resolução CMN 4.893 (data-base 31/12/2025).')
    ]

    for log in audit_logs:
        cursor.execute("""
        INSERT INTO auditoria_log (data_hora, usuario, acao, entidade, entidade_id, detalhes)
        VALUES (?, ?, ?, ?, ?, ?);
        """, log)

    conn.commit()
    conn.close()
    print("Seed data loaded successfully with PARI and institution support!")

if __name__ == "__main__":
    seed()
