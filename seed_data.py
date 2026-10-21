"""
Seed data script for BACEN CMN 4.893 and CMN 5.274 GRC Compliance System.
Full multi-tenant seeding for Institution 1 (Alpha Bank - S3) and Institution 2 (Torra SCD - S4).
Includes complete PARI module, 14 controls of Res. 5.274, Pentest fragilidades, and Art. 8 annual report records.
"""
import sqlite3
import os
import hashlib
from datetime import datetime, date

DB_PATH = "/home/gustavo/.gemini/antigravity/scratch/bacen-grc-compliance/data/compliance.db"

def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Clear existing
    cursor.execute("DELETE FROM sessoes;")
    cursor.execute("DELETE FROM usuario_instituicoes;")
    cursor.execute("DELETE FROM usuarios;")
    cursor.execute("DELETE FROM auditoria_log;")
    cursor.execute("DELETE FROM auditorias_fragilidades;")
    cursor.execute("DELETE FROM relatorio_anual_parecer;")
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

    # 0. Usuários e RBAC (Least Privilege & MFA)
    from auth import hash_password, generate_mfa_secret

    salt_admin, hash_admin = hash_password("Admin@Bacen2026!")
    salt_gestor1, hash_gestor1 = hash_password("Gestor@2026!")
    salt_analista, hash_analista = hash_password("Analista@2026!")
    salt_auditor, hash_auditor = hash_password("Auditor@2026!")
    salt_gestor2, hash_gestor2 = hash_password("Gestor@Torra2026!")

    mfa_admin = "JBSWY3DPEHPK3PXP"
    mfa_gestor1 = "JBSWY3DPEHPK3PXQ"
    mfa_analista = "JBSWY3DPEHPK3PXR"
    mfa_auditor = "JBSWY3DPEHPK3PXS"
    mfa_gestor2 = "JBSWY3DPEHPK3PXT"

    cursor.execute("""
    INSERT INTO usuarios (id, nome, email, senha_hash, senha_salt, is_admin_geral, mfa_habilitado, mfa_secret, ativo, cargo)
    VALUES
    (1, 'Administrador Geral GRC', 'admin@bacen.local', ?, ?, 1, 1, ?, 1, 'Administrador da Plataforma GRC'),
    (2, 'Roberto Silveira Mello', 'gestor@alphabank.com.br', ?, ?, 0, 1, ?, 1, 'Diretor Executivo de Riscos / CISO'),
    (3, 'Felipe Albuquerque', 'analista@alphabank.com.br', ?, ?, 0, 1, ?, 1, 'Analista Sênior de Cibersegurança'),
    (4, 'Dr. Marcelo Nogueira', 'auditor@bacen.gov.br', ?, ?, 0, 1, ?, 1, 'Auditor Fiscal do Banco Central'),
    (5, 'Camila Ramos', 'gestor@torrascd.com.br', ?, ?, 0, 1, ?, 1, 'Gerente Executiva de Riscos & Compliance');
    """, (hash_admin, salt_admin, mfa_admin,
          hash_gestor1, salt_gestor1, mfa_gestor1,
          hash_analista, salt_analista, mfa_analista,
          hash_auditor, salt_auditor, mfa_auditor,
          hash_gestor2, salt_gestor2, mfa_gestor2))

    # Vínculos com as Instituições (Least Privilege Multi-Tenant)
    cursor.execute("""
    INSERT INTO usuario_instituicoes (usuario_id, instituicao_id, perfil)
    VALUES
    (2, 1, 'gestor'),    -- Roberto é gestor no Alpha Bank
    (3, 1, 'analista'),  -- Felipe é analista no Alpha Bank
    (3, 2, 'analista'),  -- Felipe também tem perfil analista na Torra SCD
    (4, 1, 'auditor'),   -- Dr. Marcelo (BACEN) é auditor no Alpha Bank
    (4, 2, 'auditor'),   -- Dr. Marcelo (BACEN) é auditor na Torra SCD
    (5, 2, 'gestor');    -- Camila é gestora na Torra SCD
    """)

    # 1. Instituições Financeiras Avaliadas
    cursor.execute("""
    INSERT INTO instituicao (
        id, razao_social, nome_fantasia, cnpj, segmento, tipo_instituicao, registro_unicad,
        diretor_responsavel, cargo_diretor, email_diretor, telefone_diretor,
        data_aprovacao_politica, data_ultima_revisao, versao_politica, escopo_operacional, is_ativa
    ) VALUES 
    (
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
    ),
    (
        2,
        'Torra Sociedade de Crédito Direto S.A.',
        'Torra SCD',
        '12.345.678/0001-90',
        'S4',
        'Sociedade de Crédito Direto (SCD)',
        'BACEN-UNICAD-4512',
        'Sílvio Cavalcanti',
        'Diretor de Cibersegurança e Operações (Art. 7º BACEN)',
        'silvio.cavalcanti@torrascd.com.br',
        '(11) 4004-9988',
        '2025-10-10',
        '2026-01-20',
        '2.1',
        'Instituição autorizada pelo BACEN no segmento S4 especializada em microcrédito digital, antecipação de recebíveis e liquidação via arranjo PIX.',
        0
    );
    """)

    # 2. Domínios Regulatórios
    dominios = [
        ('DOM-01', 'Governança & Política de Segurança Cibernética', 'Estrutura de governança corporativa, aprovação por Conselho e diretoria estatutária perante o BACEN.', 'Arts. 1º, 2º, 7º, 9º e 10', 'shield-check', 1),
        ('DOM-02', '14 Controles Mínimos Mandatórios (Resolução CMN 5.274)', 'Controles técnicos obrigatórios, prescritivos e auditáveis inseridos pela Resolução CMN 5.274 no Art. 3º.', 'Art. 3º (Res. CMN 5.274/2025)', 'lock', 2),
        ('DOM-03', 'Gestão, Resposta a Incidentes (PARI) & Compartilhamento', 'Plano de Ação e de Resposta a Incidentes, contenção, mitigação e comunicação ao Banco Central.', 'Arts. 4º, 5º, 6º e 8º', 'alert-triangle', 3),
        ('DOM-04', 'Testes de Intrusão, Pentests & Gestão de Vulnerabilidades', 'Rotinas periódicas de varreduras técnicas, testes de intrusão independentes e remediação.', 'Arts. 3º, 6º e 8º', 'target', 4),
        ('DOM-05', 'Contratação de Nuvem, Processamento & Notificação BACEN', 'Requisitos para contratação de serviços relevantes de TI/Nuvem no Brasil e exterior e cláusulas do Art. 17.', 'Arts. 11 a 17', 'cloud', 5),
        ('DOM-06', 'Continuidade de Negócios & Reversibilidade', 'Planos de contingência, continuidade operacional de serviços críticos e estratégia de saída de nuvem.', 'Arts. 18, 19 e 20', 'refresh-cw', 6),
        ('DOM-07', 'Relatório Anual do Diretor Responsável & Guarda de Documentos', 'Elaboração do relatório anual com data-base em 31/12, submissão ao Conselho e custódia por 5 anos.', 'Arts. 8º e 21', 'file-text', 7)
    ]

    for dom in dominios:
        cursor.execute("""
        INSERT INTO dominios (codigo, nome, descricao, artigo_referencia, icone, ordem)
        VALUES (?, ?, ?, ?, ?, ?);
        """, dom)

    cursor.execute("SELECT id, codigo FROM dominios;")
    dom_map = {row['codigo']: row['id'] for row in cursor.fetchall()}

    # 3. 32 Requisitos Regulatórios (Resoluções CMN 4.893 e 5.274)
    requisitos = [
        # DOM-01: Governança & Política
        (
            'REQ-01', dom_map['DOM-01'], 'Arts. 1º e 2º',
            'Implementação e Formalização da Política de Segurança Cibernética',
            'As instituições financeiras devem implementar e manter política de segurança cibernética com princípios e diretrizes para garantir a confidencialidade, integridade e disponibilidade.',
            'Documento aprovado pelo Conselho de Administração contemplando objetivos de segurança, autenticação, criptografia, prevenção e salvaguardas contra vazamentos.',
            0, None, 'Critica', 'Todos',
            'Política de Segurança Cibernética assinada; Ata de aprovação pelo Conselho de Administração; Registro de divulgação aos colaboradores.'
        ),
        (
            'REQ-02', dom_map['DOM-01'], 'Art. 7º',
            'Indicação Formal de Diretor Estatutário Responsável perante o BACEN',
            'A instituição deve indicar perante o Banco Central do Brasil diretor estatutário formalmente responsável pelo cumprimento das disposições da Resolução CMN nº 4.893/2021.',
            'Homologação cadastral no UNICAD/SISBACEN do Diretor Estatutário com poderes de governança e reporte direto ao Conselho.',
            0, None, 'Critica', 'Todos',
            'Ata de Eleição do Diretor Registrada na Junta Comercial; Certidão UNICAD/BACEN com indicação expressa da responsabilidade pelo Art. 7º.'
        ),
        (
            'REQ-03', dom_map['DOM-01'], 'Art. 9º',
            'Aprovação da Política pelo Conselho de Administração ou Diretoria',
            'A política de segurança cibernética e suas revisões devem ser aprovadas pelo conselho de administração ou pela diretoria da instituição.',
            'Deliberação colegiada formal registrada em ata arquivada com quórum qualificado.',
            0, None, 'Alta', 'Todos',
            'Ata formal de reunião do Conselho de Administração ou Diretoria Executiva.'
        ),
        (
            'REQ-04', dom_map['DOM-01'], 'Art. 10',
            'Revisão Periódica da Política de Cibersegurança (Ciclo Anual)',
            'A política de segurança cibernética deve ser revisada, no mínimo, a cada 12 (doze) meses, ou sempre que ocorrerem mudanças relevantes na infraestrutura.',
            'Fluxo anual documentado de revisão, validação de adequação frente a novas ameaças e aprovação de nova versão pelo Conselho.',
            0, None, 'Alta', 'Todos',
            'Histórico de versionamento da política; Parecer anual de conformidade emitido pela área de GRC/Compliance.'
        ),
        (
            'REQ-05', dom_map['DOM-01'], 'Art. 2º, §2º',
            'Divulgação Interna e Externa da Política de Segurança Cibernética',
            'A instituição deve assegurar a divulgação da política aos colaboradores e manter resumo público acessível aos clientes e usuários.',
            'Publicação na intranet, termos de ciência no onboarding de funcionários e disponibilização de resumo executivo no site institucional.',
            0, None, 'Media', 'Todos',
            'Link público do resumo no portal institucional; Termos de aceite dos colaboradores no sistema de gestão de RH.'
        ),

        # DOM-02: 14 Controles Mandatórios da Resolução CMN 5.274/2025
        (
            'REQ-5274-01', dom_map['DOM-02'], 'Art. 3º, §2º, I (Res. 5.274)',
            'Controle 01/14: Mecanismos de Autenticação Multifator (MFA)',
            'Adoção de autenticação multifator para acesso a redes, sistemas corporativos, ambientes em nuvem e privilégios administrativos.',
            'Obrigatoriedade de pelo menos dois fatores de autenticação distintos (conhecimento, posse ou biometria) para 100% dos acessos privilegiados e acessos remotos.',
            1, 1, 'Critica', 'Todos',
            'Configuração de IdP/IAM corporativo; Relatório de cobertura de MFA em estações, servidores e consoles de nuvem; Políticas de Conditional Access.'
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
            'Controle 12/14: Monitoramento Contínuo e Inteligência de Ameaças',
            'Monitoramento 24x7 de eventos de segurança da informação e consumo de fontes qualificadas de inteligência de ameaças (Threat Intelligence).',
            'SOC com escala 24x7x365, ingestão de IoCs (Indicators of Compromise), monitoramento proativo de vazamentos de credenciais corporativas na Dark Web e fóruns cibernéticos.',
            1, 12, 'Alta', 'Todos',
            'Contrato/SLA com serviço de SOC/SIEM 24x7; Relatórios periódicos de Threat Intelligence; Registro de feeds de IoC integrados.'
        ),
        (
            'REQ-5274-13', dom_map['DOM-02'], 'Art. 3º, §2º, XIII (Res. 5.274)',
            'Controle 13/14: Segurança na Rede do Sistema Financeiro Nacional (RSFN)',
            'Controles específicos de proteção e isolamento lógico para as conexões com a RSFN, mensageria SPB, PIX e serviços do Sistema de Pagamentos Brasileiro.',
            'Segmentação física ou lógica da RSFN, uso de certificados digitais ICP-Brasil padrão BACEN, proteção perimetral com regras restritas e redundância de circuitos de telecom.',
            1, 13, 'Critica', 'Todos',
            'Diagrama de interconexão RSFN; Configuração de roteadores e firewalls dedicados ao SPB/PIX; Certificados digitais da RSFN válidos.'
        ),
        (
            'REQ-5274-14', dom_map['DOM-02'], 'Art. 3º, §2º, XIV (Res. 5.274)',
            'Controle 14/14: Segurança no Desenvolvimento de Software (DevSecOps)',
            'Adoção de práticas de desenvolvimento seguro no ciclo de vida de softwares e APIs, incluindo análises de vulnerabilidades em código-fonte e dependências.',
            'Integração de testes SAST, DAST e SCA nas esteiras de CI/CD, revisão de segurança com base no OWASP Top 10 e conformidade de segurança para APIs do Open Finance.',
            1, 14, 'Alta', 'Todos',
            'Diretrizes de Secure Coding OWASP; Relatórios de análise SAST/DAST emitidos na esteira CI/CD; Atas de aprovação de segurança pré-deploy.'
        ),

        # DOM-03: PARI & Resposta a Incidentes
        (
            'REQ-PARI-01', dom_map['DOM-03'], 'Arts. 4º e 5º',
            'Elaboração e Manutenção do Plano de Ação e de Resposta a Incidentes (PARI)',
            'A instituição deve elaborar e manter plano de ação e de resposta a incidentes contendo ações para prevenção, detecção, contenção, erradicação e recuperação de incidentes cibernéticos.',
            'PARI formalizado contendo equipe de CSIRT estabelecida, papéis e responsabilidades, canais de escalonamento e playbooks técnicos para diferentes cenários de ataque.',
            0, None, 'Critica', 'Todos',
            'Documento formal do PARI aprovado; Portaria ou ata de designação dos membros do CSIRT; Playbooks operacionais de resposta a incidentes.'
        ),
        (
            'REQ-PARI-02', dom_map['DOM-03'], 'Art. 6º',
            'Comunicação de Incidentes Relevantes ao Banco Central do Brasil',
            'A instituição deve comunicar formalmente ao Banco Central do Brasil os incidentes relevantes no prazo estabelecido na regulamentação, detalhando causas e impactos.',
            'Procedimento operacional padrão (POP) de comunicação via SISBACEN / Protocolo Digital em até 24 horas após caracterização de relevância, com modelo de relatório preliminar.',
            0, None, 'Critica', 'Todos',
            'Procedimento documentado de notificação de incidentes ao BACEN; Histórico de notificações no Sisbacen ou termo de inocorrência.'
        ),
        (
            'REQ-PARI-03', dom_map['DOM-03'], 'Art. 5º, §2º',
            'Compartilhamento de Informações sobre Incidentes Relevantes',
            'Mecanismos de compartilhamento tempestivo de informações sobre incidentes relevantes e vulnerabilidades com outras instituições financeiras e o BACEN.',
            'Adesão e integração formal ao Cyber Hub Febraban ou rede setorial de compartilhamento de indicadores de comprometimento (IoCs).',
            0, None, 'Media', 'Todos',
            'Comprovante de filiação à rede de compartilhamento setorial (Febraban/Anbima); Registro de intercâmbio de IoCs.'
        ),

        # DOM-04: Testes de Intrusão & Pentests
        (
            'REQ-TEST-01', dom_map['DOM-04'], 'Art. 3º, IV',
            'Execução Periódica de Testes de Intrusão (Pentests) Independentes',
            'Realização periódica de testes de intrusão nos sistemas e aplicações críticas por equipe ou consultoria externa independente da equipe de desenvolvimento e operação.',
            'Pentests anuais (ou semestrais para S1/S2/S3) abrangendo aplicações móveis, web banking, APIs e infraestrutura de perímetro, com metodologia OSSTMM/OWASP.',
            0, None, 'Critica', 'Todos',
            'Relatório Executivo e Técnico de Teste de Intrusão emitido por terceira parte; Atestado de independência da consultoria executora.'
        ),
        (
            'REQ-TEST-02', dom_map['DOM-04'], 'Art. 8º',
            'Comprovação da Efetividade e Remediação dos Testes de Segurança',
            'Documentação do acompanhamento da remediação das falhas identificadas nos testes de intrusão e testes de vulnerabilidade.',
            'Testes de revalidação (Retest) para todas as vulnerabilidades Críticas e Altas apontadas no relatório de intrusão, com assinatura de encerramento pelo CISO.',
            0, None, 'Alta', 'Todos',
            'Relatório de Reteste de Intrusão comprovando mitigação; Planilha de acompanhamento com datas e responsáveis.'
        ),

        # DOM-05: Contratação de Serviços de Nuvem
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

    # 4. Avaliações Iniciais para Instituição 1 (Alpha Bank - S3)
    avaliacoes_inst1 = [
        (1, req_map['REQ-01'], 'atendido', 100, 'Política de Cibersegurança revisada e aprovada pelo Conselho.', 'Governança Corporativa', '2025-11-25', '2026-02-10', 'Auditoria Interna', 'Total conformidade com o Art. 2º.'),
        (1, req_map['REQ-02'], 'atendido', 100, 'Diretor Estatutário homologado formalmente no Unicad BACEN.', 'Jurídico Corporativo', '2025-05-10', '2026-01-15', 'Compliance & Risco', 'Registro checado no Sisbacen.'),
        (1, req_map['REQ-03'], 'atendido', 100, 'Aprovação unânime em reunião ordinária do Conselho.', 'Secretaria de Governança', '2025-11-25', '2026-02-10', 'Auditoria Interna', 'Ata arquivada e registrada.'),
        (1, req_map['REQ-04'], 'atendido', 100, 'Revisão anual ciclo 2025/2026 finalizada e documentada.', 'CISO Office', '2026-02-15', '2026-02-15', 'Auditoria Interna', 'Próxima revisão agendada para fev/2027.'),
        (1, req_map['REQ-05'], 'atendido', 100, 'Resumo executivo publicado no portal web oficial.', 'Comunicação & CISO', '2025-12-01', '2026-02-10', 'Compliance', 'Página web ativa.'),
        (1, req_map['REQ-5274-01'], 'atendido', 100, 'MFA baseado em FIDO2 e app TOTP habilitado para 100% dos usuários.', 'Equipe de IAM', '2026-01-10', '2026-02-20', 'Auditoria Externa TI', 'MFA mandatório em AD e AWS SSO.'),
        (1, req_map['REQ-5274-02'], 'atendido', 100, 'Criptografia AES-256 e TLS 1.3 obrigatório em todas as conexões.', 'Infraestrutura Cloud', '2025-10-15', '2026-02-18', 'Auditoria Externa TI', 'Chaves gerenciadas em AWS KMS e HSM.'),
        (1, req_map['REQ-5274-03'], 'atendido', 100, 'Solução EDR instalada em 100% dos endpoints e servidores.', 'SOC & Operações', '2025-09-30', '2026-02-12', 'Auditoria Interna', 'Alertas monitorados 24x7 pelo SOC.'),
        (1, req_map['REQ-5274-04'], 'parcialmente_atendido', 65, 'DLP implementado para e-mails institucionais e endpoints.', 'Segurança da Informação', '2026-03-31', '2026-02-05', 'Auditoria Interna', 'Plano de ação em andamento para cobrir Git.'),
        (1, req_map['REQ-5274-05'], 'atendido', 100, 'Antimalware corporativo com motor heurístico ativo.', 'Operações de TI', '2025-08-20', '2026-01-20', 'Auditoria Interna', 'Taxa de cobertura 100%.'),
        (1, req_map['REQ-5274-06'], 'atendido', 100, 'Logs centralizados em SIEM com NTP sincronizado ao Observatório Nacional.', 'Engenharia de Segurança', '2025-11-05', '2026-02-14', 'Auditoria Externa TI', 'Retenção configurada para 5 anos com hash SHA-256.'),
        (1, req_map['REQ-5274-07'], 'atendido', 100, 'Backups diários com repositórios imutáveis (Object Lock).', 'Infraestrutura & DBA', '2026-01-15', '2026-02-15', 'Auditoria Interna', 'RTO obtido: 2h35m; RPO obtido: 12 min.'),
        (1, req_map['REQ-5274-08'], 'parcialmente_atendido', 75, 'Scans semanais de vulnerabilidades ativos com SLA de remediação.', 'Vulnerability Management', '2026-03-15', '2026-02-10', 'Auditoria Interna', '92% de cumprimento do SLA.'),
        (1, req_map['REQ-5274-09'], 'atendido', 100, 'Hardening baseado no CIS Benchmark aplicado em todas as Golden Images.', 'DevSecOps', '2025-12-10', '2026-02-08', 'Auditoria Interna', 'Conformidade de configuração aferida em 98.4%.'),
        (1, req_map['REQ-5274-10'], 'atendido', 100, 'Microssegmentação via VPC e Security Groups; DMZ e WAF ativo.', 'Redes e Segurança', '2025-10-01', '2026-01-30', 'Auditoria Externa TI', 'Tráfego leste-oeste estritamente restrito.'),
        (1, req_map['REQ-5274-11'], 'em_implementacao', 50, 'Inventário de certificados criado, automação via Cert-Manager em curso.', 'Infraestrutura Cloud', '2026-03-31', '2026-02-01', 'Auditoria Interna', 'Exigência da Resolução 5.274 em fase final.'),
        (1, req_map['REQ-5274-12'], 'em_implementacao', 40, 'Contratação de provedor de Threat Intelligence em homologação contratual.', 'CISO Office', '2026-04-15', '2026-02-05', 'Auditoria Interna', 'Novo requisito formal da Resolução CMN 5.274/2025.'),
        (1, req_map['REQ-5274-13'], 'atendido', 100, 'Comunicação na RSFN operando com mTLS e certificados ICP-Brasil específicos.', 'Telecom & Conectividade BACEN', '2025-07-22', '2026-02-11', 'BACEN Fiscalização', 'Homologação oficial BACEN para PIX e SPB regular.'),
        (1, req_map['REQ-5274-14'], 'parcialmente_atendido', 70, 'SAST e SCA integrados no pipeline GitLab CI.', 'DevSecOps', '2026-03-30', '2026-02-09', 'Auditoria Interna', 'APIs do Open Finance 100% aderentes ao perfil FAPI 1.0.'),
        (1, req_map['REQ-PARI-01'], 'atendido', 100, 'PARI formalizado com playbooks operacionais e CSIRT 24x7.', 'CSIRT Lead', '2025-11-15', '2026-02-10', 'Auditoria Interna', 'Simulado de mesa realizado em nov/2025.'),
        (1, req_map['REQ-PARI-02'], 'atendido', 100, 'Procedimento operacional de comunicação ao BACEN via Sisbacen.', 'Compliance Regulatório', '2025-10-10', '2026-01-20', 'Compliance', 'Nenhum incidente crítico no período.'),
        (1, req_map['REQ-PARI-03'], 'atendido', 100, 'Filiada ao Cyber Hub Febraban com compartilhamento de IoCs.', 'Threat Intelligence', '2025-06-01', '2026-02-01', 'Auditoria Interna', 'Feed de IoCs integrado diretamente ao firewall/SIEM.'),
        (1, req_map['REQ-TEST-01'], 'atendido', 100, 'Pentest executado por empresa independente cobrindo Mobile, Web e PIX.', 'CISO Office', '2025-10-30', '2026-01-10', 'Auditoria Externa', 'Relatório e atestado de independência emitidos.'),
        (1, req_map['REQ-TEST-02'], 'atendido', 100, 'Reteste realizado confirmando mitigação das 2 falhas apontadas.', 'Equipe de Aplicações', '2025-12-15', '2026-01-15', 'Auditoria Externa', 'Termo de encerramento emitido.'),
        (1, req_map['REQ-CLOUD-01'], 'atendido', 100, 'Due Diligence anual concluída para AWS e Microsoft Azure.', 'Gestão de Terceiros (TPRM)', '2025-09-15', '2026-02-12', 'Auditoria Interna', 'Classificação de risco residual baixo.'),
        (1, req_map['REQ-CLOUD-02'], 'atendido', 100, 'Contratações e aditivos relevantes em nuvem comunicados ao BACEN com antecedência de 60 dias.', 'Regulatório & Jurídico', '2025-08-01', '2026-01-18', 'Auditoria Interna', 'Protocolos do Sisbacen arquivados.'),
        (1, req_map['REQ-CLOUD-03'], 'atendido', 100, 'Dados armazenados nos EUA e Brasil. Convênio formal BACEN-FED verificado.', 'Jurídico Regulatório', '2025-08-01', '2026-01-18', 'Auditoria Interna', 'Parecer jurídico atestando existência de convênio.'),
        (1, req_map['REQ-CLOUD-04'], 'atendido', 100, 'Todos os contratos de nuvem contêm as cláusulas mandatórias do Art. 17.', 'Jurídico Contratos', '2025-10-20', '2026-02-10', 'Auditoria Externa', 'Cláusulas de acesso BACEN e segregação lógica checadas.'),
        (1, req_map['REQ-CONT-01'], 'atendido', 100, 'Plano de Continuidade e DR testado com failover simulado.', 'Continuidade de Negócios (BCM)', '2025-11-28', '2026-02-15', 'Auditoria Interna', 'RTO de recuperação: 48 minutos.'),
        (1, req_map['REQ-CONT-02'], 'parcialmente_atendido', 60, 'Plano de saída documentado para IaaS; detalhamento de SaaS CRM em andamento.', 'Arquitetura Corporativa', '2026-04-30', '2026-01-25', 'Auditoria Interna', 'Gap apontado pela auditoria em remediação.'),
        (1, req_map['REQ-AUD-01'], 'atendido', 100, 'Relatório anual com data-base 31/12/2025 aprovado pelo Conselho.', 'Diretor Estatutário CISO', '2026-02-15', '2026-02-18', 'Conselho de Administração', 'Relatório completo disponível no sistema.'),
        (1, req_map['REQ-AUD-02'], 'atendido', 100, 'Repositório digital com controle de acesso e retenção por 5 anos.', 'Compliance & Arquivo', '2026-02-15', '2026-02-18', 'Auditoria Interna', 'Evidências catalogadas e auditadas.')
    ]

    for a in avaliacoes_inst1:
        cursor.execute("""
        INSERT INTO avaliacoes (
            instituicao_id, requisito_id, status, percentual_aderencia, justificativa, responsavel,
            prazo_adequacao, ultima_auditoria, avaliador, observacoes_auditor
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, a)

    # 4b. Avaliações Iniciais para Instituição 2 (Torra SCD - S4)
    avaliacoes_inst2 = [
        (2, req_map['REQ-01'], 'atendido', 100, 'Política de Cibersegurança simplificada e aderente ao segmento S4 aprovada pela Diretoria.', 'Compliance Torra', '2025-10-10', '2026-01-15', 'Auditoria Interna', 'Aderente ao Art. 2º.'),
        (2, req_map['REQ-02'], 'atendido', 100, 'Diretor de Operações formalmente homologado no Unicad BACEN sob nº BACEN-UNICAD-4512.', 'Jurídico Torra', '2025-06-15', '2026-01-10', 'Compliance', 'Homologação confirmada.'),
        (2, req_map['REQ-03'], 'atendido', 100, 'Aprovação por deliberação da Diretoria Executiva em ata registrada.', 'Secretaria Executiva', '2025-10-10', '2026-01-15', 'Auditoria Interna', 'Ata registrada.'),
        (2, req_map['REQ-04'], 'atendido', 100, 'Revisão anual ciclo 2025/2026 efetuada em janeiro de 2026.', 'Equipe de Segurança', '2026-01-20', '2026-01-20', 'Auditoria Interna', 'Revisão arquivada.'),
        (2, req_map['REQ-05'], 'atendido', 100, 'Resumo da política disponibilizado na área institucional do app Torra Crédito.', 'Comunicação', '2025-11-01', '2026-01-15', 'Compliance', 'Disponível no app.'),
        (2, req_map['REQ-5274-01'], 'atendido', 100, 'MFA obrigatório via Google Authenticator para todos os operadores de crédito e DevOps.', 'SecOps Torra', '2025-11-20', '2026-01-18', 'Auditoria Interna', '100% de adesão nos acessos internos.'),
        (2, req_map['REQ-5274-02'], 'atendido', 100, 'Criptografia de ponta a ponta TLS 1.3 e banco de dados Postgres criptografado em repouso.', 'Engenharia de Software', '2025-09-10', '2026-01-12', 'Auditoria Interna', 'KMS AWS ativo.'),
        (2, req_map['REQ-5274-03'], 'atendido', 100, 'Agentes EDR implantados em todas as instâncias de microsserviços e estações.', 'SecOps Torra', '2025-10-05', '2026-01-14', 'Auditoria Interna', 'Integração com Datadog Security.'),
        (2, req_map['REQ-5274-04'], 'parcialmente_atendido', 55, 'DLP configurado no Google Workspace corporativo. Bloqueio em endpoints ainda em implantação.', 'Segurança da Informação', '2026-05-15', '2026-01-10', 'Auditoria Interna', 'Ação 5W2H em andamento.'),
        (2, req_map['REQ-5274-05'], 'atendido', 100, 'Antivírus corporativo gerenciado em nuvem com isolamento automatizado.', 'Suporte TI', '2025-08-15', '2026-01-10', 'Auditoria Interna', 'Endpoints cobertos.'),
        (2, req_map['REQ-5274-06'], 'atendido', 100, 'Centralização de logs em bucket S3 com Object Lock e NTP sincronizado.', 'DevSecOps Torra', '2025-10-25', '2026-01-19', 'Auditoria Interna', 'Retenção por 5 anos garantida.'),
        (2, req_map['REQ-5274-07'], 'atendido', 100, 'Rotina diária de snapshots de banco de dados com replicação multi-região.', 'DBA Torra', '2025-12-01', '2026-01-15', 'Auditoria Interna', 'Último teste de restore: 15/12/2025.'),
        (2, req_map['REQ-5274-08'], 'parcialmente_atendido', 60, 'Scans mensais de vulnerabilidades executados; remediação de falhas médias com prazo estendido.', 'SecOps Torra', '2026-04-10', '2026-01-12', 'Auditoria Interna', 'Necessidade de automação de patch.'),
        (2, req_map['REQ-5274-09'], 'atendido', 100, 'Imagens Docker baseadas em distroless e CIS Benchmark para contêineres.', 'DevSecOps', '2025-11-15', '2026-01-16', 'Auditoria Interna', 'Scans no pipeline de deploy.'),
        (2, req_map['REQ-5274-10'], 'atendido', 100, 'Isolamento de VPC e firewalls Cloudflare WAF ativos na API pública.', 'Redes e Cloud', '2025-09-01', '2026-01-15', 'Auditoria Interna', 'Ambientes segregados.'),
        (2, req_map['REQ-5274-11'], 'atendido', 100, 'Certificados TLS 1.3 automatizados via Let''s Encrypt e mTLS no conector SPI.', 'Infraestrutura Cloud', '2025-11-10', '2026-01-18', 'Auditoria Interna', 'Validade monitorada por robô.'),
        (2, req_map['REQ-5274-12'], 'em_implementacao', 35, 'Estruturação de processo de Threat Intelligence e acompanhamento de canais de fraude.', 'Risco Operacional', '2026-05-30', '2026-01-10', 'Auditoria Interna', 'Em contratação de ferramenta.'),
        (2, req_map['REQ-5274-13'], 'atendido', 100, 'Conector Pix via participante direto (PST) homologado perante o BACEN.', 'Telecom & Pix', '2025-08-20', '2026-01-15', 'Auditoria Interna', 'Canal criptografado seguro.'),
        (2, req_map['REQ-5274-14'], 'parcialmente_atendido', 60, 'Análise estática (SAST) integrada ao GitHub Actions. DAST em fase piloto.', 'DevSecOps', '2026-04-30', '2026-01-10', 'Auditoria Interna', 'Ajustando thresholds de bloqueio.'),
        (2, req_map['REQ-PARI-01'], 'atendido', 100, 'PARI aprovado para instituição S4 contendo fluxos essenciais de contenção.', 'Líder CSIRT Torra', '2025-10-15', '2026-01-15', 'Auditoria Interna', 'Playbooks básicos validados.'),
        (2, req_map['REQ-PARI-02'], 'atendido', 100, 'Procedimento de comunicação ao BACEN no Sisbacen formalizado.', 'Compliance Torra', '2025-10-15', '2026-01-15', 'Compliance', 'Prazos alinhados ao Art. 6º.'),
        (2, req_map['REQ-PARI-03'], 'parcialmente_atendido', 50, 'Processo de filiação ao grupo setorial de cibersegurança da ABFintechs em curso.', 'Relações Institucionais', '2026-04-15', '2026-01-10', 'Auditoria Interna', 'Fase final de associação.'),
        (2, req_map['REQ-TEST-01'], 'atendido', 100, 'Pentest anual na API de concessão de crédito realizado por terceira parte.', 'CISO Office', '2025-09-30', '2026-01-12', 'Auditoria Externa', 'Laudo técnico conclusivo emitido.'),
        (2, req_map['REQ-TEST-02'], 'atendido', 100, 'Reteste realizado comprovando correção da fragilidade de média severidade.', 'Desenvolvimento', '2025-11-20', '2026-01-12', 'Auditoria Externa', 'Vulnerabilidade sanada.'),
        (2, req_map['REQ-CLOUD-01'], 'atendido', 100, 'Due Diligence prévia realizada para AWS e Datadog.', 'Gestão de Fornecedores', '2025-07-20', '2026-01-10', 'Auditoria Interna', 'Relatórios SOC 2 analisados.'),
        (2, req_map['REQ-CLOUD-02'], 'atendido', 100, 'Notificação prévia de 60 dias ao BACEN protocolada via Sisbacen.', 'Jurídico Torra', '2025-06-01', '2026-01-10', 'Auditoria Interna', 'Protocolo regular.'),
        (2, req_map['REQ-CLOUD-03'], 'atendido', 100, 'Serviços de nuvem em região Brasil (São Paulo).', 'Infraestrutura Cloud', '2025-06-01', '2026-01-10', 'Auditoria Interna', 'Processamento local.'),
        (2, req_map['REQ-CLOUD-04'], 'atendido', 100, 'Contratos de processamento e nuvem com cláusulas do Art. 17.', 'Jurídico Torra', '2025-08-10', '2026-01-10', 'Auditoria Interna', 'Cláusulas de acesso BACEN ativas.'),
        (2, req_map['REQ-CONT-01'], 'atendido', 100, 'Plano de Continuidade Operacional e DR testado para a esteira de crédito.', 'Continuidade de Negócios', '2025-11-05', '2026-01-14', 'Auditoria Interna', 'RTO atingido: 35 min.'),
        (2, req_map['REQ-CONT-02'], 'em_implementacao', 45, 'Documentação do plano de reversibilidade e portabilidade de dados de crédito.', 'Arquitetura de Soluções', '2026-05-30', '2026-01-10', 'Auditoria Interna', 'Elaboração do plano em andamento.'),
        (2, req_map['REQ-AUD-01'], 'atendido', 100, 'Relatório anual com data-base 31/12/2025 em elaboração e revisão executiva.', 'Diretor de Cibersegurança', '2026-01-20', '2026-01-20', 'Diretoria', 'Em processo de emissão de parecer.'),
        (2, req_map['REQ-AUD-02'], 'atendido', 100, 'Repositório de evidências mantido com trilha de integridade para 5 anos.', 'Compliance Torra', '2026-01-20', '2026-01-20', 'Auditoria Interna', 'Guarda regulatória assegurada.')
    ]

    for a in avaliacoes_inst2:
        cursor.execute("""
        INSERT INTO avaliacoes (
            instituicao_id, requisito_id, status, percentual_aderencia, justificativa, responsavel,
            prazo_adequacao, ultima_auditoria, avaliador, observacoes_auditor
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, a)

    conn.commit()

    # 5. MÓDULO PARI: Governança do CSIRT (Inst 1 e Inst 2)
    cursor.execute("""
    INSERT INTO pari_governanca (
        instituicao_id, lider_csirt, email_csirt, telefone_plantao_247, membros_csirt,
        comite_crise, canais_emergencia, criterios_relevancia_bacen, procedimento_sisbacen,
        data_ultima_revisao_pari, versao_pari
    ) VALUES 
    (
        1,
        'Eng. Marcos Vinícius Ferreira',
        'csirt@alphabank.com.br',
        '(11) 98765-4321 (Plantão 24x7)',
        'Líder CSIRT (Coordenação), Analista Sênior SOC (Triagem), Engenheiro de Redes & Firewall, Especialista Forense, DBA Líder, Encarregado DPO.',
        'Diretor Estatutário Responsável (Art. 7º), Diretor Presidente (CEO), CISO Corporativo, Diretor Jurídico / DPO e Assessor Chefe de Comunicação.',
        'Canal de voz criptografado dedicado (out-of-band), sala de guerra física isolada e e-mails de contingência.',
        'Critérios BACEN: (1) Indisponibilidade de serviços essenciais (PIX, TED, SPB) > 2h; (2) Exfiltração de dados protegidos por sigilo bancário; (3) Fraudes cibernéticas relevantes ou contaminação sistêmica.',
        'Notificação compulsória em até 24 horas via módulo de Risco Operacional no Sisbacen / Protocolo Digital BACEN com relatório preliminar.',
        '2026-02-15',
        '2.4'
    ),
    (
        2,
        'Camila Ramos',
        'csirt@torrascd.com.br',
        '(11) 99888-7766 (Plantão 24x7)',
        'Líder CSIRT (Camila Ramos), Especialista SecOps (Felipe Albuquerque), Engenheiro Cloud e Advogada Especialista em LGPD.',
        'Diretor Estatutário (Sílvio Cavalcanti), Gerente de Riscos, Gerente de TI e Consultoria Jurídica Externa.',
        'Grupo corporativo fechado com criptografia ponto a ponto e linha telefônica redundante de emergência.',
        'Critérios BACEN: Indisponibilidade de emissão de crédito/Pix > 2h ou vazamento cadastral sensível de mutuários.',
        'Comunicação em até 24h via Sisbacen acompanhada de relatório preliminar e plano de contenção.',
        '2026-01-20',
        '1.8'
    );
    """)

    # 6. MÓDULO PARI: Playbooks Operacionais (Inst 1 e Inst 2)
    playbooks = [
        # Inst 1
        (
            1, 'PB-01', 'Ataque de Ransomware e Sequestro de Ativos', 'Ransomware',
            'Identificação de telemetria anômala no EDR (criptografia em massa de arquivos, chamadas vssadmin). Alertas imediatos no SOC nível P1.',
            'Isolamento imediato de rede das máquinas afetadas via console EDR; desconexão de túneis VPN e bloqueio de portas SMB nas VLANs.',
            'Identificação do vetor inicial (phishing, RDP exposto); quarentena de contas comprometidas; revogação de tokens de autenticação.',
            'Validação de integridade dos backups imutáveis; restauração de servidores a partir de repositório WORM; revalidação de regras de firewall.',
            'Se houver indisponibilidade superior a 2 horas ou vazamento de dados, acionamento do Diretor Estatutário para comunicação imediata no SISBACEN.',
            'Contenção em até 15 minutos; Restauração completa em até 4 horas (RTO).'
        ),
        (
            1, 'PB-02', 'Vazamento ou Exfiltração de Dados Bancários e Pessoais (LGPD)', 'Vazamento de Dados',
            'Disparo de alertas de DLP corporativo indicando transferência volumosa atípica de dados sigilosos; alertas de Threat Intelligence na Dark Web.',
            'Revogação imediata de credenciais de acesso do usuário/serviço suspeito; bloqueio de IPs de destino e encerramento forçado de sessões ativas.',
            'Análise forense das trilhas de auditoria e logs do SIEM para determinar o escopo exato dos dados acessados.',
            'Correção e fechamento da brecha técnica ou vulnerabilidade de API explorada; reemissão forçada de senhas.',
            'Notificação simultânea ao Banco Central do Brasil (SISBACEN) e à ANPD em até 24h úteis.',
            'Identificação do escopo em 2 horas; Parecer executivo preliminar em 12 horas.'
        ),
        (
            1, 'PB-03', 'Ataque de Negação de Serviço Distribuída (DDoS) no PIX e Internet Banking', 'DDoS',
            'Monitoramento de saturação de banda e aumento exponencial de requisições HTTP/SYN flood na borda da rede.',
            'Ativação imediata de proteção de mitigação DDoS em nuvem; redirecionamento de DNS e desafio de mitigação.',
            'Análise das assinaturas do tráfego malicioso e criação de regras de rate limiting e bloqueio geográfico no WAF.',
            'Rebalanceamento de carga e retorno gradual do tráfego limpo; monitoramento contínuo de estabilidade das transações PIX.',
            'Comunicação ao Deban/BACEN se houver oscilação de conectividade no canal do PIX.',
            'Ativação de mitigação em menos de 5 minutos; Estabilização em até 20 minutos.'
        ),
        (
            1, 'PB-04', 'Indisponibilidade ou Falha em Nuvem Crítica (Failover & DR)', 'Nuvem',
            'Alerta automático do sistema de observabilidade apontando interrupção total na região primária da AWS.',
            'Acionamento do procedimento de Disaster Recovery (DR); congelamento de transações em trânsito no banco primário.',
            'Chaveamento de tráfego (failover DNS via Route 53) para a região secundária na Microsoft Azure.',
            'Restauração das esteiras de microsserviços na região de contingência; checagem de consistência de saldos.',
            'Notificação formal ao BACEN sobre acionamento de contingência em nuvem conforme previsto no Art. 19.',
            'RTO operacional de chaveamento: até 45 minutos; RPO de dados: até 15 minutos.'
        ),
        (
            1, 'PB-05', 'Indisponibilidade ou Falha de Conectividade na RSFN / SPB', 'RSFN',
            'Perda de sincronismo no roteador principal da Rede do Sistema Financeiro Nacional (RSFN); falha no envio de mensagens STR/PIX.',
            'Chaveamento automático para o canal redundante e circuito secundário de telecomunicação da RSFN.',
            'Diagnóstico físico e lógico da interface serial/fibra com a operadora de telecomunicações credenciada.',
            'Reenvio seguro das mensagens pendentes com validação de certificados ICP-Brasil SPB e conferência de protocolo.',
            'Contato imediato com o suporte operacional da RSFN / Banco Central do Brasil para sincronização dos lotes.',
            'Chaveamento para canal redundante em até 2 minutos.'
        ),
        # Inst 2 (Torra SCD)
        (
            2, 'PB-SCD-01', 'Ataque de Ransomware em Ambiente de Microcrédito', 'Ransomware',
            'Telemetria do EDR detecta atividade de criptografia em volumes EBS de microsserviços.',
            'Isolamento imediato das instâncias afetadas via Security Group e desligamento forçado.',
            'Identificação da chave de acesso vazada e revogação das credenciais IAM na AWS.',
            'Restauração a partir de snapshots EBS imutáveis com retenção garantida.',
            'Comunicação ao Diretor Estatutário para envio de notificação no Sisbacen se houver impacto operacional.',
            'Contenção em 20 minutos; Recuperação em até 2 horas.'
        ),
        (
            2, 'PB-SCD-02', 'Indisponibilidade na Liquidação de Recebíveis PIX', 'Indisponibilidade',
            'Falha de webhook e timeouts sucessivos com o Participante Direto liquidante do arranjo Pix.',
            'Acionamento da fila de contingência assíncrona para reprocessamento das ordens de crédito.',
            'Contato imediato com o NOC do banco liquidante para chaveamento de rota.',
            'Reprocessamento ordenado das transações pendentes após reativação do canal.',
            'Registro interno de incidente operacional e envio de relatório se a indisponibilidade ultrapassar 2 horas.',
            'Comutação de fila em 5 minutos; Sincronização em até 30 minutos.'
        ),
        (
            2, 'PB-SCD-03', 'Exposição de Credenciais de API de Parceiros Financeiros', 'Vazamento de Dados',
            'Detecção de credencial de API exposta publicamente ou alerta de monitoramento externo.',
            'Revogação imediata da API Key no API Gateway da AWS e invalidação de refresh tokens ativos.',
            'Auditoria de chamadas nos logs do CloudTrail para verificar uso indevido das chaves expostas.',
            'Geração e entrega de nova chave ao parceiro por canal seguro com autenticação de duplo fator.',
            'Notificação de segurança ao parceiro e avaliação de reporte regulatório ao BACEN.',
            'Revogação da chave em menos de 10 minutos.'
        ),
        (
            2, 'PB-SCD-04', 'Tentativa de Engenharia Social contra Operadores de Crédito', 'Engenharia Social',
            'Relato de colaborador de tentativa de spear phishing via WhatsApp corporativo solicitando liberação de limite.',
            'Bloqueio preventivo do usuário alvo e suspensão de alçadas de aprovação temporariamente.',
            'Verificação de ausência de acessos indevidos e validação de autenticidade dos dados bancários.',
            'Desbloqueio de acesso após confirmação biométrica e emissão de alerta interno de conscientização.',
            'Registro na base de incidentes preventivos do CSIRT.',
            'Bloqueio em até 10 minutos; Investigação preliminar em 1 hora.'
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
        # Inst 1
        (
            1,
            'Simulado de Mesa 2025: Cenário de Ransomware com Tentativa de Dupla Extorsão',
            '2025-11-20',
            'Simulação de infecção por ransomware atingindo servidores de arquivos e tentativa de exfiltração de dados cadastrais, com teste de tomada de decisão da Diretoria.',
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
        ),
        # Inst 2
        (
            2,
            'Simulado de Continuidade: Indisponibilidade de Nuvem e Failover Multi-Region',
            '2025-11-05',
            'Simulação de degradação massiva na zona de disponibilidade AWS sa-east-1a com chaveamento para sa-east-1b e sa-east-1c.',
            'Diretor Sílvio Cavalcanti, Camila Ramos (CSIRT), Felipe Albuquerque (SecOps) e Engenheiro de Dados.',
            'Tempo total de chaveamento de esteira: 28 minutos.',
            'Mecanismos de auto-scaling responderam com eficácia e réplica de leitura do RDS assumiu como master sem perda de registros.',
            'Necessidade de documentar passo a passo simplificado para acionamento noturno por operador de plantão.',
            'Criação de playbook interativo no Runbook corporativo e automação de alertas no Slack de emergência.',
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

    # 8. Evidências Iniciais (Inst 1 e Inst 2)
    evidencias = [
        # Inst 1
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
            1, req_map['REQ-5274-11'],
            'Inventário e Gestão de Certificados Digitais ICP-Brasil / TLS 1.3',
            'Documento',
            'Relatório de inventário dos certificados digitais em uso na RSFN e borda de rede, com datas de renovação e custódia em HSM.',
            'Inventario_Certificados_2026.pdf',
            '/uploads/Inventario_Certificados_2026.pdf',
            'd9a4b882310b892341908bdeac417120349812bcadaef4172839217823901bca',
            640200, 'application/pdf', None,
            'Infraestrutura Cloud', '2026-02-01', 'Validada'
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
        ),
        # Inst 2 (Torra SCD)
        (
            2, req_map['REQ-01'],
            'Política de Segurança Cibernética Torra SCD v2.1',
            'Politica',
            'Política aprovada pela Diretoria da Sociedade de Crédito Direto aderente às resoluções CMN 4.893 e 5.274.',
            'Politica_Torra_SCD_v2.1.pdf',
            '/uploads/Politica_Torra_SCD_v2.1.pdf',
            '33a1e2f491c981248019bca88921dfa0194821049281a1829481928419284102',
            980400, 'application/pdf', None,
            'Camila Ramos', '2026-01-20', 'Validada'
        ),
        (
            2, req_map['REQ-02'],
            'Homologação UNICAD Diretor Art. 7º - Torra SCD',
            'Ata de Diretoria',
            'Certidão de homologação do Diretor Sílvio Cavalcanti emitida pelo Banco Central do Brasil.',
            'Certidao_UNICAD_Silvio_Cavalcanti.pdf',
            '/uploads/Certidao_UNICAD_Silvio_Cavalcanti.pdf',
            '44b2f3a582d092359120cdb99032efb1205932150392b2930592039520395213',
            412000, 'application/pdf', None,
            'Jurídico Torra', '2025-06-15', 'Validada'
        ),
        (
            2, req_map['REQ-5274-11'],
            'Inventário de Certificados e TLS 1.3 - Torra SCD',
            'Documento',
            'Inventário dos certificados SSL de APIs públicas e credenciais mTLS homologadas no SPI/Pix.',
            'Inventario_TLS_Pix_Torra.pdf',
            '/uploads/Inventario_TLS_Pix_Torra.pdf',
            '55c3a4b693e103460231dec00143fac2316043261403c3041603140631406324',
            510000, 'application/pdf', None,
            'Felipe Albuquerque', '2026-01-18', 'Validada'
        ),
        (
            2, req_map['REQ-TEST-01'],
            'Relatório Executivo de Pentest em API de Microcrédito',
            'Relatório Pentest',
            'Laudo técnico de testes de invasão e intrusão na esteira de concessão de crédito digital.',
            'Pentest_API_Credito_2025.pdf',
            '/uploads/Pentest_API_Credito_2025.pdf',
            '66d4b5c704f214571342efd11254abd3427154372514d4152714251742517435',
            1850000, 'application/pdf', None,
            'Auditoria Externa TI', '2025-09-30', 'Validada'
        ),
        (
            2, req_map['REQ-CLOUD-04'],
            'Termo Aditivo de Cláusulas BACEN Art. 17 - AWS Brasil',
            'Contrato Cloud',
            'Aditivo contratual de processamento de dados contendo salvaguardas de auditoria BACEN e sigilo bancário.',
            'Aditivo_Art17_AWS_Torra.pdf',
            '/uploads/Aditivo_Art17_AWS_Torra.pdf',
            '77e5c6d8150325682453fae22365bce4538265483625e5263825362853628546',
            730000, 'application/pdf', None,
            'Jurídico Torra', '2025-08-10', 'Validada'
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

    # 9. Planos de Ação (5W2H) (Inst 1 e Inst 2)
    planos = [
        # Inst 1
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
            'Substituir processos manuais de renovação de certificados por pipeline automatizado com Cert-Manager.',
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
            'Mapear e documentar a rotina técnica de extração integral e reversibilidade dos dados de clientes hospedados no CRM.',
            'Atender ao Artigo 20 da Resolução CMN nº 4.893 (plano de descontinuidade com garantia de portabilidade total).',
            'Ambiente Corporativo de Relacionamento',
            'Rodrigo Prado (Arquiteto Corporativo)',
            '2026-04-30',
            'Construir script de exportação diária via API para data lake corporativo no formato Parquet aberto e testar carga.',
            35000.0, 'Em_Andamento', 35, None
        ),
        # Inst 2 (Torra SCD)
        (
            2, req_map['REQ-5274-04'],
            'Configuração de Políticas DLP para Google Workspace da Torra SCD',
            'Ativar regras de inspeção de conteúdo para bloquear envio de CPF e dados de crédito para fora do domínio.',
            'Proteger o sigilo bancário e prevenir exfiltração de base de mutuários.',
            'Ambiente Google Workspace corporativo',
            'Camila Ramos',
            '2026-05-15',
            'Habilitar regras de DLP com quarentena automática de mensagens.',
            15000.0, 'Em_Andamento', 55, None
        ),
        (
            2, req_map['REQ-5274-12'],
            'Contratação de Feed de Threat Intelligence para Fraudes em Crédito',
            'Contratar feed especializado em monitoramento de fraude e vazamento de CPFs.',
            'Atendimento integral à Resolução CMN 5.274/2025 para instituições de crédito direto.',
            'SOC Terceirizado',
            'Diretor Sílvio Cavalcanti',
            '2026-05-30',
            'Aprovar proposta comercial com provedor setorial.',
            40000.0, 'Em_Andamento', 30, None
        ),
        (
            2, req_map['REQ-CONT-02'],
            'Plano de Saída e Reversibilidade da Nuvem AWS para SCD',
            'Documentar procedimentos de exportação dos bancos de crédito e imagens de contêiner para formato neutro.',
            'Cumprimento do Art. 20 da Res. CMN 4.893 para garantia de reversibilidade contratual.',
            'Infraestrutura Torra',
            'Felipe Albuquerque',
            '2026-05-30',
            'Construir rotina automatizada de dump lógico e armazenamento em cold storage off-cloud.',
            20000.0, 'Em_Andamento', 45, None
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

    # 10. Fornecedores de Nuvem (Inst 1 e Inst 2)
    fornecedores = [
        # Inst 1
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
        ),
        # Inst 2 (Torra SCD)
        (
            2, 'Amazon Web Services Brasil Ltda',
            'Serviços de computação elástica ECS/Fargate, banco RDS Aurora Postgres e S3',
            'IaaS', 'Brasil (São Paulo sa-east-1)',
            1, 1, '2024-05-10', 1, 1, 1, 1, 1,
            '2025-11-05', 'Baixo',
            'Notificação de contratação relevante homologada no BACEN. Cláusulas do Art. 17 atendidas.'
        ),
        (
            2, 'Datadog Inc.',
            'Plataforma SaaS de observabilidade, APM, Cloud SIEM e monitoramento de logs de segurança',
            'SaaS', 'Estados Unidos (us-east-1)',
            1, 1, '2024-07-22', 1, 1, 1, 1, 1,
            '2025-09-18', 'Baixo',
            'Logs encriptados antes do envio com chave custodiada na Torra SCD. Convênio BACEN verificado.'
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

    # 11. Incidentes Reais com MTTD e MTTR (Inst 1 e Inst 2)
    incidentes = [
        # Inst 1
        (
            1, 'INC-2025-0042',
            'Tentativa de Credential Stuffing em API de Autenticação Móvel',
            '2025-09-14 03:22:00', '2025-09-14 03:24:15', '2025-09-14 03:45:00',
            2, 21,
            'Intrusão', 'Média', 'API Gateway Móvel',
            'Nenhuma conta comprometida. Bloqueio automático de 1.450 IPs maliciosos pelo WAF e rate-limiting.',
            'Encerrado', 0, None,
            'Ataque de força bruta distribuído originado de botnet internacional utilizando vazamentos públicos.',
            'Ajuste das regras de rate-limiting e inclusão de desafio de prova de trabalho (PoW) no app.'
        ),
        (
            1, 'INC-2025-0089',
            'E-mail de Phishing Temático Simulando Comunicado de RH com Link Malicioso',
            '2025-11-03 10:15:00', '2025-11-03 10:18:30', '2025-11-03 10:45:00',
            3, 27,
            'Phishing', 'Baixa', 'Serviço de Correio Eletrônico Corporativo',
            'Mensagem capturada pelo filtro anti-phishing. Três colaboradores clicaram, mas o sandbox bloqueou a execução da macro.',
            'Encerrado', 0, None,
            'Phishing direcionado de spear-phishing usando domínio falso similar.',
            'Campanha de reforço em conscientização e inclusão do domínio na lista negra do DNS corporativo.'
        ),
        (
            1, 'INC-2026-0005',
            'Indisponibilidade Momentânea em Conector Secundário da RSFN durante Manutenção',
            '2026-01-22 01:10:00', '2026-01-22 01:11:00', '2026-01-22 01:25:00',
            1, 14,
            'Indisponibilidade', 'Baixa', 'Roteador RSFN 02 (Secundário)',
            'Sem impacto nas operações ou transferências PIX, pois o conector primário absorveu o tráfego de imediato.',
            'Encerrado', 0, None,
            'Falha em placa de rede durante atualização programada de firmware.',
            'Substituição da placa defeituosa e rehomologação dos testes de chaveamento redundante.'
        ),
        # Inst 2 (Torra SCD)
        (
            2, 'INC-2025-0101',
            'Tentativa de Escalação de Privilégios em Bastion Host',
            '2025-10-12 14:40:00', '2025-10-12 14:48:00', '2025-10-12 15:30:00',
            8, 42,
            'Intrusão', 'Média', 'Servidor Bastion de Gerência Cloud',
            'Nenhum acesso indevido consumado aos bancos produtivos. Usuário desconhecido bloqueado de imediato pelo EDR.',
            'Encerrado', 0, None,
            'Tentativa de exploração de vulnerabilidade conhecida em pacote utilitário de terminal.',
            'Remoção do pacote, atualização do baseline de hardening e restrição de acesso SSH via VPN corporativa.'
        ),
        (
            2, 'INC-2025-0145',
            'Falha de Sincronismo em Webhook de Liquidação Pix',
            '2025-12-05 10:50:00', '2025-12-05 10:54:00', '2025-12-05 11:15:00',
            4, 21,
            'Indisponibilidade', 'Baixa', 'Webhook Receiver de Liquidação',
            'Atraso temporário de 15 minutos na confirmação de 14 propostas de crédito. Todas as transações foram liquidadas com sucesso.',
            'Encerrado', 0, None,
            'Oscilação temporária de DNS do parceiro liquidante.',
            'Implementação de cache DNS local com TTL estendido e fila de retry com backoff exponencial.'
        )
    ]

    for inc in incidentes:
        cursor.execute("""
        INSERT INTO incidentes (
            instituicao_id, protocolo, titulo, data_ocorrencia, data_deteccao, data_resolucao,
            tempo_deteccao_minutos, tempo_resolucao_minutos, categoria, criticidade,
            sistemas_afetados, impacto_operacional, status, notificado_bacen, data_notificacao_bacen,
            causa_raiz, acoes_corretivas
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, inc)

    conn.commit()

    # 12. Fragilidades Identificadas e Auditorias / Pentests (Art. 8º - Seção 5)
    fragilidades = [
        # Inst 1
        (
            1, 'Pentest Externo Periódico 2025 - Headers de Segurança HTTP',
            'Pentest Externo', 'Media',
            'Ausência de cabeçalho Strict-Transport-Security (HSTS) e Content-Security-Policy (CSP) em subdomínio de teste exposto.',
            req_map['REQ-TEST-01'], 'Remediada', '2025-10-30', '2025-11-20', 'SecOps Lead'
        ),
        (
            1, 'Auditoria Interna de Acessos Privilegiados - Contas de Serviço',
            'Auditoria Interna', 'Alta',
            'Contas de serviço em ambiente de homologação com credenciais antigas sem processo automatizado de rotação semestral.',
            req_map['REQ-5274-01'], 'Em_Tratamento', '2025-12-10', '2026-03-31', 'Equipe de IAM'
        ),
        # Inst 2
        (
            2, 'Pentest em API de Microcrédito - Rate Limiting em Endpoint de Simulação',
            'Pentest Externo', 'Media',
            'Falta de rate-limiting estrito em rota pública de simulação cadastral, permitindo requisições automatizadas atípicas.',
            req_map['REQ-TEST-01'], 'Remediada', '2025-09-30', '2025-11-15', 'Felipe Albuquerque'
        ),
        (
            2, 'Varredura Semestral de Vulnerabilidades - Versão de OpenSSH em Servidor de Staging',
            'Varredura de Vulnerabilidades', 'Baixa',
            'Versão de OpenSSH desatualizada em máquina virtual isolada de laboratório de desenvolvimento.',
            req_map['REQ-5274-08'], 'Remediada', '2025-11-10', '2025-11-25', 'DevSecOps Torra'
        )
    ]

    for f in fragilidades:
        cursor.execute("""
        INSERT INTO auditorias_fragilidades (
            instituicao_id, titulo, tipo, severidade, descricao, requisito_id,
            status_remediacao, data_identificacao, prazo_remediacao, responsavel
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, f)

    conn.commit()

    # 13. Parecer Formal do Diretor Estatutário (Art. 8º - Seção 7)
    # Pré-cria parecer assinado para Inst 1 e parecer pendente para Inst 2
    parecer_texto_1 = (
        "Na qualidade de Diretor Estatutário formalmente indicado perante o Banco Central do Brasil nos termos "
        "do Art. 7º da Resolução CMN nº 4.893/2021, declaro que analisei a efetividade da implementação da "
        "Política de Segurança Cibernética e do Plano de Ação e de Resposta a Incidentes (PARI) da Instituição "
        "Financeira Alpha S.A. durante o exercício encerrado em 31 de dezembro de 2025. "
        "Atesto que os controles mandatórios prescritos pela novel Resolução CMN nº 5.274/2025 encontram-se em elevado grau "
        "de aderência e maturidade operacional (91.2%), com planos de ação corretiva formalizados para as oportunidades "
        "de melhoria remanescentes. Os simulados de crise e testes de intrusão independentes atestaram a resiliência "
        "operacional dos sistemas críticos perante o ecossistema do Sistema Financeiro Nacional (SFN)."
    )
    hash_inst1 = hashlib.sha256(f"AlphaBank_2025_{parecer_texto_1}".encode('utf-8')).hexdigest()

    pareceres = [
        (
            1, '2025', parecer_texto_1, 'Assinado_Digitalmente',
            'Roberto Silveira Mello',
            'Diretor Estatutário de Riscos e Segurança Cibernética (Art. 7º BACEN)',
            'BACEN-UNICAD-9821',
            '2026-02-18 14:00:00',
            hash_inst1
        ),
        (
            2, '2025',
            "Na qualidade de Diretor responsável pela segurança cibernética da Torra SCD perante o BACEN (Art. 7º), "
            "atesto que os controles de cibersegurança foram avaliados com efetividade para o segmento S4, mantendo-se "
            "as rotinas de contingência e salvaguardas contratuais do Art. 17 em estrita conformidade.",
            'Pendente',
            'Sílvio Cavalcanti',
            'Diretor de Cibersegurança e Operações (Art. 7º BACEN)',
            'BACEN-UNICAD-4512',
            None,
            None
        )
    ]

    for p in pareceres:
        cursor.execute("""
        INSERT INTO relatorio_anual_parecer (
            instituicao_id, ano_base, parecer_conclusivo, status_assinatura, assinado_por,
            cargo_assinante, unicad_assinante, data_assinatura, hash_sha256_relatorio
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, p)

    conn.commit()

    # 14. Trilha de Auditoria (Audit Log) Segregada por Tenant
    audit_logs = [
        # Inst 1
        (1, '2026-02-15 09:30:00', 'admin@bacen.local', 'SISTEMA_INICIALIZADO', 'instituicao', 1, 'Plataforma GRC carregada com governança Alpha Bank (S3).'),
        (1, '2026-02-15 10:15:00', 'gestor@alphabank.com.br', 'AUDITAR_REQUISITO', 'avaliacoes', req_map['REQ-5274-01'], 'Avaliação do controle 01 da Resolução CMN 5.274 confirmada como Atendido (MFA).'),
        (1, '2026-02-15 11:20:00', 'gestor@alphabank.com.br', 'REVISAR_PARI', 'pari_governanca', 1, 'Revisão das rotinas do PARI e playbooks operacionais concluída.'),
        (1, '2026-02-18 14:00:00', 'gestor@alphabank.com.br', 'ASSINATURA_PARECER_ART8', 'relatorio_anual_parecer', 1, f"Parecer formal emitido e assinado digitalmente com hash SHA-256 {hash_inst1[:16]}..."),
        # Inst 2
        (2, '2026-01-20 08:45:00', 'admin@bacen.local', 'SISTEMA_INICIALIZADO', 'instituicao', 2, 'Ambiente multi-tenant provisionado para Torra SCD (S4).'),
        (2, '2026-01-20 14:30:00', 'gestor@torrascd.com.br', 'AUDITAR_REQUISITO', 'avaliacoes', req_map['REQ-01'], 'Política de Segurança Cibernética Torra v2.1 homologada como Atendida.')
    ]

    for log in audit_logs:
        cursor.execute("""
        INSERT INTO auditoria_log (instituicao_id, data_hora, usuario, acao, entidade, entidade_id, detalhes)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, log)

    conn.commit()
    conn.close()
    print("Seed data loaded successfully with multi-tenant isolation, PARI, Pentests and Art. 8 module!")

if __name__ == "__main__":
    seed()
