"""
Database initialization and regulatory schema for BACEN CMN 4.893 / 5.274 Compliance GRC.
Includes RBAC (Role-Based Access Control), Least Privilege, MFA and Multi-institution mapping.
"""
import sqlite3
import os

DB_PATH = "/home/gustavo/.gemini/antigravity/scratch/bacen-grc-compliance/data/compliance.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("PRAGMA foreign_keys = ON;")

    # 1. Usuários do Sistema (RBAC)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        senha_salt TEXT NOT NULL,
        is_admin_geral INTEGER DEFAULT 0,
        mfa_habilitado INTEGER DEFAULT 1,
        mfa_secret TEXT NOT NULL,
        ativo INTEGER DEFAULT 1,
        cargo TEXT,
        ultimo_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Vínculo Usuário x Instituições x Perfil (Menor Privilégio por Instituição)
    # Perfis: 'gestor' (CISO/Compliance), 'analista' (Operador), 'auditor' (Somente Leitura/BACEN)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuario_instituicoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL,
        instituicao_id INTEGER NOT NULL,
        perfil TEXT NOT NULL CHECK(perfil IN ('gestor', 'analista', 'auditor')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE,
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE,
        UNIQUE(usuario_id, instituicao_id)
    );
    """)

    # 3. Sessões Ativas e Tokens de Autenticação com MFA
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        usuario_id INTEGER NOT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expira_em TIMESTAMP NOT NULL,
        mfa_verificado INTEGER DEFAULT 0,
        ip_origem TEXT,
        user_agent TEXT,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE
    );
    """)

    # 4. Instituições Financeiras Avaliadas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS instituicao (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        razao_social TEXT NOT NULL,
        nome_fantasia TEXT,
        cnpj TEXT NOT NULL,
        segmento TEXT NOT NULL DEFAULT 'S3', -- S1, S2, S3, S4, S5
        tipo_instituicao TEXT DEFAULT 'Banco Múltiplo',
        registro_unicad TEXT,
        diretor_responsavel TEXT NOT NULL,
        cargo_diretor TEXT NOT NULL,
        email_diretor TEXT,
        telefone_diretor TEXT,
        data_aprovacao_politica DATE,
        data_ultima_revisao DATE,
        versao_politica TEXT DEFAULT '1.0',
        escopo_operacional TEXT,
        is_ativa INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Domínios Regulatórios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dominios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codigo TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        descricao TEXT NOT NULL,
        artigo_referencia TEXT NOT NULL,
        icone TEXT NOT NULL,
        ordem INTEGER NOT NULL
    );
    """)

    # 6. Requisitos Normativos
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS requisitos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codigo TEXT UNIQUE NOT NULL,
        dominio_id INTEGER NOT NULL,
        artigo TEXT NOT NULL,
        titulo TEXT NOT NULL,
        descricao_legal TEXT NOT NULL,
        especificacao_tecnica TEXT NOT NULL,
        is_cmn_5274_obrigatorio INTEGER DEFAULT 0,
        numero_controle_5274 INTEGER,
        severidade TEXT NOT NULL,
        segmento_aplicavel TEXT NOT NULL DEFAULT 'Todos',
        evidencias_sugeridas TEXT NOT NULL,
        FOREIGN KEY (dominio_id) REFERENCES dominios (id)
    );
    """)

    # 7. Avaliações de Compliance (GRC) vinculadas à instituição
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS avaliacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        requisito_id INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('atendido', 'parcialmente_atendido', 'em_implementacao', 'nao_atendido', 'nao_aplicavel')),
        percentual_aderencia INTEGER NOT NULL DEFAULT 0 CHECK(percentual_aderencia BETWEEN 0 AND 100),
        justificativa TEXT,
        responsavel TEXT,
        prazo_adequacao DATE,
        ultima_auditoria DATE,
        avaliador TEXT,
        observacoes_auditor TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (requisito_id) REFERENCES requisitos (id),
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE,
        UNIQUE(instituicao_id, requisito_id)
    );
    """)

    # 8. Evidências Regulatórias
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidencias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        requisito_id INTEGER NOT NULL,
        titulo TEXT NOT NULL,
        tipo TEXT NOT NULL,
        descricao TEXT,
        nome_arquivo TEXT,
        caminho_arquivo TEXT,
        hash_sha256 TEXT,
        tamanho_bytes INTEGER,
        mime_type TEXT,
        link_externo TEXT,
        coletor TEXT NOT NULL,
        data_coleta DATE NOT NULL,
        status_validacao TEXT DEFAULT 'Validada',
        FOREIGN KEY (requisito_id) REFERENCES requisitos (id),
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 9. Planos de Ação (5W2H)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS planos_acao (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        requisito_id INTEGER NOT NULL,
        titulo TEXT NOT NULL,
        o_que TEXT NOT NULL,
        por_que TEXT NOT NULL,
        onde TEXT NOT NULL,
        quem TEXT NOT NULL,
        quando DATE NOT NULL,
        como TEXT NOT NULL,
        quanto REAL DEFAULT 0.0,
        status TEXT DEFAULT 'Em_Andamento',
        progresso_pct INTEGER DEFAULT 0,
        data_conclusao DATE,
        FOREIGN KEY (requisito_id) REFERENCES requisitos (id),
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 10. Fornecedores de Nuvem e Terceiros Relevantes (Arts. 11 a 17)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fornecedores_nuvem (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        nome_provedor TEXT NOT NULL,
        servico_prestado TEXT NOT NULL,
        tipo_nuvem TEXT NOT NULL,
        pais_armazenamento TEXT NOT NULL,
        servico_relevante INTEGER NOT NULL DEFAULT 1,
        notificado_bacen INTEGER NOT NULL DEFAULT 1,
        data_notificacao_bacen DATE,
        convenio_bacen_pais INTEGER NOT NULL DEFAULT 1,
        clausula_acesso_bacen INTEGER NOT NULL DEFAULT 1,
        clausula_segregacao_dados INTEGER NOT NULL DEFAULT 1,
        clausula_continuidade INTEGER NOT NULL DEFAULT 1,
        clausula_reversibilidade INTEGER NOT NULL DEFAULT 1,
        data_ultimo_teste_contingencia DATE,
        nivel_risco TEXT DEFAULT 'Baixo',
        observacoes TEXT,
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 11. MÓDULO PARI: Governança do CSIRT (Arts. 6º e 8º)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pari_governanca (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER UNIQUE NOT NULL,
        lider_csirt TEXT NOT NULL,
        email_csirt TEXT NOT NULL,
        telefone_plantao_247 TEXT NOT NULL,
        membros_csirt TEXT,
        comite_crise TEXT,
        canais_emergencia TEXT,
        criterios_relevancia_bacen TEXT,
        procedimento_sisbacen TEXT,
        data_ultima_revisao_pari DATE,
        versao_pari TEXT DEFAULT '2.0',
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 12. MÓDULO PARI: Playbooks Operacionais
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pari_playbooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        codigo TEXT NOT NULL,
        titulo_cenario TEXT NOT NULL,
        categoria TEXT NOT NULL,
        etapa_deteccao TEXT NOT NULL,
        etapa_contencao TEXT NOT NULL,
        etapa_erradicacao TEXT NOT NULL,
        etapa_recuperacao TEXT NOT NULL,
        etapa_comunicacao_bacen TEXT NOT NULL,
        tempo_estimado_resposta TEXT,
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 13. MÓDULO PARI: Simulados e Exercícios de Crise
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pari_simulados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        titulo_simulado TEXT NOT NULL,
        data_realizacao DATE NOT NULL,
        cenario_testado TEXT NOT NULL,
        participantes TEXT NOT NULL,
        tempo_resposta_alcancado TEXT,
        pontos_fortes TEXT,
        gargalos_identificados TEXT,
        acoes_melhoria TEXT,
        status TEXT DEFAULT 'Concluido',
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 14. Registro de Incidentes Reais
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidentes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        protocolo TEXT UNIQUE NOT NULL,
        titulo TEXT NOT NULL,
        data_ocorrencia TIMESTAMP NOT NULL,
        data_deteccao TIMESTAMP NOT NULL,
        data_resolucao TIMESTAMP,
        tempo_deteccao_minutos INTEGER DEFAULT 0,
        tempo_resolucao_minutos INTEGER DEFAULT 0,
        categoria TEXT NOT NULL,
        criticidade TEXT NOT NULL,
        sistemas_afetados TEXT NOT NULL,
        impacto_operacional TEXT,
        status TEXT NOT NULL,
        notificado_bacen INTEGER DEFAULT 0,
        data_notificacao_bacen DATE,
        causa_raiz TEXT,
        acoes_corretivas TEXT,
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 15. Trilha de Auditoria (Audit Log) Segregada por Tenant
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auditoria_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER DEFAULT 1,
        data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        usuario TEXT NOT NULL,
        acao TEXT NOT NULL,
        entidade TEXT NOT NULL,
        entidade_id INTEGER,
        detalhes TEXT,
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE
    );
    """)

    # 16. Fragilidades Identificadas e Testes de Intrusão (Art. 8º da Res. 4.893)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auditorias_fragilidades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL DEFAULT 1,
        titulo TEXT NOT NULL,
        tipo TEXT NOT NULL, -- 'Pentest Externo', 'Auditoria Interna', 'Varredura de Vulnerabilidades', 'Auditoria Externa BACEN'
        severidade TEXT NOT NULL, -- 'Critica', 'Alta', 'Media', 'Baixa'
        descricao TEXT NOT NULL,
        requisito_id INTEGER,
        status_remediacao TEXT NOT NULL DEFAULT 'Em_Tratamento', -- 'Em_Tratamento', 'Remediada', 'Risco_Aceito'
        data_identificacao DATE NOT NULL,
        prazo_remediacao DATE,
        responsavel TEXT,
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE,
        FOREIGN KEY (requisito_id) REFERENCES requisitos (id)
    );
    """)

    # 17. Parecer Formal do Diretor Estatutário e Assinatura Eletrônica (Art. 8º da Res. 4.893)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS relatorio_anual_parecer (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instituicao_id INTEGER NOT NULL,
        ano_base TEXT NOT NULL DEFAULT '2025',
        parecer_conclusivo TEXT NOT NULL,
        status_assinatura TEXT NOT NULL DEFAULT 'Pendente', -- 'Pendente', 'Assinado_Digitalmente'
        assinado_por TEXT,
        cargo_assinante TEXT,
        unicad_assinante TEXT,
        data_assinatura TIMESTAMP,
        hash_sha256_relatorio TEXT,
        FOREIGN KEY (instituicao_id) REFERENCES instituicao (id) ON DELETE CASCADE,
        UNIQUE(instituicao_id, ano_base)
    );
    """)

    # Migrações automáticas para esquemas existentes
    cursor.execute("PRAGMA table_info(auditoria_log);")
    audit_cols = [r[1] for r in cursor.fetchall()]
    if 'instituicao_id' not in audit_cols:
        cursor.execute("ALTER TABLE auditoria_log ADD COLUMN instituicao_id INTEGER DEFAULT 1;")

    cursor.execute("PRAGMA table_info(incidentes);")
    inc_cols = [r[1] for r in cursor.fetchall()]
    if 'tempo_deteccao_minutos' not in inc_cols:
        cursor.execute("ALTER TABLE incidentes ADD COLUMN tempo_deteccao_minutos INTEGER DEFAULT 0;")
    if 'tempo_resolucao_minutos' not in inc_cols:
        cursor.execute("ALTER TABLE incidentes ADD COLUMN tempo_resolucao_minutos INTEGER DEFAULT 0;")
    if 'data_resolucao' not in inc_cols:
        cursor.execute("ALTER TABLE incidentes ADD COLUMN data_resolucao TIMESTAMP;")

    conn.commit()
    conn.close()
    print("Database tables with RBAC, MFA, Multi-tenancy and Art. 8 initialized successfully.")

if __name__ == "__main__":
    init_db()
