"""
Enterprise-grade Web Server and REST API for BACEN CMN 4.893 & 5.274 Compliance GRC.
Features:
- Multi-company / Institution Registration & Customization (No assumed/hardcoded names)
- Dedicated PARI Module (Plano de Ação e de Resposta a Incidentes - Arts. 6º e 8º)
- 14 Mandatory Minimum Controls of Resolução CMN nº 5.274/2025
- Evidence Vault with SHA-256 integrity calculation
- Real-time Dashboards, KPIs and Annual Report Generator
"""
import http.server
import socketserver
import json
import sqlite3
import os
import urllib.parse
import mimetypes
import hashlib
from datetime import datetime

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "compliance.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def dict_from_row(row):
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}

def get_active_institution_id(cursor):
    cursor.execute("SELECT id FROM instituicao WHERE is_ativa = 1 LIMIT 1;")
    row = cursor.fetchone()
    if row:
        return row['id']
    cursor.execute("SELECT id FROM instituicao ORDER BY id ASC LIMIT 1;")
    row = cursor.fetchone()
    return row['id'] if row else 1

class ComplianceAPIHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        try:
            msg = format % args
        except Exception:
            msg = " ".join(str(a) for a in args)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

    def do_HEAD(self):
        self.do_GET()

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Static assets
        if path == "/" or path == "/index.html":
            self.serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html; charset=utf-8")
            return
        elif path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            full_path = os.path.join(STATIC_DIR, rel_path)
            mime, _ = mimetypes.guess_type(full_path)
            self.serve_file(full_path, mime or "application/octet-stream")
            return
        elif path.startswith("/uploads/"):
            rel_path = path[len("/uploads/"):]
            full_path = os.path.join(UPLOAD_DIR, rel_path)
            mime, _ = mimetypes.guess_type(full_path)
            self.serve_file(full_path, mime or "application/octet-stream")
            return

        conn = get_db()
        cursor = conn.cursor()

        try:
            inst_id = get_active_institution_id(cursor)

            # 1. INSTITUICOES (Multi-empresa)
            if path == "/api/instituicoes":
                cursor.execute("SELECT * FROM instituicao ORDER BY is_ativa DESC, id ASC;")
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            elif path == "/api/instituicao" or path == "/api/instituicao/ativa":
                cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (inst_id,))
                row = cursor.fetchone()
                self.send_json(dict_from_row(row) if row else {})

            elif path.startswith("/api/instituicao/"):
                req_inst_id = path.split("/")[-1]
                cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (req_inst_id,))
                row = cursor.fetchone()
                self.send_json(dict_from_row(row) if row else {}, 200 if row else 404)

            # 2. DASHBOARD
            elif path == "/api/dashboard":
                data = self.get_dashboard_metrics(cursor, inst_id)
                self.send_json(data)

            # 3. DOMÍNIOS
            elif path == "/api/dominios":
                cursor.execute("SELECT * FROM dominios ORDER BY ordem ASC;")
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            # 4. REQUISITOS & AVALIAÇÕES
            elif path == "/api/requisitos":
                dominio_id = query.get('dominio_id', [None])[0]
                status = query.get('status', [None])[0]
                is_5274 = query.get('is_cmn_5274', [None])[0]
                search = query.get('search', [None])[0]

                sql = """
                SELECT r.*, d.nome as dominio_nome, d.codigo as dominio_codigo,
                       COALESCE(a.status, 'nao_atendido') as status,
                       COALESCE(a.percentual_aderencia, 0) as percentual_aderencia,
                       a.justificativa, a.responsavel,
                       a.prazo_adequacao, a.ultima_auditoria, a.avaliador, a.observacoes_auditor,
                       (SELECT COUNT(*) FROM evidencias e WHERE e.requisito_id = r.id AND e.instituicao_id = ?) as total_evidencias,
                       (SELECT COUNT(*) FROM planos_acao p WHERE p.requisito_id = r.id AND p.instituicao_id = ?) as total_planos
                FROM requisitos r
                JOIN dominios d ON r.dominio_id = d.id
                LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
                WHERE 1=1
                """
                params = [inst_id, inst_id, inst_id]
                if dominio_id:
                    sql += " AND r.dominio_id = ?"
                    params.append(dominio_id)
                if status:
                    sql += " AND COALESCE(a.status, 'nao_atendido') = ?"
                    params.append(status)
                if is_5274 is not None and is_5274 != '':
                    sql += " AND r.is_cmn_5274_obrigatorio = ?"
                    params.append(int(is_5274))
                if search:
                    sql += " AND (r.codigo LIKE ? OR r.titulo LIKE ? OR r.artigo LIKE ? OR r.descricao_legal LIKE ?)"
                    term = f"%{search}%"
                    params.extend([term, term, term, term])

                sql += " ORDER BY d.ordem ASC, r.numero_controle_5274 ASC, r.id ASC;"
                cursor.execute(sql, params)
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            elif path.startswith("/api/requisitos/"):
                req_id = path.split("/")[-1]
                cursor.execute("""
                SELECT r.*, d.nome as dominio_nome, d.codigo as dominio_codigo,
                       COALESCE(a.status, 'nao_atendido') as status,
                       COALESCE(a.percentual_aderencia, 0) as percentual_aderencia,
                       a.justificativa, a.responsavel,
                       a.prazo_adequacao, a.ultima_auditoria, a.avaliador, a.observacoes_auditor
                FROM requisitos r
                JOIN dominios d ON r.dominio_id = d.id
                LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
                WHERE r.id = ?;
                """, (inst_id, req_id))
                req_row = cursor.fetchone()
                if not req_row:
                    self.send_json({"error": "Requisito não encontrado"}, 404)
                    return
                req_data = dict_from_row(req_row)

                cursor.execute("SELECT * FROM evidencias WHERE requisito_id = ? AND instituicao_id = ? ORDER BY id DESC;", (req_id, inst_id))
                req_data['evidencias'] = [dict_from_row(r) for r in cursor.fetchall()]

                cursor.execute("SELECT * FROM planos_acao WHERE requisito_id = ? AND instituicao_id = ? ORDER BY id DESC;", (req_id, inst_id))
                req_data['planos_acao'] = [dict_from_row(r) for r in cursor.fetchall()]

                self.send_json(req_data)

            # 5. MÓDULO PARI
            elif path == "/api/pari":
                cursor.execute("SELECT * FROM pari_governanca WHERE instituicao_id = ? LIMIT 1;", (inst_id,))
                gov = dict_from_row(cursor.fetchone())
                if not gov:
                    cursor.execute("""
                    INSERT INTO pari_governanca (instituicao_id, lider_csirt, email_csirt, telefone_plantao_247)
                    VALUES (?, 'Coordenador CSIRT', 'csirt@instituicao.com.br', '(11) 90000-0000');
                    """, (inst_id,))
                    conn.commit()
                    cursor.execute("SELECT * FROM pari_governanca WHERE instituicao_id = ? LIMIT 1;", (inst_id,))
                    gov = dict_from_row(cursor.fetchone())

                cursor.execute("SELECT * FROM pari_playbooks WHERE instituicao_id = ? ORDER BY codigo ASC;", (inst_id,))
                playbooks = [dict_from_row(r) for r in cursor.fetchall()]

                cursor.execute("SELECT * FROM pari_simulados WHERE instituicao_id = ? ORDER BY data_realizacao DESC;", (inst_id,))
                simulados = [dict_from_row(r) for r in cursor.fetchall()]

                cursor.execute("SELECT * FROM incidentes WHERE instituicao_id = ? ORDER BY data_ocorrencia DESC;", (inst_id,))
                incidentes = [dict_from_row(r) for r in cursor.fetchall()]

                self.send_json({
                    "governanca": gov,
                    "playbooks": playbooks,
                    "simulados": simulados,
                    "incidentes": incidentes
                })

            # 6. EVIDÊNCIAS
            elif path == "/api/evidencias":
                requisito_id = query.get('requisito_id', [None])[0]
                sql = """
                SELECT e.*, r.codigo as requisito_codigo, r.titulo as requisito_titulo, r.artigo
                FROM evidencias e
                JOIN requisitos r ON e.requisito_id = r.id
                WHERE e.instituicao_id = ?
                """
                params = [inst_id]
                if requisito_id:
                    sql += " AND e.requisito_id = ?"
                    params.append(requisito_id)
                sql += " ORDER BY e.id DESC;"
                cursor.execute(sql, params)
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            # 7. PLANOS DE AÇÃO 5W2H
            elif path == "/api/planos_acao":
                cursor.execute("""
                SELECT p.*, r.codigo as requisito_codigo, r.titulo as requisito_titulo, r.artigo
                FROM planos_acao p
                JOIN requisitos r ON p.requisito_id = r.id
                WHERE p.instituicao_id = ?
                ORDER BY p.id DESC;
                """, (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            # 8. FORNECEDORES DE NUVEM
            elif path == "/api/fornecedores_nuvem":
                cursor.execute("SELECT * FROM fornecedores_nuvem WHERE instituicao_id = ? ORDER BY id ASC;", (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            # 9. INCIDENTES
            elif path == "/api/incidentes":
                cursor.execute("SELECT * FROM incidentes WHERE instituicao_id = ? ORDER BY data_ocorrencia DESC;", (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            # 10. RELATÓRIO ANUAL (ART. 8º)
            elif path == "/api/relatorio_anual":
                relatorio = self.generate_annual_report(cursor, inst_id)
                self.send_json(relatorio)

            # 11. AUDIT LOG
            elif path == "/api/auditoria_log":
                cursor.execute("SELECT * FROM auditoria_log ORDER BY id DESC LIMIT 100;")
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)

            # 12. EXPORTADORES
            elif path == "/api/export/csv":
                self.export_csv(cursor, inst_id)

            elif path == "/api/export/json":
                self.export_full_json(cursor, inst_id)

            else:
                self.send_json({"error": "Endpoint não encontrado"}, 404)

        finally:
            conn.close()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        conn = get_db()
        cursor = conn.cursor()

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length)
            inst_id = get_active_institution_id(cursor)

            # 1. CADASTRAR NOVA INSTITUIÇÃO
            if path == "/api/instituicoes":
                payload = json.loads(raw_body.decode('utf-8'))
                cursor.execute("""
                INSERT INTO instituicao (
                    razao_social, nome_fantasia, cnpj, segmento, tipo_instituicao, registro_unicad,
                    diretor_responsavel, cargo_diretor, email_diretor, telefone_diretor,
                    data_aprovacao_politica, data_ultima_revisao, versao_politica, escopo_operacional, is_ativa
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1);
                """, (
                    payload.get('razao_social', 'Nova Instituição Financeira S.A.'),
                    payload.get('nome_fantasia', ''),
                    payload.get('cnpj', '00.000.000/0001-00'),
                    payload.get('segmento', 'S3'),
                    payload.get('tipo_instituicao', 'Banco Múltiplo'),
                    payload.get('registro_unicad', ''),
                    payload.get('diretor_responsavel', 'Diretor Estatutário'),
                    payload.get('cargo_diretor', 'Diretor de Cibersegurança'),
                    payload.get('email_diretor', ''),
                    payload.get('telefone_diretor', ''),
                    payload.get('data_aprovacao_politica', datetime.now().strftime('%Y-%m-%d')),
                    payload.get('data_ultima_revisao', datetime.now().strftime('%Y-%m-%d')),
                    payload.get('versao_politica', '1.0'),
                    payload.get('escopo_operacional', '')
                ))
                new_id = cursor.lastrowid

                # Desativar outras instituições
                cursor.execute("UPDATE instituicao SET is_ativa = 0 WHERE id != ?;", (new_id,))

                # Inicializar avaliações padrão para todos os requisitos
                cursor.execute("SELECT id FROM requisitos;")
                all_reqs = cursor.fetchall()
                for req in all_reqs:
                    cursor.execute("""
                    INSERT OR IGNORE INTO avaliacoes (instituicao_id, requisito_id, status, percentual_aderencia)
                    VALUES (?, ?, 'nao_atendido', 0);
                    """, (new_id, req['id']))

                # Inicializar governança PARI padrão
                cursor.execute("""
                INSERT INTO pari_governanca (
                    instituicao_id, lider_csirt, email_csirt, telefone_plantao_247,
                    membros_csirt, comite_crise, criterios_relevancia_bacen, procedimento_sisbacen
                ) VALUES (?, 'Líder CSIRT', 'csirt@empresa.com.br', '(11) 99999-0000',
                          'Equipe de Segurança da Informação, Redes e DBA',
                          'Diretor Estatutário, CISO e Jurídico',
                          'Incidentes que causem indisponibilidade de canais essenciais > 2h ou vazamento de dados.',
                          'Comunicação em até 24h via Sisbacen / Protocolo Digital.');
                """, (new_id,))

                # Inicializar playbooks básicos
                default_playbooks = [
                    ('PB-01', 'Ataque de Ransomware', 'Ransomware', 'Alertas de criptografia em massa no EDR.', 'Isolamento de rede das máquinas afetadas.', 'Remoção do malware e revogação de acessos.', 'Restauração de backups imutáveis.', 'Notificação no SISBACEN se houver impacto operacional.', 'Contenção em 15 min; RTO 4h.'),
                    ('PB-02', 'Vazamento de Dados (LGPD & Sigilo Bancário)', 'Vazamento de Dados', 'Alertas de DLP ou Threat Intel de vazamento.', 'Bloqueio de credenciais e canais de exfiltração.', 'Análise forense e fechamento de brecha.', 'Reemissão forçada de credenciais.', 'Notificação simultânea ao BACEN e ANPD.', 'Análise de escopo em até 2h.')
                ]
                for dp in default_playbooks:
                    cursor.execute("""
                    INSERT INTO pari_playbooks (
                        instituicao_id, codigo, titulo_cenario, categoria, etapa_deteccao,
                        etapa_contencao, etapa_erradicacao, etapa_recuperacao, etapa_comunicacao_bacen, tempo_estimado_resposta
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (new_id, dp[0], dp[1], dp[2], dp[3], dp[4], dp[5], dp[6], dp[7], dp[8]))

                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES ('Administrador', 'CRIAR_INSTITUICAO', 'instituicao', ?, ?);
                """, (new_id, f"Cadastrada nova instituição {payload.get('razao_social')}."))

                conn.commit()
                self.send_json({"success": True, "id": new_id})

            # ATIVAR INSTITUIÇÃO ESPECÍFICA
            elif path.endswith("/ativar") and "/api/instituicao/" in path:
                target_id = path.split("/")[-2]
                cursor.execute("UPDATE instituicao SET is_ativa = 0;")
                cursor.execute("UPDATE instituicao SET is_ativa = 1 WHERE id = ?;", (target_id,))
                conn.commit()
                self.send_json({"success": True, "ativo_id": target_id})

            # 2. REGISTRAR EVIDÊNCIA
            elif path == "/api/evidencias":
                payload = json.loads(raw_body.decode('utf-8'))
                req_id = payload.get('requisito_id')
                titulo = payload.get('titulo')
                tipo = payload.get('tipo', 'Documento')
                descricao = payload.get('descricao', '')
                coletor = payload.get('coletor', 'Auditor Responsável')
                link_ext = payload.get('link_externo')
                nome_arq = payload.get('nome_arquivo', 'evidencia.txt')
                conteudo_b64 = payload.get('conteudo_base64')

                caminho_arq = None
                hash_sha256 = None
                tam_bytes = 0

                if conteudo_b64:
                    import base64
                    file_data = base64.b64decode(conteudo_b64)
                    hash_sha256 = hashlib.sha256(file_data).hexdigest()
                    tam_bytes = len(file_data)
                    safe_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{nome_arq.replace(' ', '_')}"
                    file_path = os.path.join(UPLOAD_DIR, safe_filename)
                    with open(file_path, "wb") as f:
                        f.write(file_data)
                    caminho_arq = f"/uploads/{safe_filename}"
                elif link_ext:
                    hash_sha256 = hashlib.sha256(link_ext.encode('utf-8')).hexdigest()
                else:
                    hash_sha256 = hashlib.sha256(descricao.encode('utf-8')).hexdigest()

                cursor.execute("""
                INSERT INTO evidencias (
                    instituicao_id, requisito_id, titulo, tipo, descricao, nome_arquivo, caminho_arquivo,
                    hash_sha256, tamanho_bytes, mime_type, link_externo, coletor, data_coleta, status_validacao
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'), 'Validada');
                """, (inst_id, req_id, titulo, tipo, descricao, nome_arq, caminho_arq, hash_sha256, tam_bytes, 'application/octet-stream', link_ext, coletor))

                ev_id = cursor.lastrowid
                conn.commit()
                self.send_json({"success": True, "id": ev_id, "hash_sha256": hash_sha256})

            # 3. PLANOS DE AÇÃO 5W2H
            elif path == "/api/planos_acao":
                payload = json.loads(raw_body.decode('utf-8'))
                cursor.execute("""
                INSERT INTO planos_acao (
                    instituicao_id, requisito_id, titulo, o_que, por_que, onde, quem, quando, como, quanto, status, progresso_pct
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    inst_id,
                    payload.get('requisito_id'),
                    payload.get('titulo'),
                    payload.get('o_que'),
                    payload.get('por_que'),
                    payload.get('onde'),
                    payload.get('quem'),
                    payload.get('quando'),
                    payload.get('como'),
                    float(payload.get('quanto', 0)),
                    payload.get('status', 'Em_Andamento'),
                    int(payload.get('progresso_pct', 0))
                ))
                p_id = cursor.lastrowid
                conn.commit()
                self.send_json({"success": True, "id": p_id})

            # 4. FORNECEDORES DE NUVEM
            elif path == "/api/fornecedores_nuvem":
                payload = json.loads(raw_body.decode('utf-8'))
                cursor.execute("""
                INSERT INTO fornecedores_nuvem (
                    instituicao_id, nome_provedor, servico_prestado, tipo_nuvem, pais_armazenamento, servico_relevante,
                    notificado_bacen, data_notificacao_bacen, convenio_bacen_pais, clausula_acesso_bacen,
                    clausula_segregacao_dados, clausula_continuidade, clausula_reversibilidade,
                    data_ultimo_teste_contingencia, nivel_risco, observacoes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    inst_id,
                    payload.get('nome_provedor'),
                    payload.get('servico_prestado'),
                    payload.get('tipo_nuvem', 'IaaS'),
                    payload.get('pais_armazenamento', 'Brasil'),
                    int(payload.get('servico_relevante', 1)),
                    int(payload.get('notificado_bacen', 1)),
                    payload.get('data_notificacao_bacen'),
                    int(payload.get('convenio_bacen_pais', 1)),
                    int(payload.get('clausula_acesso_bacen', 1)),
                    int(payload.get('clausula_segregacao_dados', 1)),
                    int(payload.get('clausula_continuidade', 1)),
                    int(payload.get('clausula_reversibilidade', 1)),
                    payload.get('data_ultimo_teste_contingencia'),
                    payload.get('nivel_risco', 'Baixo'),
                    payload.get('observacoes', '')
                ))
                f_id = cursor.lastrowid
                conn.commit()
                self.send_json({"success": True, "id": f_id})

            # 5. PARI PLAYBOOKS
            elif path == "/api/pari/playbooks":
                payload = json.loads(raw_body.decode('utf-8'))
                cursor.execute("""
                INSERT INTO pari_playbooks (
                    instituicao_id, codigo, titulo_cenario, categoria, etapa_deteccao,
                    etapa_contencao, etapa_erradicacao, etapa_recuperacao, etapa_comunicacao_bacen, tempo_estimado_resposta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    inst_id,
                    payload.get('codigo', f"PB-{datetime.now().strftime('%M%S')}"),
                    payload.get('titulo_cenario'),
                    payload.get('categoria', 'Incidente Geral'),
                    payload.get('etapa_deteccao', ''),
                    payload.get('etapa_contencao', ''),
                    payload.get('etapa_erradicacao', ''),
                    payload.get('etapa_recuperacao', ''),
                    payload.get('etapa_comunicacao_bacen', ''),
                    payload.get('tempo_estimado_resposta', '')
                ))
                pb_id = cursor.lastrowid
                conn.commit()
                self.send_json({"success": True, "id": pb_id})

            # 6. PARI SIMULADOS (TABLETOP DRILLS)
            elif path == "/api/pari/simulados":
                payload = json.loads(raw_body.decode('utf-8'))
                cursor.execute("""
                INSERT INTO pari_simulados (
                    instituicao_id, titulo_simulado, data_realizacao, cenario_testado, participantes,
                    tempo_resposta_alcancado, pontos_fortes, gargalos_identificados, acoes_melhoria, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    inst_id,
                    payload.get('titulo_simulado'),
                    payload.get('data_realizacao', datetime.now().strftime('%Y-%m-%d')),
                    payload.get('cenario_testado'),
                    payload.get('participantes'),
                    payload.get('tempo_resposta_alcancado'),
                    payload.get('pontos_fortes'),
                    payload.get('gargalos_identificados'),
                    payload.get('acoes_melhoria'),
                    payload.get('status', 'Concluido')
                ))
                sim_id = cursor.lastrowid
                conn.commit()
                self.send_json({"success": True, "id": sim_id})

            # 7. INCIDENTES
            elif path == "/api/incidentes":
                payload = json.loads(raw_body.decode('utf-8'))
                cursor.execute("""
                INSERT INTO incidentes (
                    instituicao_id, protocolo, titulo, data_ocorrencia, data_deteccao, categoria, criticidade,
                    sistemas_afetados, impacto_operacional, status, notificado_bacen, data_notificacao_bacen,
                    causa_raiz, acoes_corretivas
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    inst_id,
                    payload.get('protocolo', f"INC-{datetime.now().strftime('%Y-%m%d')}"),
                    payload.get('titulo'),
                    payload.get('data_ocorrencia', datetime.now().isoformat()),
                    payload.get('data_deteccao', datetime.now().isoformat()),
                    payload.get('categoria', 'Intrusão'),
                    payload.get('criticidade', 'Média'),
                    payload.get('sistemas_afetados'),
                    payload.get('impacto_operacional'),
                    payload.get('status', 'Em Análise'),
                    int(payload.get('notificado_bacen', 0)),
                    payload.get('data_notificacao_bacen'),
                    payload.get('causa_raiz'),
                    payload.get('acoes_corretivas')
                ))
                inc_id = cursor.lastrowid
                conn.commit()
                self.send_json({"success": True, "id": inc_id})

            else:
                self.send_json({"error": "Endpoint não encontrado"}, 404)

        finally:
            conn.close()

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        conn = get_db()
        cursor = conn.cursor()

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode('utf-8'))
            inst_id = get_active_institution_id(cursor)

            # 1. ATUALIZAR INSTITUIÇÃO ATIVA
            if path == "/api/instituicao" or path.startswith("/api/instituicao/"):
                target_id = inst_id
                if path.startswith("/api/instituicao/") and path.split("/")[-1].isdigit():
                    target_id = int(path.split("/")[-1])

                cursor.execute("""
                UPDATE instituicao
                SET razao_social = ?, nome_fantasia = ?, cnpj = ?, segmento = ?, tipo_instituicao = ?,
                    registro_unicad = ?, diretor_responsavel = ?, cargo_diretor = ?, email_diretor = ?,
                    telefone_diretor = ?, data_aprovacao_politica = ?, data_ultima_revisao = ?,
                    versao_politica = ?, escopo_operacional = ?
                WHERE id = ?;
                """, (
                    payload.get('razao_social'),
                    payload.get('nome_fantasia'),
                    payload.get('cnpj'),
                    payload.get('segmento'),
                    payload.get('tipo_instituicao'),
                    payload.get('registro_unicad'),
                    payload.get('diretor_responsavel'),
                    payload.get('cargo_diretor'),
                    payload.get('email_diretor'),
                    payload.get('telefone_diretor'),
                    payload.get('data_aprovacao_politica'),
                    payload.get('data_ultima_revisao'),
                    payload.get('versao_politica'),
                    payload.get('escopo_operacional'),
                    target_id
                ))

                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'ATUALIZAR_INSTITUICAO', 'instituicao', ?, ?);
                """, (payload.get('diretor_responsavel', 'Administrador'), target_id, f"Atualizados dados cadastrais da empresa {payload.get('razao_social')}."))

                conn.commit()
                self.send_json({"success": True, "id": target_id})

            # 2. ATUALIZAR GOVERNANÇA DO PARI
            elif path == "/api/pari/governanca":
                cursor.execute("""
                UPDATE pari_governanca
                SET lider_csirt = ?, email_csirt = ?, telefone_plantao_247 = ?, membros_csirt = ?,
                    comite_crise = ?, canais_emergencia = ?, criterios_relevancia_bacen = ?,
                    procedimento_sisbacen = ?, data_ultima_revisao_pari = ?, versao_pari = ?
                WHERE instituicao_id = ?;
                """, (
                    payload.get('lider_csirt'),
                    payload.get('email_csirt'),
                    payload.get('telefone_plantao_247'),
                    payload.get('membros_csirt'),
                    payload.get('comite_crise'),
                    payload.get('canais_emergencia'),
                    payload.get('criterios_relevancia_bacen'),
                    payload.get('procedimento_sisbacen'),
                    payload.get('data_ultima_revisao_pari'),
                    payload.get('versao_pari'),
                    inst_id
                ))
                conn.commit()
                self.send_json({"success": True})

            # 3. ATUALIZAR PLAYBOOK DO PARI
            elif path.startswith("/api/pari/playbooks/"):
                pb_id = path.split("/")[-1]
                cursor.execute("""
                UPDATE pari_playbooks
                SET titulo_cenario = ?, categoria = ?, etapa_deteccao = ?, etapa_contencao = ?,
                    etapa_erradicacao = ?, etapa_recuperacao = ?, etapa_comunicacao_bacen = ?, tempo_estimado_resposta = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    payload.get('titulo_cenario'),
                    payload.get('categoria'),
                    payload.get('etapa_deteccao'),
                    payload.get('etapa_contencao'),
                    payload.get('etapa_erradicacao'),
                    payload.get('etapa_recuperacao'),
                    payload.get('etapa_comunicacao_bacen'),
                    payload.get('tempo_estimado_resposta'),
                    pb_id,
                    inst_id
                ))
                conn.commit()
                self.send_json({"success": True, "id": pb_id})

            # 4. ATUALIZAR AVALIAÇÃO DE COMPLIANCE
            elif path.startswith("/api/avaliacoes/"):
                req_id = path.split("/")[-1]
                status = payload.get('status')
                pct = int(payload.get('percentual_aderencia', 0))
                justificativa = payload.get('justificativa', '')
                responsavel = payload.get('responsavel', '')
                prazo = payload.get('prazo_adequacao')
                auditor = payload.get('avaliador', 'Auditor GRC')
                obs = payload.get('observacoes_auditor', '')

                cursor.execute("""
                INSERT INTO avaliacoes (
                    instituicao_id, requisito_id, status, percentual_aderencia, justificativa,
                    responsavel, prazo_adequacao, avaliador, observacoes_auditor, ultima_auditoria, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'), CURRENT_TIMESTAMP)
                ON CONFLICT(instituicao_id, requisito_id) DO UPDATE SET
                    status = excluded.status,
                    percentual_aderencia = excluded.percentual_aderencia,
                    justificativa = excluded.justificativa,
                    responsavel = excluded.responsavel,
                    prazo_adequacao = excluded.prazo_adequacao,
                    avaliador = excluded.avaliador,
                    observacoes_auditor = excluded.observacoes_auditor,
                    ultima_auditoria = DATE('now'),
                    updated_at = CURRENT_TIMESTAMP;
                """, (inst_id, req_id, status, pct, justificativa, responsavel, prazo, auditor, obs))

                conn.commit()
                self.send_json({"success": True, "requisito_id": req_id})

            # 5. ATUALIZAR PLANOS DE AÇÃO 5W2H
            elif path.startswith("/api/planos_acao/"):
                p_id = path.split("/")[-1]
                cursor.execute("""
                UPDATE planos_acao
                SET status = ?, progresso_pct = ?, data_conclusao = ?, como = ?, quem = ?, quando = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    payload.get('status'),
                    int(payload.get('progresso_pct', 0)),
                    payload.get('data_conclusao'),
                    payload.get('como'),
                    payload.get('quem'),
                    payload.get('quando'),
                    p_id,
                    inst_id
                ))
                conn.commit()
                self.send_json({"success": True, "id": p_id})

            # 6. ATUALIZAR NUVEM
            elif path.startswith("/api/fornecedores_nuvem/"):
                f_id = path.split("/")[-1]
                cursor.execute("""
                UPDATE fornecedores_nuvem
                SET notificado_bacen = ?, convenio_bacen_pais = ?, clausula_acesso_bacen = ?,
                    clausula_segregacao_dados = ?, clausula_continuidade = ?, clausula_reversibilidade = ?,
                    data_ultimo_teste_contingencia = ?, nivel_risco = ?, observacoes = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    int(payload.get('notificado_bacen', 1)),
                    int(payload.get('convenio_bacen_pais', 1)),
                    int(payload.get('clausula_acesso_bacen', 1)),
                    int(payload.get('clausula_segregacao_dados', 1)),
                    int(payload.get('clausula_continuidade', 1)),
                    int(payload.get('clausula_reversibilidade', 1)),
                    payload.get('data_ultimo_teste_contingencia'),
                    payload.get('nivel_risco'),
                    payload.get('observacoes'),
                    f_id,
                    inst_id
                ))
                conn.commit()
                self.send_json({"success": True, "id": f_id})

            else:
                self.send_json({"error": "Endpoint não encontrado"}, 404)

        finally:
            conn.close()

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        conn = get_db()
        cursor = conn.cursor()

        try:
            inst_id = get_active_institution_id(cursor)

            if path.startswith("/api/evidencias/"):
                ev_id = path.split("/")[-1]
                cursor.execute("SELECT caminho_arquivo FROM evidencias WHERE id = ? AND instituicao_id = ?;", (ev_id, inst_id))
                row = cursor.fetchone()
                if row and row['caminho_arquivo']:
                    disk_path = os.path.join(BASE_DIR, row['caminho_arquivo'].lstrip('/'))
                    if os.path.exists(disk_path):
                        try:
                            os.remove(disk_path)
                        except Exception:
                            pass
                cursor.execute("DELETE FROM evidencias WHERE id = ? AND instituicao_id = ?;", (ev_id, inst_id))
                conn.commit()
                self.send_json({"success": True, "deleted_id": ev_id})

            elif path.startswith("/api/planos_acao/"):
                p_id = path.split("/")[-1]
                cursor.execute("DELETE FROM planos_acao WHERE id = ? AND instituicao_id = ?;", (p_id, inst_id))
                conn.commit()
                self.send_json({"success": True, "deleted_id": p_id})

            elif path.startswith("/api/pari/playbooks/"):
                pb_id = path.split("/")[-1]
                cursor.execute("DELETE FROM pari_playbooks WHERE id = ? AND instituicao_id = ?;", (pb_id, inst_id))
                conn.commit()
                self.send_json({"success": True, "deleted_id": pb_id})

            elif path.startswith("/api/pari/simulados/"):
                sim_id = path.split("/")[-1]
                cursor.execute("DELETE FROM pari_simulados WHERE id = ? AND instituicao_id = ?;", (sim_id, inst_id))
                conn.commit()
                self.send_json({"success": True, "deleted_id": sim_id})

            elif path.startswith("/api/instituicoes/"):
                del_id = path.split("/")[-1]
                cursor.execute("SELECT COUNT(*) as count FROM instituicao;")
                total = cursor.fetchone()['count']
                if total <= 1:
                    self.send_json({"error": "Não é possível excluir a única instituição existente."}, 400)
                    return
                cursor.execute("DELETE FROM avaliacoes WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM evidencias WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM planos_acao WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM fornecedores_nuvem WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM pari_playbooks WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM pari_simulados WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM pari_governanca WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM incidentes WHERE instituicao_id = ?;", (del_id,))
                cursor.execute("DELETE FROM instituicao WHERE id = ?;", (del_id,))
                # Ativar a primeira restante se a ativa foi excluída
                cursor.execute("UPDATE instituicao SET is_ativa = 1 WHERE id = (SELECT id FROM instituicao LIMIT 1);")
                conn.commit()
                self.send_json({"success": True, "deleted_id": del_id})

            else:
                self.send_json({"error": "Endpoint não encontrado"}, 404)

        finally:
            conn.close()

    def get_dashboard_metrics(self, cursor, inst_id):
        cursor.execute("SELECT COUNT(*) as total FROM requisitos;")
        total_req = cursor.fetchone()['total']

        cursor.execute("""
        SELECT COALESCE(a.status, 'nao_atendido') as status, COUNT(*) as count, AVG(COALESCE(a.percentual_aderencia, 0)) as avg_pct
        FROM requisitos r
        LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
        GROUP BY COALESCE(a.status, 'nao_atendido');
        """, (inst_id,))

        status_map = {
            'atendido': 0,
            'parcialmente_atendido': 0,
            'em_implementacao': 0,
            'nao_atendido': 0,
            'nao_aplicavel': 0
        }
        for r in cursor.fetchall():
            status_map[r['status']] = r['count']

        cursor.execute("""
        SELECT AVG(COALESCE(a.percentual_aderencia, 0)) as global_avg
        FROM requisitos r
        LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?;
        """, (inst_id,))
        global_avg = cursor.fetchone()['global_avg'] or 0.0

        cursor.execute("""
        SELECT r.numero_controle_5274, r.codigo, r.titulo,
               COALESCE(a.status, 'nao_atendido') as status,
               COALESCE(a.percentual_aderencia, 0) as percentual_aderencia
        FROM requisitos r
        LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
        WHERE r.is_cmn_5274_obrigatorio = 1
        ORDER BY r.numero_controle_5274 ASC;
        """, (inst_id,))
        cmn_5274_controles = [dict_from_row(r) for r in cursor.fetchall()]

        cmn_5274_stats = {
            'total': len(cmn_5274_controles),
            'atendido': sum(1 for c in cmn_5274_controles if c['status'] == 'atendido'),
            'parcialmente_atendido': sum(1 for c in cmn_5274_controles if c['status'] == 'parcialmente_atendido'),
            'em_implementacao': sum(1 for c in cmn_5274_controles if c['status'] == 'em_implementacao'),
            'nao_atendido': sum(1 for c in cmn_5274_controles if c['status'] == 'nao_atendido'),
            'aderencia_media': round(sum(c['percentual_aderencia'] for c in cmn_5274_controles) / (len(cmn_5274_controles) or 1), 1)
        }

        cursor.execute("""
        SELECT d.id, d.codigo, d.nome, d.icone, d.artigo_referencia,
               COUNT(r.id) as total_requisitos,
               SUM(CASE WHEN a.status = 'atendido' THEN 1 ELSE 0 END) as atendidos,
               SUM(CASE WHEN a.status = 'parcialmente_atendido' THEN 1 ELSE 0 END) as parciais,
               SUM(CASE WHEN a.status = 'em_implementacao' THEN 1 ELSE 0 END) as em_implementacao,
               SUM(CASE WHEN a.status = 'nao_atendido' OR a.status IS NULL THEN 1 ELSE 0 END) as nao_atendidos,
               ROUND(AVG(COALESCE(a.percentual_aderencia, 0)), 1) as score_medio
        FROM dominios d
        LEFT JOIN requisitos r ON r.dominio_id = d.id
        LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
        GROUP BY d.id
        ORDER BY d.ordem ASC;
        """, (inst_id,))
        dominios_stats = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("SELECT COUNT(*) as total FROM evidencias WHERE instituicao_id = ?;", (inst_id,))
        total_evidencias = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM planos_acao WHERE instituicao_id = ? AND status != 'Concluido';", (inst_id,))
        planos_em_aberto = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM fornecedores_nuvem WHERE instituicao_id = ? AND notificado_bacen = 1;", (inst_id,))
        fornecedores_notificados = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM incidentes WHERE instituicao_id = ?;", (inst_id,))
        total_incidentes = cursor.fetchone()['total']

        cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (inst_id,))
        inst = dict_from_row(cursor.fetchone())

        return {
            "instituicao": inst,
            "resumo_kpi": {
                "total_requisitos": total_req,
                "atendidos": status_map['atendido'],
                "parcialmente_atendidos": status_map['parcialmente_atendido'],
                "em_implementacao": status_map['em_implementacao'],
                "nao_atendidos": status_map['nao_atendido'],
                "nao_aplicaveis": status_map['nao_aplicavel'],
                "percentual_aderencia_global": round(global_avg, 1),
                "total_evidencias": total_evidencias,
                "planos_em_aberto": planos_em_aberto,
                "fornecedores_nuvem": fornecedores_notificados,
                "total_incidentes": total_incidentes
            },
            "cmn_5274_controles": cmn_5274_controles,
            "cmn_5274_stats": cmn_5274_stats,
            "dominios_stats": dominios_stats
        }

    def generate_annual_report(self, cursor, inst_id):
        cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (inst_id,))
        inst = dict_from_row(cursor.fetchone())
        dashboard = self.get_dashboard_metrics(cursor, inst_id)

        cursor.execute("""
        SELECT r.codigo, r.artigo, r.titulo, r.is_cmn_5274_obrigatorio,
               COALESCE(a.status, 'nao_atendido') as status,
               COALESCE(a.percentual_aderencia, 0) as percentual_aderencia,
               a.justificativa, a.responsavel, a.observacoes_auditor
        FROM requisitos r
        LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
        ORDER BY r.is_cmn_5274_obrigatorio DESC, r.id ASC;
        """, (inst_id,))
        todos_requisitos = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM fornecedores_nuvem WHERE instituicao_id = ? ORDER BY id ASC;", (inst_id,))
        fornecedores = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM incidentes WHERE instituicao_id = ? ORDER BY data_ocorrencia DESC;", (inst_id,))
        incidentes = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM planos_acao WHERE instituicao_id = ? ORDER BY quando ASC;", (inst_id,))
        planos = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM pari_governanca WHERE instituicao_id = ? LIMIT 1;", (inst_id,))
        pari_gov = dict_from_row(cursor.fetchone())

        diretor = inst['diretor_responsavel'] if inst else 'Diretor Estatutário'
        razao = inst['razao_social'] if inst else 'Instituição Financeira'

        return {
            "instituicao": inst,
            "data_base": "31 de dezembro de 2025",
            "data_emissao": datetime.now().strftime("%d/%m/%Y"),
            "kpis": dashboard['resumo_kpi'],
            "cmn_5274_stats": dashboard['cmn_5274_stats'],
            "requisitos": todos_requisitos,
            "fornecedores_nuvem": fornecedores,
            "incidentes": incidentes,
            "planos_acao": planos,
            "pari_governanca": pari_gov,
            "conclusao_diretor": (
                f"Declaro, na qualidade de Diretor Estatutário responsável pela Política de Segurança Cibernética "
                f"da instituição {razao} perante o Banco Central do Brasil, nos termos do Art. 7º e 8º "
                f"da Resolução CMN nº 4.893/2021 e alterações da Resolução CMN nº 5.274/2025, que as informações "
                f"contidas neste relatório refletem com fidedignidade o estado de maturidade dos controles de segurança, "
                f"a efetividade do Plano de Ação e de Resposta a Incidentes (PARI), e os planos de adequação contínua."
            )
        }

    def export_csv(self, cursor, inst_id):
        cursor.execute("""
        SELECT r.codigo, d.nome as dominio, r.artigo, r.titulo, r.severidade,
               r.is_cmn_5274_obrigatorio, r.numero_controle_5274,
               COALESCE(a.status, 'nao_atendido') as status,
               COALESCE(a.percentual_aderencia, 0) as percentual_aderencia,
               a.responsavel, a.prazo_adequacao,
               a.justificativa, a.observacoes_auditor
        FROM requisitos r
        JOIN dominios d ON r.dominio_id = d.id
        LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
        ORDER BY r.id ASC;
        """, (inst_id,))
        rows = cursor.fetchall()
        import io
        import csv

        output = io.StringIO()
        writer = csv.writer(output, delimiter=';')
        writer.writerow([
            'Código', 'Domínio', 'Artigo Normativo', 'Título do Requisito', 'Severidade',
            'Obrigatório Res. 5.274', 'Nº Controle 5.274', 'Status', 'Aderência (%)',
            'Responsável', 'Prazo de Adequação', 'Justificativa Técnica', 'Observações Auditor'
        ])
        for r in rows:
            writer.writerow([
                r['codigo'], r['dominio'], r['artigo'], r['titulo'], r['severidade'],
                'Sim' if r['is_cmn_5274_obrigatorio'] else 'Não',
                r['numero_controle_5274'] or '',
                r['status'], f"{r['percentual_aderencia']}%",
                r['responsavel'] or '', r['prazo_adequacao'] or '',
                r['justificativa'] or '', r['observacoes_auditor'] or ''
            ])

        csv_bytes = output.getvalue().encode('utf-8-sig')
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8-sig')
        self.send_header('Content-Disposition', 'attachment; filename="Compliance_BACEN_4893_5274.csv"')
        self.send_header('Content-Length', str(len(csv_bytes)))
        self.end_headers()
        self.wfile.write(csv_bytes)

    def export_full_json(self, cursor, inst_id):
        report = self.generate_annual_report(cursor, inst_id)
        body = json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="Compliance_BACEN_4893_5274.json"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_file(self, full_path, content_type):
        if not os.path.exists(full_path):
            self.send_json({"error": "Arquivo não encontrado"}, 404)
            return
        with open(full_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

def run():
    server_address = ('0.0.0.0', PORT)
    httpd = socketserver.TCPServer(server_address, ComplianceAPIHandler)
    print(f"============================================================")
    print(f"  BACEN CMN 4.893 & 5.274 GRC Compliance System Started")
    print(f"  Listening on http://localhost:{PORT}")
    print(f"============================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    run()
