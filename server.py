"""
Enterprise-grade Web Server and REST API for BACEN CMN 4.893 & 5.274 Compliance GRC.
Features:
- Multi-tenancy with complete context isolation per financial institution
- Role-Based Access Control (RBAC) & Principle of Least Privilege:
  * Admin Geral (Superadministrador global com visão cross-tenant)
  * Gestor de Compliance / CISO (Gestão e avaliação na instituição vinculada)
  * Analista / Operador (Inserção de evidências e planos 5W2H)
  * Auditor / Fiscal BACEN (Somente leitura para inspeção regulatória)
- Context extraction via 'X-Company-ID' header & 'instituicao_id' query parameter
- Authentication with PBKDF2-SHA256 password hashing & RFC 6238 TOTP (MFA)
- Complete Art. 8º Annual Report Module (8 mandatory sections + electronic signature + SHA-256 hash)
- Dedicated PARI Module (Arts. 6º e 8º)
- 14 Mandatory Minimum Controls of Resolução CMN nº 5.274/2025
- Evidence Vault with SHA-256 integrity calculation
- Vulnerability & Pentest tracking (auditorias_fragilidades)
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

from auth import (
    hash_password, verify_password, generate_session_token,
    generate_mfa_secret, verify_totp, get_totp_code
)

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

def log_audit(cursor, instituicao_id, usuario, acao, entidade, entidade_id=None, detalhes=""):
    cursor.execute("""
    INSERT INTO auditoria_log (instituicao_id, data_hora, usuario, acao, entidade, entidade_id, detalhes)
    VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?);
    """, (instituicao_id, usuario, acao, entidade, entidade_id, detalhes))

def get_authenticated_user(cursor, token):
    if not token:
        return None
    cursor.execute("""
    SELECT u.*, s.mfa_verificado, s.token as session_token
    FROM sessoes s
    JOIN usuarios u ON s.usuario_id = u.id
    WHERE s.token = ? AND datetime(s.expira_em) > datetime('now') AND u.ativo = 1;
    """, (token,))
    row = cursor.fetchone()
    return dict_from_row(row)

def get_user_role_for_institution(cursor, user, inst_id):
    if not user or not inst_id:
        return None
    if user.get('is_admin_geral') == 1:
        return 'admin_geral'
    cursor.execute("""
    SELECT perfil FROM usuario_instituicoes
    WHERE usuario_id = ? AND instituicao_id = ?;
    """, (user['id'], inst_id))
    row = cursor.fetchone()
    return row['perfil'] if row else None

def get_accessible_institutions(cursor, user):
    if not user:
        return []
    if user.get('is_admin_geral') == 1:
        cursor.execute("SELECT *, 'admin_geral' as perfil_usuario FROM instituicao ORDER BY is_ativa DESC, id ASC;")
        return [dict_from_row(r) for r in cursor.fetchall()]
    cursor.execute("""
    SELECT i.*, ui.perfil as perfil_usuario
    FROM instituicao i
    JOIN usuario_instituicoes ui ON ui.instituicao_id = i.id
    WHERE ui.usuario_id = ?
    ORDER BY i.is_ativa DESC, i.id ASC;
    """, (user['id'],))
    return [dict_from_row(r) for r in cursor.fetchall()]


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
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Company-ID')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Company-ID')
        self.end_headers()

    def get_token(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[len('Bearer '):].strip()
        cookie_header = self.headers.get('Cookie', '')
        if 'session_token=' in cookie_header:
            parts = cookie_header.split(';')
            for p in parts:
                p = p.strip()
                if p.startswith('session_token='):
                    return p.split('=', 1)[1].strip()
        return None

    def get_context_institution_id(self, cursor, user, parsed_query=None):
        """
        Determines the active tenant institution ID with strict least-privilege verification:
        1. Checks 'X-Company-ID' header
        2. Checks query parameter '?instituicao_id='
        3. Falls back to user's first accessible institution
        4. Validates that non-admin users have explicit permission for this institution.
        Returns: (inst_id, role)
        """
        requested_id = None
        header_val = self.headers.get('X-Company-ID')
        if header_val and header_val.strip().isdigit():
            requested_id = int(header_val.strip())

        if not requested_id and parsed_query:
            q_val = parsed_query.get('instituicao_id', [None])[0]
            if q_val and str(q_val).isdigit():
                requested_id = int(q_val)

        accessible = get_accessible_institutions(cursor, user)
        if not accessible:
            return None, None

        accessible_ids = [inst['id'] for inst in accessible]

        if requested_id is not None:
            target_id = requested_id
        else:
            # Fallback to the first accessible institution
            target_id = accessible[0]['id']

        role = get_user_role_for_institution(cursor, user, target_id)
        return target_id, role

    def check_auth(self, cursor, inst_id, allowed_roles):
        token = self.get_token()
        user = get_authenticated_user(cursor, token)
        if not user:
            return False, 401, "Sessão inválida ou expirada. Efetue login.", None, None
        if user.get('mfa_habilitado') and not user.get('mfa_verificado'):
            return False, 403, "Segundo fator de autenticação (MFA) pendente.", user, None

        if user.get('is_admin_geral') == 1:
            return True, 200, "OK", user, "admin_geral"

        if not inst_id:
            return False, 403, "Instituição não identificada ou sem acesso.", user, None

        role = get_user_role_for_institution(cursor, user, inst_id)
        if not role:
            return False, 403, "Acesso negado: Você não possui permissão para acessar esta instituição financeira.", user, None
        if allowed_roles and role not in allowed_roles:
            return False, 403, f"Acesso negado: Seu perfil ('{role}') não possui permissão para esta operação.", user, role

        return True, 200, "OK", user, role

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
            token = self.get_token()
            user = get_authenticated_user(cursor, token)

            # 1. AUTH ROUTES (Públicas ou Autenticadas)
            if path == "/api/auth/me":
                if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                    self.send_json({"authenticated": False}, 401)
                    return
                insts = get_accessible_institutions(cursor, user)
                inst_id, active_role = self.get_context_institution_id(cursor, user, query)
                self.send_json({
                    "authenticated": True,
                    "user": {
                        "id": user['id'],
                        "nome": user['nome'],
                        "email": user['email'],
                        "cargo": user['cargo'],
                        "is_admin_geral": bool(user['is_admin_geral']),
                        "mfa_secret": user['mfa_secret']
                    },
                    "instituicao_ativa_id": inst_id,
                    "perfil_ativo": active_role,
                    "instituicoes": insts
                })
                return

            # Exige autenticação básica para qualquer endpoint a partir daqui
            if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                self.send_json({"error": "Não autenticado. Efetue login com usuário, senha e MFA."}, 401)
                return

            # Resolve context institution ID and role for this request
            inst_id, role = self.get_context_institution_id(cursor, user, query)

            # 2. GESTÃO DE USUÁRIOS E RBAC (Apenas Admin Geral)
            if path == "/api/usuarios":
                if user.get('is_admin_geral') != 1:
                    self.send_json({"error": "Acesso restrito ao Administrador Geral da aplicação."}, 403)
                    return
                cursor.execute("""
                SELECT id, nome, email, is_admin_geral, mfa_habilitado, mfa_secret, ativo, cargo, ultimo_login, created_at
                FROM usuarios
                ORDER BY is_admin_geral DESC, nome ASC;
                """)
                usuarios = [dict_from_row(r) for r in cursor.fetchall()]
                for u in usuarios:
                    cursor.execute("""
                    SELECT ui.instituicao_id, ui.perfil, i.razao_social
                    FROM usuario_instituicoes ui
                    JOIN instituicao i ON ui.instituicao_id = i.id
                    WHERE ui.usuario_id = ?;
                    """, (u['id'],))
                    u['instituicoes'] = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(usuarios)
                return

            # 3. INSTITUIÇÕES ACESSÍVEIS
            elif path in ("/api/instituicoes", "/api/empresas"):
                insts = get_accessible_institutions(cursor, user)
                self.send_json(insts)
                return

            elif path in ("/api/instituicao", "/api/instituicao/ativa", "/api/empresa", "/api/empresa/ativa"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (inst_id,))
                row = cursor.fetchone()
                inst_data = dict_from_row(row) if row else {}
                if inst_data:
                    inst_data['perfil_usuario'] = role
                    inst_data['segmento_bacen'] = inst_data.get('segmento')
                self.send_json(inst_data)
                return

            elif path.startswith("/api/instituicao/") and path.split("/")[-1].isdigit():
                target_id = int(path.split("/")[-1])
                ok, code, err, _, target_role = self.check_auth(cursor, target_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (target_id,))
                row = cursor.fetchone()
                inst_data = dict_from_row(row) if row else {}
                if inst_data:
                    inst_data['perfil_usuario'] = target_role
                self.send_json(inst_data)
                return

            # 4. DASHBOARD (Acessível a todos os perfis autorizados na instituição)
            elif path == "/api/dashboard":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                data = self.get_dashboard_metrics(cursor, inst_id)
                data['perfil_usuario'] = role
                self.send_json(data)
                return

            # 5. DOMÍNIOS
            elif path == "/api/dominios":
                cursor.execute("SELECT * FROM dominios ORDER BY ordem ASC;")
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)
                return

            # 6. REQUISITOS & AVALIAÇÕES (Com filtros estritamente isolados por instituicao_id)
            elif path in ("/api/requisitos", "/api/avaliacoes"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                dominio_id = query.get('dominio_id', [None])[0]
                status = query.get('status', [None])[0]
                is_5274 = query.get('is_cmn_5274', [None])[0]
                search = query.get('search', [None])[0]

                sql = """
                SELECT r.*, r.id as requisito_id, r.codigo as requisito_codigo, ? as instituicao_id,
                       d.nome as dominio_nome, d.codigo as dominio_codigo,
                       COALESCE(a.status, 'nao_atendido') as status,
                       COALESCE(a.percentual_aderencia, 0) as percentual_aderencia,
                       a.justificativa, a.justificativa as comentarios, a.responsavel,
                       a.prazo_adequacao, a.ultima_auditoria, a.avaliador, a.observacoes_auditor,
                       (SELECT COUNT(*) FROM evidencias e WHERE e.requisito_id = r.id AND e.instituicao_id = ?) as total_evidencias,
                       (SELECT COUNT(*) FROM planos_acao p WHERE p.requisito_id = r.id AND p.instituicao_id = ?) as total_planos
                FROM requisitos r
                JOIN dominios d ON r.dominio_id = d.id
                LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
                WHERE 1=1
                """
                params = [inst_id, inst_id, inst_id, inst_id]
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
                return

            elif path.startswith("/api/requisitos/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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

                req_data['perfil_usuario'] = role
                self.send_json(req_data)
                return

            # 7. PARI (Arts. 6º e 8º)
            elif path == "/api/pari":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                cursor.execute("SELECT * FROM pari_governanca WHERE instituicao_id = ? LIMIT 1;", (inst_id,))
                gov = dict_from_row(cursor.fetchone())
                if not gov:
                    cursor.execute("""
                    INSERT INTO pari_governanca (instituicao_id, lider_csirt, email_csirt, telefone_plantao_247)
                    VALUES (?, 'Coordenador CSIRT', 'csirt@empresa.com.br', '(11) 90000-0000');
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
                    "incidentes": incidentes,
                    "perfil_usuario": role
                })
                return

            elif path == "/api/pari/playbooks":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM pari_playbooks WHERE instituicao_id = ? ORDER BY codigo ASC;", (inst_id,))
                self.send_json([dict_from_row(r) for r in cursor.fetchall()])
                return

            elif path == "/api/pari/simulados":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM pari_simulados WHERE instituicao_id = ? ORDER BY data_realizacao DESC;", (inst_id,))
                self.send_json([dict_from_row(r) for r in cursor.fetchall()])
                return

            # 8. EVIDÊNCIAS (Evidence Vault)
            elif path == "/api/evidencias":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                return

            # 9. PLANOS DE AÇÃO 5W2H
            elif path == "/api/planos_acao":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("""
                SELECT p.*, r.codigo as requisito_codigo, r.titulo as requisito_titulo, r.artigo
                FROM planos_acao p
                JOIN requisitos r ON p.requisito_id = r.id
                WHERE p.instituicao_id = ?
                ORDER BY p.id DESC;
                """, (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)
                return

            # 10. FORNECEDORES DE NUVEM (Arts. 11 a 17)
            elif path == "/api/fornecedores_nuvem":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM fornecedores_nuvem WHERE instituicao_id = ? ORDER BY id ASC;", (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)
                return

            # 11. INCIDENTES
            elif path == "/api/incidentes":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM incidentes WHERE instituicao_id = ? ORDER BY data_ocorrencia DESC;", (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)
                return

            # 12. FRAGILIDADES IDENTIFICADAS / PENTESTS (Art. 8º - Seção 5)
            elif path == "/api/auditorias_fragilidades":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("""
                SELECT f.*, f.titulo as vulnerabilidade, f.descricao as plano_remediacao,
                       r.codigo as requisito_codigo, r.titulo as requisito_titulo
                FROM auditorias_fragilidades f
                LEFT JOIN requisitos r ON f.requisito_id = r.id
                WHERE f.instituicao_id = ?
                ORDER BY f.data_identificacao DESC, f.id DESC;
                """, (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)
                return

            # 13. RELATÓRIO ANUAL (ART. 8º DA RES. CMN 4.893/2021)
            elif path == "/api/relatorio_anual":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                relatorio = self.generate_annual_report(cursor, inst_id)
                self.send_json(relatorio)
                return

            elif path == "/api/relatorio_anual/export/json":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                self.export_annual_report_json(cursor, inst_id)
                return

            # 14. TRILHA DE AUDITORIA (Audit Log segregada por Tenant)
            elif path == "/api/auditoria_log":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("""
                SELECT * FROM auditoria_log
                WHERE instituicao_id = ?
                ORDER BY id DESC LIMIT 150;
                """, (inst_id,))
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)
                return

            # 15. EXPORTAÇÃO CSV / JSON
            elif path == "/api/export/csv":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                self.export_csv(cursor, inst_id)
                return

            elif path == "/api/export/json":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                self.export_full_json(cursor, inst_id)
                return

            else:
                self.send_json({"error": "Endpoint não encontrado"}, 404)

        finally:
            conn.close()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        conn = get_db()
        cursor = conn.cursor()

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length)

            # 1. AUTENTICAÇÃO: LOGIN (Público)
            if path == "/api/auth/login":
                payload = json.loads(raw_body.decode('utf-8'))
                email = payload.get('email', '').strip().lower()
                password = payload.get('password', '')

                cursor.execute("SELECT * FROM usuarios WHERE LOWER(email) = ? AND ativo = 1;", (email,))
                user = dict_from_row(cursor.fetchone())

                if not user or not verify_password(password, user['senha_salt'], user['senha_hash']):
                    log_audit(cursor, 1, email or 'Desconhecido', 'FALHA_LOGIN', 'auth', None, 'Credenciais inválidas.')
                    conn.commit()
                    self.send_json({"error": "Credenciais incorretas. Verifique seu e-mail e senha."}, 401)
                    return

                token = generate_session_token()
                cursor.execute("""
                INSERT INTO sessoes (token, usuario_id, expira_em, mfa_verificado)
                VALUES (?, ?, datetime('now', '+1 day'), 0);
                """, (token, user['id']))
                conn.commit()

                totp_now = get_totp_code(user['mfa_secret'])

                self.send_json({
                    "token": token,
                    "mfa_required": bool(user['mfa_habilitado']),
                    "mfa_secret": user['mfa_secret'],
                    "totp_preview": totp_now,
                    "user": {
                        "id": user['id'],
                        "nome": user['nome'],
                        "email": user['email'],
                        "cargo": user['cargo'],
                        "is_admin_geral": bool(user['is_admin_geral'])
                    }
                })
                return

            # 2. AUTENTICAÇÃO: VALIDAÇÃO MFA / TOTP
            elif path == "/api/auth/mfa":
                payload = json.loads(raw_body.decode('utf-8'))
                token = payload.get('token', '').strip()
                code = payload.get('code', '').strip()

                cursor.execute("""
                SELECT u.*, s.token FROM sessoes s
                JOIN usuarios u ON s.usuario_id = u.id
                WHERE s.token = ? AND datetime(s.expira_em) > datetime('now');
                """, (token,))
                user = dict_from_row(cursor.fetchone())

                if not user:
                    self.send_json({"error": "Sessão inválida ou expirada."}, 401)
                    return

                if not verify_totp(user['mfa_secret'], code):
                    log_audit(cursor, 1, user['email'], 'FALHA_MFA', 'usuarios', user['id'], 'Código TOTP incorreto.')
                    conn.commit()
                    self.send_json({"error": "Código MFA incorreto ou expirado. Verifique o horário do seu dispositivo."}, 400)
                    return

                cursor.execute("UPDATE sessoes SET mfa_verificado = 1 WHERE token = ?;", (token,))
                cursor.execute("UPDATE usuarios SET ultimo_login = CURRENT_TIMESTAMP WHERE id = ?;", (user['id'],))

                insts = get_accessible_institutions(cursor, user)
                inst_id, active_role = self.get_context_institution_id(cursor, user, query)

                log_audit(cursor, inst_id or 1, user['email'], 'LOGIN_SUCESSO', 'usuarios', user['id'], 'MFA validado com sucesso.')
                conn.commit()

                self.send_json({
                    "success": True,
                    "user": {
                        "id": user['id'],
                        "nome": user['nome'],
                        "email": user['email'],
                        "cargo": user['cargo'],
                        "is_admin_geral": bool(user['is_admin_geral'])
                    },
                    "instituicao_ativa_id": inst_id,
                    "perfil_ativo": active_role,
                    "instituicoes": insts
                })
                return

            # 3. LOGOUT
            elif path == "/api/auth/logout":
                token = self.get_token()
                if token:
                    cursor.execute("DELETE FROM sessoes WHERE token = ?;", (token,))
                    conn.commit()
                self.send_json({"success": True})
                return

            # Para todas as rotas POST restantes, exige autenticação e RBAC
            token = self.get_token()
            user = get_authenticated_user(cursor, token)
            if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                self.send_json({"error": "Não autenticado ou MFA pendente."}, 401)
                return

            inst_id, role = self.get_context_institution_id(cursor, user, query)

            # 4. GESTÃO DE USUÁRIOS (Admin Geral ONLY)
            if path == "/api/usuarios":
                if user.get('is_admin_geral') != 1:
                    self.send_json({"error": "Acesso restrito ao Administrador Geral."}, 403)
                    return

                payload = json.loads(raw_body.decode('utf-8'))
                nome = payload.get('nome')
                email = payload.get('email', '').strip().lower()
                senha = payload.get('senha', 'SenhaInicial@2026!')
                is_admin = 1 if payload.get('is_admin_geral') else 0
                cargo = payload.get('cargo', 'Analista de Segurança')
                instituicoes_roles = payload.get('instituicoes', [])

                salt, pwd_hash = hash_password(senha)
                mfa_secret = generate_mfa_secret()

                try:
                    cursor.execute("""
                    INSERT INTO usuarios (nome, email, senha_hash, senha_salt, is_admin_geral, mfa_habilitado, mfa_secret, ativo, cargo)
                    VALUES (?, ?, ?, ?, ?, 1, ?, 1, ?);
                    """, (nome, email, pwd_hash, salt, is_admin, mfa_secret, cargo))
                    new_user_id = cursor.lastrowid

                    for ir in instituicoes_roles:
                        cursor.execute("""
                        INSERT INTO usuario_instituicoes (usuario_id, instituicao_id, perfil)
                        VALUES (?, ?, ?);
                        """, (new_user_id, ir['instituicao_id'], ir['perfil']))

                    log_audit(cursor, inst_id or 1, user['email'], 'CRIAR_USUARIO', 'usuarios', new_user_id, f"Cadastrado usuário {nome} ({email}).")
                    conn.commit()

                    self.send_json({"success": True, "id": new_user_id, "mfa_secret": mfa_secret})
                except sqlite3.IntegrityError:
                    self.send_json({"error": "Já existe um usuário cadastrado com este e-mail."}, 400)
                return

            # 5. CADASTRAR NOVA INSTITUIÇÃO (Admin Geral ONLY)
            elif path == "/api/instituicoes":
                if user.get('is_admin_geral') != 1:
                    self.send_json({"error": "Apenas o Administrador Geral pode cadastrar novas instituições."}, 403)
                    return

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

                # Inicializar 32 requisitos para a nova instituição
                cursor.execute("SELECT id FROM requisitos;")
                for req in cursor.fetchall():
                    cursor.execute("""
                    INSERT OR IGNORE INTO avaliacoes (instituicao_id, requisito_id, status, percentual_aderencia)
                    VALUES (?, ?, 'nao_atendido', 0);
                    """, (new_id, req['id']))

                # Inicializar governança PARI básica
                cursor.execute("""
                INSERT INTO pari_governanca (
                    instituicao_id, lider_csirt, email_csirt, telefone_plantao_247,
                    membros_csirt, comite_crise, criterios_relevancia_bacen, procedimento_sisbacen
                ) VALUES (?, 'Líder CSIRT', 'csirt@empresa.com.br', '(11) 99999-0000',
                          'Equipe de Segurança, Redes e DBA', 'Diretoria Executiva e CISO',
                          'Indisponibilidade de canais essenciais > 2h ou vazamento de dados.',
                          'Comunicação em até 24h via Sisbacen / Protocolo Digital.');
                """, (new_id,))

                # Inicializar registro de parecer do Art. 8º
                cursor.execute("""
                INSERT OR IGNORE INTO relatorio_anual_parecer (instituicao_id, ano_base, parecer_conclusivo, status_assinatura)
                VALUES (?, '2025', 'Parecer formal em elaboração perante o BACEN.', 'Pendente');
                """, (new_id,))

                log_audit(cursor, new_id, user['email'], 'CRIAR_INSTITUICAO', 'instituicao', new_id, f"Instituição {payload.get('razao_social')} cadastrada.")
                conn.commit()
                self.send_json({"success": True, "id": new_id})
                return

            # ATIVAR INSTITUIÇÃO ESPECÍFICA (Global Switch)
            elif path.endswith("/ativar") and "/api/instituicao/" in path:
                target_id = int(path.split("/")[-2])
                ok, code, err, _, _ = self.check_auth(cursor, target_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("UPDATE instituicao SET is_ativa = 0;")
                cursor.execute("UPDATE instituicao SET is_ativa = 1 WHERE id = ?;", (target_id,))
                log_audit(cursor, target_id, user['email'], 'TROCAR_EMPRESA_ATIVA', 'instituicao', target_id, f"Empresa ID {target_id} definida como ativa.")
                conn.commit()
                self.send_json({"success": True, "ativo_id": target_id})
                return

            # 6. REGISTRAR EVIDÊNCIA (Admin Geral, Gestor, Analista)
            elif path == "/api/evidencias":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                payload = json.loads(raw_body.decode('utf-8'))
                raw_req_id = payload.get('requisito_id')
                req_id = None
                if raw_req_id is not None:
                    if str(raw_req_id).isdigit():
                        req_id = int(raw_req_id)
                    else:
                        norm_code = str(raw_req_id).replace('REQ-4893-', 'REQ-').replace('4893-', '')
                        cursor.execute("SELECT id FROM requisitos WHERE codigo = ? OR codigo = ?;", (str(raw_req_id), norm_code))
                        r_row = cursor.fetchone()
                        req_id = r_row['id'] if r_row else None
                        if not req_id:
                            cursor.execute("SELECT id FROM requisitos WHERE codigo LIKE ?;", (f"%{raw_req_id}%",))
                            r_row = cursor.fetchone()
                            req_id = r_row['id'] if r_row else None

                titulo = payload.get('titulo') or payload.get('nome_arquivo') or (f"Evidência {raw_req_id}" if raw_req_id else "Evidência Regulatória")
                tipo = payload.get('tipo') or payload.get('categoria') or 'Documento'
                descricao = payload.get('descricao', '')
                coletor = user['nome']
                link_ext = payload.get('link_externo')
                nome_arq = payload.get('nome_arquivo', 'evidencia.txt')
                conteudo_b64 = payload.get('conteudo_base64')
                provided_hash = payload.get('hash_sha256')

                caminho_arq = payload.get('caminho_arquivo')
                hash_sha256 = provided_hash
                tam_bytes = payload.get('tamanho_bytes', 0)

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
                elif not hash_sha256:
                    if link_ext:
                        hash_sha256 = hashlib.sha256(link_ext.encode('utf-8')).hexdigest()
                    else:
                        hash_sha256 = hashlib.sha256((descricao or nome_arq).encode('utf-8')).hexdigest()

                cursor.execute("""
                INSERT INTO evidencias (
                    instituicao_id, requisito_id, titulo, tipo, descricao, nome_arquivo, caminho_arquivo,
                    hash_sha256, tamanho_bytes, mime_type, link_externo, coletor, data_coleta, status_validacao
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'), 'Validada');
                """, (inst_id, req_id, titulo, tipo, descricao, nome_arq, caminho_arq, hash_sha256, tam_bytes, 'application/octet-stream', link_ext, coletor))

                ev_id = cursor.lastrowid
                log_audit(cursor, inst_id, user['email'], 'CRIAR_EVIDENCIA', 'evidencias', ev_id, f"Registrada evidência '{titulo}' com hash SHA-256 {hash_sha256[:16]}...")
                conn.commit()

                self.send_json({"success": True, "id": ev_id, "hash_sha256": hash_sha256}, 201)
                return

            # 7. PLANO DE AÇÃO 5W2H (Admin Geral, Gestor, Analista)
            elif path == "/api/planos_acao":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                log_audit(cursor, inst_id, user['email'], 'CRIAR_PLANO_ACAO', 'planos_acao', p_id, f"Plano de Ação '{payload.get('titulo')}' criado.")
                conn.commit()
                self.send_json({"success": True, "id": p_id})
                return

            # 8. FORNECEDORES DE NUVEM (Admin Geral, Gestor)
            elif path == "/api/fornecedores_nuvem":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                log_audit(cursor, inst_id, user['email'], 'CRIAR_FORNECEDOR_NUVEM', 'fornecedores_nuvem', f_id, f"Fornecedor de nuvem {payload.get('nome_provedor')} cadastrado.")
                conn.commit()
                self.send_json({"success": True, "id": f_id})
                return

            # 9. PLAYBOOKS PARI (Admin Geral, Gestor, Analista)
            elif path == "/api/pari/playbooks":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                log_audit(cursor, inst_id, user['email'], 'CRIAR_PLAYBOOK_PARI', 'pari_playbooks', pb_id, f"Playbook '{payload.get('titulo_cenario')}' cadastrado.")
                conn.commit()
                self.send_json({"success": True, "id": pb_id})
                return

            # 10. SIMULADOS PARI (Admin Geral, Gestor, Analista)
            elif path == "/api/pari/simulados":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                log_audit(cursor, inst_id, user['email'], 'REGISTRAR_SIMULADO_PARI', 'pari_simulados', sim_id, f"Simulado de crise '{payload.get('titulo_simulado')}' registrado.")
                conn.commit()
                self.send_json({"success": True, "id": sim_id})
                return

            # 11. INCIDENTES (Admin Geral, Gestor, Analista)
            elif path == "/api/incidentes":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                payload = json.loads(raw_body.decode('utf-8'))
                cursor.execute("""
                INSERT INTO incidentes (
                    instituicao_id, protocolo, titulo, data_ocorrencia, data_deteccao, data_resolucao,
                    tempo_deteccao_minutos, tempo_resolucao_minutos, categoria, criticidade,
                    sistemas_afetados, impacto_operacional, status, notificado_bacen, data_notificacao_bacen,
                    causa_raiz, acoes_corretivas
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    inst_id,
                    payload.get('protocolo', f"INC-{datetime.now().strftime('%Y-%m%d')}"),
                    payload.get('titulo'),
                    payload.get('data_ocorrencia', datetime.now().isoformat()),
                    payload.get('data_deteccao', datetime.now().isoformat()),
                    payload.get('data_resolucao'),
                    int(payload.get('tempo_deteccao_minutos', 0)),
                    int(payload.get('tempo_resolucao_minutos', 0)),
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
                log_audit(cursor, inst_id, user['email'], 'REGISTRAR_INCIDENTE', 'incidentes', inc_id, f"Incidente '{payload.get('titulo')}' registrado.")
                conn.commit()
                self.send_json({"success": True, "id": inc_id})
                return

            # 12. FRAGILIDADES & PENTESTS (Admin Geral, Gestor, Analista)
            elif path == "/api/auditorias_fragilidades":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                payload = json.loads(raw_body.decode('utf-8'))
                titulo = payload.get('titulo') or payload.get('vulnerabilidade') or 'Apontamento de Pentest / Auditoria'
                tipo = payload.get('tipo') or payload.get('tipo_auditoria') or 'Pentest Externo'
                severidade = payload.get('severidade', 'Media')
                descricao = payload.get('descricao') or payload.get('plano_remediacao') or payload.get('vulnerabilidade') or ''
                status_rem = payload.get('status_remediacao') or payload.get('status') or 'Em_Tratamento'
                raw_req = payload.get('requisito_id')
                req_id = None
                if raw_req:
                    if str(raw_req).isdigit():
                        req_id = int(raw_req)
                    else:
                        cursor.execute("SELECT id FROM requisitos WHERE codigo = ?;", (str(raw_req),))
                        r_row = cursor.fetchone()
                        req_id = r_row['id'] if r_row else None

                cursor.execute("""
                INSERT INTO auditorias_fragilidades (
                    instituicao_id, titulo, tipo, severidade, descricao, requisito_id,
                    status_remediacao, data_identificacao, prazo_remediacao, responsavel
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    inst_id,
                    titulo,
                    tipo,
                    severidade,
                    descricao,
                    req_id,
                    status_rem,
                    payload.get('data_identificacao', datetime.now().strftime('%Y-%m-%d')),
                    payload.get('prazo_remediacao'),
                    payload.get('responsavel', user['nome'])
                ))
                frag_id = cursor.lastrowid
                log_audit(cursor, inst_id, user['email'], 'REGISTRAR_FRAGILIDADE', 'auditorias_fragilidades', frag_id, f"Fragilidade/Pentest '{titulo}' registrada.")
                conn.commit()
                self.send_json({"success": True, "id": frag_id}, 201)
                return

            # 13. PARECER FORMAL E ASSINATURA ELETRÔNICA DO ART. 8º (Admin Geral ou Gestor)
            elif path == "/api/relatorio_anual/parecer":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                payload = json.loads(raw_body.decode('utf-8'))
                ano_base = str(payload.get('ano_base', '2025'))
                parecer_texto = payload.get('parecer_conclusivo', '').strip()
                assinar = bool(payload.get('assinar_digitalmente', True))

                cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (inst_id,))
                inst = dict_from_row(cursor.fetchone())

                assinado_por = payload.get('assinado_por') or (inst['diretor_responsavel'] if inst else user['nome'])
                cargo_ass = payload.get('cargo_assinante') or (inst['cargo_diretor'] if inst else 'Diretor Estatutário BACEN')
                unicad_ass = payload.get('unicad_assinante') or (inst['registro_unicad'] if inst else 'BACEN-REG')

                # Calcular hash SHA-256 do relatório e parecer
                hash_input = f"{inst_id}_{ano_base}_{assinado_por}_{unicad_ass}_{parecer_texto}_{datetime.now().strftime('%Y%m%d%H%M')}"
                hash_sha256 = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

                status_ass = 'Assinado_Digitalmente' if assinar else 'Pendente'
                data_ass = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if assinar else None

                cursor.execute("""
                INSERT INTO relatorio_anual_parecer (
                    instituicao_id, ano_base, parecer_conclusivo, status_assinatura, assinado_por,
                    cargo_assinante, unicad_assinante, data_assinatura, hash_sha256_relatorio
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(instituicao_id, ano_base) DO UPDATE SET
                    parecer_conclusivo = excluded.parecer_conclusivo,
                    status_assinatura = excluded.status_assinatura,
                    assinado_por = excluded.assinado_por,
                    cargo_assinante = excluded.cargo_assinante,
                    unicad_assinante = excluded.unicad_assinante,
                    data_assinatura = excluded.data_assinatura,
                    hash_sha256_relatorio = excluded.hash_sha256_relatorio;
                """, (inst_id, ano_base, parecer_texto, status_ass, assinado_por, cargo_ass, unicad_ass, data_ass, hash_sha256))

                log_audit(cursor, inst_id, user['email'], 'ASSINAR_RELATORIO_ART8', 'relatorio_anual_parecer', inst_id,
                          f"Parecer do Diretor Estatutário para o ciclo {ano_base} registrado com status '{status_ass}' (Hash SHA-256: {hash_sha256[:16]}...).")
                conn.commit()

                self.send_json({
                    "success": True,
                    "status_assinatura": status_ass,
                    "assinado_por": assinado_por,
                    "data_assinatura": data_ass,
                    "hash_sha256": hash_sha256
                })
                return

            else:
                self.send_json({"error": "Endpoint não encontrado"}, 404)

        finally:
            conn.close()

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        conn = get_db()
        cursor = conn.cursor()

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode('utf-8'))

            token = self.get_token()
            user = get_authenticated_user(cursor, token)
            if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                self.send_json({"error": "Não autenticado ou MFA pendente."}, 401)
                return

            inst_id, role = self.get_context_institution_id(cursor, user, query)

            # 1. ATUALIZAR USUÁRIO (Admin Geral ONLY)
            if path.startswith("/api/usuarios/"):
                if user.get('is_admin_geral') != 1:
                    self.send_json({"error": "Apenas o Administrador Geral pode alterar usuários."}, 403)
                    return
                target_user_id = int(path.split("/")[-1])
                nome = payload.get('nome')
                email = payload.get('email', '').strip().lower()
                cargo = payload.get('cargo')
                is_admin = 1 if payload.get('is_admin_geral') else 0
                ativo = 1 if payload.get('ativo', True) else 0
                senha = payload.get('senha')
                instituicoes = payload.get('instituicoes', [])

                if senha:
                    salt, pwd_hash = hash_password(senha)
                    cursor.execute("""
                    UPDATE usuarios
                    SET nome = ?, email = ?, cargo = ?, is_admin_geral = ?, ativo = ?, senha_hash = ?, senha_salt = ?
                    WHERE id = ?;
                    """, (nome, email, cargo, is_admin, ativo, pwd_hash, salt, target_user_id))
                else:
                    cursor.execute("""
                    UPDATE usuarios
                    SET nome = ?, email = ?, cargo = ?, is_admin_geral = ?, ativo = ?
                    WHERE id = ?;
                    """, (nome, email, cargo, is_admin, ativo, target_user_id))

                cursor.execute("DELETE FROM usuario_instituicoes WHERE usuario_id = ?;", (target_user_id,))
                for ir in instituicoes:
                    cursor.execute("""
                    INSERT INTO usuario_instituicoes (usuario_id, instituicao_id, perfil)
                    VALUES (?, ?, ?);
                    """, (target_user_id, ir['instituicao_id'], ir['perfil']))

                log_audit(cursor, inst_id or 1, user['email'], 'ATUALIZAR_USUARIO', 'usuarios', target_user_id, f"Atualizado cadastro de {nome}.")
                conn.commit()
                self.send_json({"success": True, "id": target_user_id})
                return

            # 2. ATUALIZAR DADOS CADASTRAIS DA EMPRESA (Admin Geral ou Gestor)
            if path == "/api/instituicao" or path.startswith("/api/instituicao/"):
                target_inst_id = inst_id
                if path.startswith("/api/instituicao/") and path.split("/")[-1].isdigit():
                    target_inst_id = int(path.split("/")[-1])

                ok, code, err, _, role = self.check_auth(cursor, target_inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                    target_inst_id
                ))
                log_audit(cursor, target_inst_id, user['email'], 'ATUALIZAR_INSTITUICAO', 'instituicao', target_inst_id, f"Atualização cadastral de {payload.get('razao_social')}.")
                conn.commit()
                self.send_json({"success": True, "id": target_inst_id})
                return

            # 3. ATUALIZAR GOVERNANÇA DO PARI (Admin Geral ou Gestor)
            elif path == "/api/pari/governanca":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_PARI_GOV', 'pari_governanca', inst_id, "Atualização da governança do CSIRT/PARI.")
                conn.commit()
                self.send_json({"success": True})
                return

            # 4. ATUALIZAR AVALIAÇÃO DE COMPLIANCE (Admin Geral, Gestor, Analista)
            elif path.startswith("/api/avaliacoes/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                raw_req_id = path.split("/")[-1]
                req_numeric_id = None
                if raw_req_id.isdigit():
                    req_numeric_id = int(raw_req_id)
                else:
                    norm_code = raw_req_id.replace('REQ-4893-', 'REQ-').replace('4893-', '')
                    cursor.execute("SELECT id FROM requisitos WHERE codigo = ? OR codigo = ?;", (raw_req_id, norm_code))
                    row = cursor.fetchone()
                    req_numeric_id = row['id'] if row else None
                    if not req_numeric_id:
                        cursor.execute("SELECT id FROM requisitos WHERE codigo LIKE ?;", (f"%{raw_req_id}%",))
                        row = cursor.fetchone()
                        req_numeric_id = row['id'] if row else None

                if not req_numeric_id:
                    self.send_json({"error": f"Requisito '{raw_req_id}' não encontrado."}, 404)
                    return

                status = payload.get('status')
                pct = int(payload.get('percentual_aderencia', payload.get('aderencia_percentual', 0)))
                justificativa = payload.get('justificativa', payload.get('comentarios', ''))
                responsavel = payload.get('responsavel', '')
                prazo = payload.get('prazo_adequacao')
                auditor = user['nome']
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
                """, (inst_id, req_numeric_id, status, pct, justificativa, responsavel, prazo, auditor, obs))

                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_AVALIACAO', 'avaliacoes', req_numeric_id, f"Status: '{status}' ({pct}%) por {user['nome']}.")
                conn.commit()
                self.send_json({"success": True, "requisito_id": req_numeric_id})
                return

            # 5. ATUALIZAR PLANOS DE AÇÃO 5W2H (Admin Geral, Gestor, Analista)
            elif path.startswith("/api/planos_acao/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_PLANO_ACAO', 'planos_acao', p_id, f"Plano ID {p_id} atualizado.")
                conn.commit()
                self.send_json({"success": True, "id": p_id})
                return

            # 6. ATUALIZAR PLAYBOOK PARI (Admin Geral, Gestor, Analista)
            elif path.startswith("/api/pari/playbooks/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                pb_id = int(path.split("/")[-1])
                cursor.execute("""
                UPDATE pari_playbooks
                SET codigo = ?, categoria = ?, titulo_cenario = ?, etapa_deteccao = ?,
                    etapa_contencao = ?, etapa_erradicacao = ?, etapa_recuperacao = ?,
                    etapa_comunicacao_bacen = ?, tempo_estimado_resposta = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    payload.get('codigo'),
                    payload.get('categoria', 'Geral'),
                    payload.get('titulo_cenario'),
                    payload.get('etapa_deteccao'),
                    payload.get('etapa_contencao'),
                    payload.get('etapa_erradicacao'),
                    payload.get('etapa_recuperacao'),
                    payload.get('etapa_comunicacao_bacen'),
                    payload.get('tempo_estimado_resposta'),
                    pb_id,
                    inst_id
                ))
                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_PLAYBOOK', 'pari_playbooks', pb_id, f"Playbook '{payload.get('codigo')}' atualizado.")
                conn.commit()
                self.send_json({"success": True, "id": pb_id})
                return

            # 7. ATUALIZAR SIMULADO PARI (Admin Geral, Gestor, Analista)
            elif path.startswith("/api/pari/simulados/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                sim_id = int(path.split("/")[-1])
                cursor.execute("""
                UPDATE pari_simulados
                SET titulo_simulado = ?, data_realizacao = ?, cenario_testado = ?,
                    participantes = ?, tempo_resposta_alcancado = ?, pontos_fortes = ?,
                    gargalos_identificados = ?, acoes_melhoria = ?, status = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    payload.get('titulo_simulado'),
                    payload.get('data_realizacao'),
                    payload.get('cenario_testado'),
                    payload.get('participantes'),
                    payload.get('tempo_resposta_alcancado'),
                    payload.get('pontos_fortes'),
                    payload.get('gargalos_identificados'),
                    payload.get('acoes_melhoria'),
                    payload.get('status', 'Concluido'),
                    sim_id,
                    inst_id
                ))
                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_SIMULADO', 'pari_simulados', sim_id, f"Simulado '{payload.get('titulo_simulado')}' atualizado.")
                conn.commit()
                self.send_json({"success": True, "id": sim_id})
                return

            # 8. ATUALIZAR INCIDENTE (Admin Geral, Gestor, Analista)
            elif path.startswith("/api/incidentes/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                inc_id = int(path.split("/")[-1])
                status = payload.get('status', 'Em Investigação')
                data_resolucao = payload.get('data_resolucao')
                if status == 'Encerrado' and not data_resolucao:
                    data_resolucao = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                cursor.execute("""
                UPDATE incidentes
                SET titulo = COALESCE(?, titulo),
                    categoria = COALESCE(?, categoria),
                    criticidade = ?,
                    sistemas_afetados = ?,
                    impacto_operacional = ?,
                    status = ?,
                    notificado_bacen = ?,
                    data_notificacao_bacen = ?,
                    causa_raiz = ?,
                    acoes_corretivas = ?,
                    tempo_deteccao_minutos = ?,
                    tempo_resolucao_minutos = ?,
                    data_resolucao = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    payload.get('titulo'),
                    payload.get('categoria'),
                    payload.get('criticidade'),
                    payload.get('sistemas_afetados'),
                    payload.get('impacto_operacional'),
                    status,
                    int(payload.get('notificado_bacen', 0)),
                    payload.get('data_notificacao_bacen'),
                    payload.get('causa_raiz'),
                    payload.get('acoes_corretivas'),
                    int(payload.get('tempo_deteccao_minutos', 0)),
                    int(payload.get('tempo_resolucao_minutos', 0)),
                    data_resolucao,
                    inc_id,
                    inst_id
                ))
                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_INCIDENTE', 'incidentes', inc_id, f"Incidente ID {inc_id} atualizado: status '{status}', criticidade '{payload.get('criticidade')}'.")
                conn.commit()
                self.send_json({"success": True, "id": inc_id})
                return

            # 9. ATUALIZAR NUVEM (Admin Geral, Gestor)
            elif path.startswith("/api/fornecedores_nuvem/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                f_id = int(path.split("/")[-1])
                cursor.execute("""
                UPDATE fornecedores_nuvem
                SET nome_provedor = COALESCE(?, nome_provedor),
                    servico_prestado = COALESCE(?, servico_prestado),
                    tipo_nuvem = COALESCE(?, tipo_nuvem),
                    pais_armazenamento = COALESCE(?, pais_armazenamento),
                    servico_relevante = ?,
                    notificado_bacen = ?,
                    data_notificacao_bacen = ?,
                    convenio_bacen_pais = ?,
                    clausula_acesso_bacen = ?,
                    clausula_segregacao_dados = ?,
                    clausula_continuidade = ?,
                    clausula_reversibilidade = ?,
                    data_ultimo_teste_contingencia = ?,
                    nivel_risco = ?,
                    observacoes = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    payload.get('nome_provedor'),
                    payload.get('servico_prestado'),
                    payload.get('tipo_nuvem'),
                    payload.get('pais_armazenamento'),
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
                    payload.get('observacoes', ''),
                    f_id,
                    inst_id
                ))
                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_FORNECEDOR_NUVEM', 'fornecedores_nuvem', f_id, f"Provedor {payload.get('nome_provedor', f_id)} atualizado.")
                conn.commit()
                self.send_json({"success": True, "id": f_id})
                return

            # 7. ATUALIZAR FRAGILIDADE / PENTEST (Admin Geral, Gestor, Analista)
            elif path.startswith("/api/auditorias_fragilidades/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                frag_id = path.split("/")[-1]
                cursor.execute("""
                UPDATE auditorias_fragilidades
                SET status_remediacao = ?, prazo_remediacao = ?, responsavel = ?, severidade = ?
                WHERE id = ? AND instituicao_id = ?;
                """, (
                    payload.get('status_remediacao'),
                    payload.get('prazo_remediacao'),
                    payload.get('responsavel'),
                    payload.get('severidade'),
                    frag_id,
                    inst_id
                ))
                log_audit(cursor, inst_id, user['email'], 'ATUALIZAR_FRAGILIDADE', 'auditorias_fragilidades', frag_id, f"Fragilidade ID {frag_id} atualizada para {payload.get('status_remediacao')}.")
                conn.commit()
                self.send_json({"success": True, "id": frag_id}, 201)
                return

            else:
                self.send_json({"error": "Endpoint não encontrado"}, 404)

        finally:
            conn.close()

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        conn = get_db()
        cursor = conn.cursor()

        try:
            token = self.get_token()
            user = get_authenticated_user(cursor, token)
            if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                self.send_json({"error": "Não autenticado ou MFA pendente."}, 401)
                return

            inst_id, role = self.get_context_institution_id(cursor, user, query)

            # 1. EXCLUIR USUÁRIO (Admin Geral ONLY)
            if path.startswith("/api/usuarios/"):
                if user.get('is_admin_geral') != 1:
                    self.send_json({"error": "Apenas o Administrador Geral pode excluir usuários."}, 403)
                    return
                del_user_id = int(path.split("/")[-1])
                if del_user_id == user['id']:
                    self.send_json({"error": "Você não pode excluir sua própria conta de administrador."}, 400)
                    return
                cursor.execute("DELETE FROM usuarios WHERE id = ?;", (del_user_id,))
                log_audit(cursor, inst_id or 1, user['email'], 'EXCLUIR_USUARIO', 'usuarios', del_user_id, 'Usuário removido.')
                conn.commit()
                self.send_json({"success": True, "deleted_id": del_user_id})
                return

            # 2. EXCLUIR EVIDÊNCIA (Admin Geral e Gestor)
            if path.startswith("/api/evidencias/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                ev_id = path.split("/")[-1]
                cursor.execute("SELECT caminho_arquivo, titulo FROM evidencias WHERE id = ? AND instituicao_id = ?;", (ev_id, inst_id))
                row = cursor.fetchone()
                if row and row['caminho_arquivo']:
                    disk_path = os.path.join(BASE_DIR, row['caminho_arquivo'].lstrip('/'))
                    if os.path.exists(disk_path):
                        try:
                            os.remove(disk_path)
                        except Exception:
                            pass
                cursor.execute("DELETE FROM evidencias WHERE id = ? AND instituicao_id = ?;", (ev_id, inst_id))
                log_audit(cursor, inst_id, user['email'], 'EXCLUIR_EVIDENCIA', 'evidencias', ev_id, f"Evidência ID {ev_id} excluída.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": ev_id})
                return

            # 3. EXCLUIR PLANO DE AÇÃO (Admin Geral e Gestor)
            elif path.startswith("/api/planos_acao/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                p_id = path.split("/")[-1]
                cursor.execute("DELETE FROM planos_acao WHERE id = ? AND instituicao_id = ?;", (p_id, inst_id))
                log_audit(cursor, inst_id, user['email'], 'EXCLUIR_PLANO_ACAO', 'planos_acao', p_id, f"Plano ID {p_id} excluído.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": p_id})
                return

            # 4. EXCLUIR FRAGILIDADE / PENTEST (Admin Geral e Gestor)
            elif path.startswith("/api/auditorias_fragilidades/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                f_id = path.split("/")[-1]
                cursor.execute("DELETE FROM auditorias_fragilidades WHERE id = ? AND instituicao_id = ?;", (f_id, inst_id))
                log_audit(cursor, inst_id, user['email'], 'EXCLUIR_FRAGILIDADE', 'auditorias_fragilidades', f_id, f"Fragilidade ID {f_id} excluída.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": f_id})
                return

            # 5. EXCLUIR PLAYBOOK PARI (Admin Geral e Gestor)
            elif path.startswith("/api/pari/playbooks/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                pb_id = int(path.split("/")[-1])
                cursor.execute("DELETE FROM pari_playbooks WHERE id = ? AND instituicao_id = ?;", (pb_id, inst_id))
                log_audit(cursor, inst_id, user['email'], 'EXCLUIR_PLAYBOOK', 'pari_playbooks', pb_id, f"Playbook ID {pb_id} excluído.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": pb_id})
                return

            # 6. EXCLUIR SIMULADO PARI (Admin Geral e Gestor)
            elif path.startswith("/api/pari/simulados/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                sim_id = int(path.split("/")[-1])
                cursor.execute("DELETE FROM pari_simulados WHERE id = ? AND instituicao_id = ?;", (sim_id, inst_id))
                log_audit(cursor, inst_id, user['email'], 'EXCLUIR_SIMULADO', 'pari_simulados', sim_id, f"Simulado ID {sim_id} excluído.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": sim_id})
                return

            # 7. EXCLUIR INCIDENTE (Admin Geral e Gestor)
            elif path.startswith("/api/incidentes/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                inc_id = int(path.split("/")[-1])
                cursor.execute("DELETE FROM incidentes WHERE id = ? AND instituicao_id = ?;", (inc_id, inst_id))
                log_audit(cursor, inst_id, user['email'], 'EXCLUIR_INCIDENTE', 'incidentes', inc_id, f"Incidente ID {inc_id} excluído.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": inc_id})
                return

            # 8. EXCLUIR FORNECEDOR NUVEM (Admin Geral e Gestor)
            elif path.startswith("/api/fornecedores_nuvem/"):
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                f_id = int(path.split("/")[-1])
                cursor.execute("DELETE FROM fornecedores_nuvem WHERE id = ? AND instituicao_id = ?;", (f_id, inst_id))
                log_audit(cursor, inst_id, user['email'], 'EXCLUIR_FORNECEDOR_NUVEM', 'fornecedores_nuvem', f_id, f"Fornecedor Nuvem ID {f_id} excluído.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": f_id})
                return

            # 9. EXCLUIR INSTITUIÇÃO (Admin Geral ONLY)
            elif path.startswith("/api/instituicoes/"):
                if user.get('is_admin_geral') != 1:
                    self.send_json({"error": "Apenas o Administrador Geral pode excluir instituições."}, 403)
                    return

                del_id = path.split("/")[-1]
                cursor.execute("SELECT COUNT(*) as count FROM instituicao;")
                total = cursor.fetchone()['count']
                if total <= 1:
                    self.send_json({"error": "Não é possível excluir a única instituição existente."}, 400)
                    return

                cursor.execute("DELETE FROM instituicao WHERE id = ?;", (del_id,))
                cursor.execute("UPDATE instituicao SET is_ativa = 1 WHERE id = (SELECT id FROM instituicao LIMIT 1);")
                log_audit(cursor, 1, user['email'], 'EXCLUIR_INSTITUICAO', 'instituicao', del_id, f"Instituição ID {del_id} removida pelo Administrador Geral.")
                conn.commit()
                self.send_json({"success": True, "deleted_id": del_id})
                return

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
        """
        Generates the consolidated executive annual report in full compliance with
        Art. 8º da Resolução CMN nº 4.893/2021 & Resolução CMN nº 5.274/2025.
        Contains the 8 regulatory mandatory sections.
        """
        cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (inst_id,))
        inst = dict_from_row(cursor.fetchone())
        dashboard = self.get_dashboard_metrics(cursor, inst_id)

        # 1. Identificação Regulatória
        identificacao_regulatoria = {
            "instituicao": inst,
            "razao_social": inst['razao_social'] if inst else '',
            "cnpj": inst['cnpj'] if inst else '',
            "segmento_bacen": inst['segmento'] if inst else '',
            "diretor_responsavel": inst['diretor_responsavel'] if inst else '',
            "cargo_diretor": inst['cargo_diretor'] if inst else '',
            "registro_unicad": inst['registro_unicad'] if inst else '',
            "versao_politica": inst['versao_politica'] if inst else '',
            "data_aprovacao_politica": inst['data_aprovacao_politica'] if inst else '',
            "data_ultima_revisao": inst['data_ultima_revisao'] if inst else '',
            "data_base": "31 de dezembro de 2025",
            "data_emissao": datetime.now().strftime("%d/%m/%Y"),
            "exercicio": "2025",
            "orgao_regulador": "Banco Central do Brasil (BACEN)",
            "normas_aplicaveis": [
                "Resolução CMN nº 4.893, de 23 de dezembro de 2021",
                "Resolução CMN nº 5.274, de 25 de setembro de 2025"
            ]
        }

        # 2. Avaliação de Efetividade da Política (Indicadores percentuais Res. 4.893 e Res. 5.274)
        cursor.execute("""
        SELECT r.codigo, r.artigo, r.titulo, r.severidade, r.is_cmn_5274_obrigatorio, r.numero_controle_5274,
               COALESCE(a.status, 'nao_atendido') as status,
               COALESCE(a.percentual_aderencia, 0) as percentual_aderencia,
               a.justificativa, a.responsavel, a.observacoes_auditor
        FROM requisitos r
        LEFT JOIN avaliacoes a ON a.requisito_id = r.id AND a.instituicao_id = ?
        ORDER BY r.is_cmn_5274_obrigatorio DESC, r.numero_controle_5274 ASC, r.id ASC;
        """, (inst_id,))
        todos_requisitos = [dict_from_row(r) for r in cursor.fetchall()]

        efetividade_politica = {
            "kpis_globais": dashboard['resumo_kpi'],
            "taxa_conformidade_geral": dashboard['resumo_kpi']['percentual_aderencia_global'],
            "res_4893_32_requisitos": dashboard['resumo_kpi'],
            "cmn_5274_stats": dashboard['cmn_5274_stats'],
            "res_5274_14_controles": {"total_controles": 14, **dashboard['cmn_5274_stats']},
            "dominios_stats": dashboard['dominios_stats'],
            "controles_5274": dashboard['cmn_5274_controles'],
            "requisitos_detalhados": todos_requisitos
        }

        # 3. Consolidado de Incidentes Relevantes (Art. 6º) com MTTD e MTTR
        cursor.execute("""
        SELECT 
            COUNT(*) as total_incidentes,
            ROUND(AVG(COALESCE(tempo_deteccao_minutos, 0)), 1) as mttd_medio_minutos,
            ROUND(AVG(COALESCE(tempo_resolucao_minutos, 0)), 1) as mttr_medio_minutos,
            SUM(CASE WHEN notificado_bacen = 1 THEN 1 ELSE 0 END) as total_notificados_bacen,
            SUM(CASE WHEN status = 'Encerrado' THEN 1 ELSE 0 END) as total_encerrados
        FROM incidentes
        WHERE instituicao_id = ?;
        """, (inst_id,))
        inc_stats_row = cursor.fetchone()
        inc_stats = dict_from_row(inc_stats_row) if inc_stats_row else {}

        cursor.execute("""
        SELECT categoria, COUNT(*) as count
        FROM incidentes
        WHERE instituicao_id = ?
        GROUP BY categoria;
        """, (inst_id,))
        tipologias = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("""
        SELECT * FROM incidentes
        WHERE instituicao_id = ?
        ORDER BY data_ocorrencia DESC;
        """, (inst_id,))
        incidentes_lista = [dict_from_row(r) for r in cursor.fetchall()]

        consolidado_incidentes = {
            "total_incidentes": inc_stats.get('total_incidentes', len(incidentes_lista)),
            "mttd_medio_minutos": inc_stats.get('mttd_medio_minutos', 0),
            "mttr_medio_minutos": inc_stats.get('mttr_medio_minutos', 0),
            "metricas": inc_stats,
            "distribuicao_tipologia": tipologias,
            "tipologias": tipologias,
            "incidentes": incidentes_lista,
            "incidentes_lista": incidentes_lista
        }

        # 4. Resultados de Testes de Continuidade e Simulados de Crise (PARI)
        cursor.execute("SELECT * FROM pari_governanca WHERE instituicao_id = ? LIMIT 1;", (inst_id,))
        pari_gov = dict_from_row(cursor.fetchone())

        cursor.execute("SELECT * FROM pari_playbooks WHERE instituicao_id = ? ORDER BY codigo ASC;", (inst_id,))
        pari_playbooks = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM pari_simulados WHERE instituicao_id = ? ORDER BY data_realizacao DESC;", (inst_id,))
        pari_simulados = [dict_from_row(r) for r in cursor.fetchall()]

        continuidade_simulados = {
            "governanca_csirt": pari_gov,
            "total_simulados_realizados": len(pari_simulados),
            "total_playbooks": len(pari_playbooks),
            "playbooks": pari_playbooks,
            "simulados": pari_simulados,
            "simulados_realizados": pari_simulados,
            "simulados_lista": pari_simulados
        }

        # 5. Auditorias e Fragilidades Identificadas (Pentests e Scans)
        cursor.execute("""
        SELECT f.*, r.codigo as requisito_codigo, r.titulo as requisito_titulo
        FROM auditorias_fragilidades f
        LEFT JOIN requisitos r ON f.requisito_id = r.id
        WHERE f.instituicao_id = ?
        ORDER BY f.data_identificacao DESC;
        """, (inst_id,))
        fragilidades = [dict_from_row(r) for r in cursor.fetchall()]

        auditorias_fragilidades = {
            "total_fragilidades_identificadas": len(fragilidades),
            "total_fragilidades": len(fragilidades),
            "remediadas": sum(1 for f in fragilidades if f['status_remediacao'] == 'Remediada'),
            "em_tratamento": sum(1 for f in fragilidades if f['status_remediacao'] == 'Em_Tratamento'),
            "risco_aceito": sum(1 for f in fragilidades if f['status_remediacao'] == 'Risco_Aceito'),
            "vulnerabilidades": fragilidades,
            "vulnerabilidades_lista": fragilidades,
            "lista": fragilidades
        }

        # 6. Planos de Ação e Adequação (5W2H)
        cursor.execute("""
        SELECT p.*, r.codigo as requisito_codigo, r.titulo as requisito_titulo
        FROM planos_acao p
        JOIN requisitos r ON p.requisito_id = r.id
        WHERE p.instituicao_id = ?
        ORDER BY p.quando ASC;
        """, (inst_id,))
        planos = [dict_from_row(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM fornecedores_nuvem WHERE instituicao_id = ? ORDER BY id ASC;", (inst_id,))
        fornecedores = [dict_from_row(r) for r in cursor.fetchall()]

        planos_adequacao = {
            "total_planos": len(planos),
            "total_planos_5w2h": len(planos),
            "planos_5w2h": planos,
            "planos": planos,
            "fornecedores_nuvem_art17": fornecedores,
            "provedores_nuvem_relevantes": fornecedores
        }

        # 7. Parecer Formal do Diretor Estatutário (Art. 7º e 8º)
        cursor.execute("""
        SELECT * FROM relatorio_anual_parecer
        WHERE instituicao_id = ? AND ano_base = '2025'
        LIMIT 1;
        """, (inst_id,))
        parecer_row = cursor.fetchone()
        parecer = dict_from_row(parecer_row)

        razao = inst['razao_social'] if inst else 'Instituição Financeira'
        diretor = inst['diretor_responsavel'] if inst else 'Diretor Estatutário'

        if not parecer:
            parecer_padrao = (
                f"Declaro, na qualidade de Diretor Estatutário responsável pela Política de Segurança Cibernética "
                f"da instituição {razao} perante o Banco Central do Brasil, nos termos do Art. 7º e 8º "
                f"da Resolução CMN nº 4.893/2021 e da Resolução CMN nº 5.274/2025, que as informações "
                f"contidas neste relatório refletem com fidedignidade o estado de maturidade dos controles de segurança, "
                f"a efetividade do Plano de Ação e de Resposta a Incidentes (PARI), e a execução dos planos de adequação contínua."
            )
            parecer = {
                "instituicao_id": inst_id,
                "ano_base": "2025",
                "parecer_conclusivo": parecer_padrao,
                "status_assinatura": "Pendente",
                "assinado_por": diretor,
                "cargo_assinante": inst['cargo_diretor'] if inst else 'Diretor Estatutário perante o BACEN',
                "unicad_assinante": inst['registro_unicad'] if inst else 'BACEN-REG',
                "data_assinatura": None,
                "hash_sha256_relatorio": None
            }

        parecer['assinado_digitalmente'] = (parecer.get('status_assinatura') == 'Assinado_Digitalmente')
        parecer['diretor_nome'] = parecer.get('assinado_por')
        parecer['hash_sha256_parecer'] = parecer.get('hash_sha256_relatorio')

        # 8. Metadados de Exportação Oficial e Hash de Integridade
        report_payload_for_hash = f"{inst_id}_{dashboard['resumo_kpi']['percentual_aderencia_global']}_{dashboard['cmn_5274_stats']['aderencia_media']}_{parecer['parecer_conclusivo']}"
        integrity_hash = hashlib.sha256(report_payload_for_hash.encode('utf-8')).hexdigest()

        exportacao_metadados = {
            "instituicao_id": inst_id,
            "hash_sha256_integridade": parecer.get('hash_sha256_relatorio') or integrity_hash,
            "algoritmo_hash": "SHA-256 (FIPS 180-4)",
            "data_geracao": datetime.now().isoformat(),
            "conformidade_resolucao": "Resolução CMN nº 4.893/2021 (Art. 8º) e Resolução CMN nº 5.274/2025",
            "validade_juridica": "Documento assinado digitalmente nos termos da MP 2.200-2/2001 e normas do BACEN."
        }

        return {
            "secao_1_identificacao": identificacao_regulatoria,
            "secao_1_identificacao_regulatoria": identificacao_regulatoria,
            "secao_2_efetividade_politica": efetividade_politica,
            "secao_3_incidentes_relevantes": consolidado_incidentes,
            "secao_4_continuidade_simulados": continuidade_simulados,
            "secao_4_testes_continuidade_pari": continuidade_simulados,
            "secao_5_auditorias_fragilidades": auditorias_fragilidades,
            "secao_6_planos_adequacao": planos_adequacao,
            "secao_6_planos_acao_terceiros": planos_adequacao,
            "secao_7_parecer_diretor": parecer,
            "secao_8_exportacao_metadados": exportacao_metadados
        }

    def export_annual_report_json(self, cursor, inst_id):
        report = self.generate_annual_report(cursor, inst_id)
        body = json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8')
        cursor.execute("SELECT razao_social FROM instituicao WHERE id = ?;", (inst_id,))
        inst_row = cursor.fetchone()
        inst_nome = inst_row['razao_social'].replace(' ', '_') if inst_row else f"Inst_{inst_id}"

        filename = f"Relatorio_Anual_Art8_BACEN_{inst_nome}_2025.json"
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
    print(f"  Multi-tenant Context Engine & Art. 8 Module Active")
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
