"""
Enterprise-grade Web Server and REST API for BACEN CMN 4.893 & 5.274 Compliance GRC.
Features:
- Role-Based Access Control (RBAC) & Least Privilege:
  * Admin Geral (Superadministrador global)
  * Gestor de Compliance / CISO (Gestão completa na instituição atribuída)
  * Analista / Operador (Alimentação de evidências e planos de ação)
  * Auditor / Fiscal BACEN (Somente leitura de requisitos, evidências e relatórios)
- Multi-Institution User Mapping (perfil granular por instituição)
- Authentication with PBKDF2-SHA256 password hashing & RFC 6238 TOTP (MFA 6 dígitos)
- Dedicated PARI Module (Arts. 6º e 8º)
- 14 Mandatory Minimum Controls of Resolução CMN nº 5.274/2025
- Evidence Vault with SHA-256 integrity calculation
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
    if not user:
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

def get_active_institution_id(cursor, user=None):
    if user and user.get('is_admin_geral') != 1:
        # Check active institution that this user actually has permission to access
        cursor.execute("""
        SELECT i.id FROM instituicao i
        JOIN usuario_instituicoes ui ON ui.instituicao_id = i.id
        WHERE ui.usuario_id = ? AND i.is_ativa = 1
        LIMIT 1;
        """, (user['id'],))
        row = cursor.fetchone()
        if row:
            return row['id']
        cursor.execute("""
        SELECT i.id FROM instituicao i
        JOIN usuario_instituicoes ui ON ui.instituicao_id = i.id
        WHERE ui.usuario_id = ?
        ORDER BY i.id ASC LIMIT 1;
        """, (user['id'],))
        row = cursor.fetchone()
        return row['id'] if row else 1

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
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
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

    def check_auth(self, cursor, inst_id, allowed_roles):
        token = self.get_token()
        user = get_authenticated_user(cursor, token)
        if not user:
            return False, 401, "Sessão inválida ou expirada. Efetue login.", None, None
        if user.get('mfa_habilitado') and not user.get('mfa_verificado'):
            return False, 403, "Segundo fator de autenticação (MFA) pendente.", user, None

        if user.get('is_admin_geral') == 1:
            return True, 200, "OK", user, "admin_geral"

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
                active_id = get_active_institution_id(cursor, user)
                active_role = get_user_role_for_institution(cursor, user, active_id)
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
                    "instituicao_ativa_id": active_id,
                    "perfil_ativo": active_role,
                    "instituicoes": insts
                })
                return

            # Exige autenticação básica para qualquer endpoint a partir daqui
            if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                self.send_json({"error": "Não autenticado. Efetue login com usuário, senha e MFA."}, 401)
                return

            inst_id = get_active_institution_id(cursor, user)

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

            # 3. INSTITUIÇÕES ACESSÍVEIS (Filtradas pelo menor privilégio do usuário)
            elif path == "/api/instituicoes":
                insts = get_accessible_institutions(cursor, user)
                self.send_json(insts)
                return

            elif path == "/api/instituicao" or path == "/api/instituicao/ativa":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM instituicao WHERE id = ?;", (inst_id,))
                row = cursor.fetchone()
                inst_data = dict_from_row(row) if row else {}
                if inst_data:
                    inst_data['perfil_usuario'] = role
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

            # 6. REQUISITOS (Com filtros)
            elif path == "/api/requisitos":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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

            # 7. PARI (Acessível para consulta a todos os perfis)
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

            # 8. EVIDÊNCIAS
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

            # 9. PLANOS DE AÇÃO
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

            # 10. FORNECEDORES DE NUVEM
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

            # 12. RELATÓRIO ANUAL (ART. 8º)
            elif path == "/api/relatorio_anual":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                relatorio = self.generate_annual_report(cursor, inst_id)
                self.send_json(relatorio)
                return

            # 13. AUDITORIA LOG
            elif path == "/api/auditoria_log":
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("SELECT * FROM auditoria_log ORDER BY id DESC LIMIT 100;")
                rows = [dict_from_row(r) for r in cursor.fetchall()]
                self.send_json(rows)
                return

            # 14. EXPORTAÇÃO
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
                    cursor.execute("""
                    INSERT INTO auditoria_log (usuario, acao, entidade, detalhes)
                    VALUES (?, 'FALHA_LOGIN', 'auth', 'Tentativa de autenticação com credenciais incorretas.');
                    """, (email or 'Desconhecido',))
                    conn.commit()
                    self.send_json({"error": "Credenciais incorretas. Verifique seu e-mail e senha."}, 401)
                    return

                token = generate_session_token()
                cursor.execute("""
                INSERT INTO sessoes (token, usuario_id, expira_em, mfa_verificado)
                VALUES (?, ?, datetime('now', '+1 day'), 0);
                """, (token, user['id']))
                conn.commit()

                # Fornece a chave TOTP e código preview para facilitar pareamento e testes locais
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

            # 2. AUTENTICAÇÃO: VALIDAÇÃO MFA / TOTP (Público mediante token de sessão pendente)
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
                    cursor.execute("""
                    INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                    VALUES (?, 'FALHA_MFA', 'usuarios', ?, 'Código TOTP de 6 dígitos inválido ou expirado.');
                    """, (user['email'], user['id']))
                    conn.commit()
                    self.send_json({"error": "Código MFA incorreto ou expirado. Verifique o horário do seu dispositivo."}, 400)
                    return

                cursor.execute("UPDATE sessoes SET mfa_verificado = 1 WHERE token = ?;", (token,))
                cursor.execute("UPDATE usuarios SET ultimo_login = CURRENT_TIMESTAMP WHERE id = ?;", (user['id'],))

                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'LOGIN_SUCESSO', 'usuarios', ?, 'Autenticação multifator validada com sucesso.');
                """, (user['email'], user['id']))
                conn.commit()

                insts = get_accessible_institutions(cursor, user)
                active_id = get_active_institution_id(cursor, user)
                active_role = get_user_role_for_institution(cursor, user, active_id)

                self.send_json({
                    "success": True,
                    "user": {
                        "id": user['id'],
                        "nome": user['nome'],
                        "email": user['email'],
                        "cargo": user['cargo'],
                        "is_admin_geral": bool(user['is_admin_geral'])
                    },
                    "instituicao_ativa_id": active_id,
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

            inst_id = get_active_institution_id(cursor, user)

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
                instituicoes_roles = payload.get('instituicoes', []) # lista de {instituicao_id, perfil}

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

                    cursor.execute("""
                    INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                    VALUES (?, 'CRIAR_USUARIO', 'usuarios', ?, ?);
                    """, (user['email'], new_user_id, f"Cadastrado usuário {nome} ({email}) com privilégios RBAC."))
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
                cursor.execute("UPDATE instituicao SET is_ativa = 0 WHERE id != ?;", (new_id,))

                # Inicializar avaliações
                cursor.execute("SELECT id FROM requisitos;")
                for req in cursor.fetchall():
                    cursor.execute("""
                    INSERT OR IGNORE INTO avaliacoes (instituicao_id, requisito_id, status, percentual_aderencia)
                    VALUES (?, ?, 'nao_atendido', 0);
                    """, (new_id, req['id']))

                # Inicializar governança PARI
                cursor.execute("""
                INSERT INTO pari_governanca (
                    instituicao_id, lider_csirt, email_csirt, telefone_plantao_247,
                    membros_csirt, comite_crise, criterios_relevancia_bacen, procedimento_sisbacen
                ) VALUES (?, 'Líder CSIRT', 'csirt@empresa.com.br', '(11) 99999-0000',
                          'Equipe de Segurança, Redes e DBA', 'Diretoria Executiva e CISO',
                          'Indisponibilidade de canais essenciais > 2h ou vazamento de dados.',
                          'Comunicação em até 24h via Sisbacen / Protocolo Digital.');
                """, (new_id,))

                conn.commit()
                self.send_json({"success": True, "id": new_id})
                return

            # ATIVAR INSTITUIÇÃO ESPECÍFICA (Apenas instituições que o usuário tem acesso)
            elif path.endswith("/ativar") and "/api/instituicao/" in path:
                target_id = int(path.split("/")[-2])
                ok, code, err, _, _ = self.check_auth(cursor, target_id, ['admin_geral', 'gestor', 'analista', 'auditor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return
                cursor.execute("UPDATE instituicao SET is_ativa = 0;")
                cursor.execute("UPDATE instituicao SET is_ativa = 1 WHERE id = ?;", (target_id,))
                conn.commit()
                self.send_json({"success": True, "ativo_id": target_id})
                return

            # 6. REGISTRAR EVIDÊNCIA (Admin Geral, Gestor, Analista - Auditor bloqueado)
            elif path == "/api/evidencias":
                ok, code, err, user, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                payload = json.loads(raw_body.decode('utf-8'))
                req_id = payload.get('requisito_id')
                titulo = payload.get('titulo')
                tipo = payload.get('tipo', 'Documento')
                descricao = payload.get('descricao', '')
                coletor = user['nome']
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
                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'CRIAR_EVIDENCIA', 'evidencias', ?, ?);
                """, (user['email'], ev_id, f"Registrada evidência '{titulo}' para requisito ID {req_id} com hash SHA-256 {hash_sha256[:16]}..."))
                conn.commit()

                self.send_json({"success": True, "id": ev_id, "hash_sha256": hash_sha256})
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
                return

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

            token = self.get_token()
            user = get_authenticated_user(cursor, token)
            if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                self.send_json({"error": "Não autenticado ou MFA pendente."}, 401)
                return

            inst_id = get_active_institution_id(cursor, user)

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

                # Atualizar vínculos de instituições
                cursor.execute("DELETE FROM usuario_instituicoes WHERE usuario_id = ?;", (target_user_id,))
                for ir in instituicoes:
                    cursor.execute("""
                    INSERT INTO usuario_instituicoes (usuario_id, instituicao_id, perfil)
                    VALUES (?, ?, ?);
                    """, (target_user_id, ir['instituicao_id'], ir['perfil']))

                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'ATUALIZAR_USUARIO', 'usuarios', ?, ?);
                """, (user['email'], target_user_id, f"Atualizado cadastro e permissões RBAC de {nome}."))
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
                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'ATUALIZAR_INSTITUICAO', 'instituicao', ?, ?);
                """, (user['email'], target_inst_id, f"Atualização cadastral da instituição {payload.get('razao_social')}."))
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
                conn.commit()
                self.send_json({"success": True})
                return

            # 4. ATUALIZAR AVALIAÇÃO DE COMPLIANCE (Admin Geral, Gestor, Analista - Auditor BLOQUEADO)
            elif path.startswith("/api/avaliacoes/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor', 'analista'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

                req_id = path.split("/")[-1]
                status = payload.get('status')
                pct = int(payload.get('percentual_aderencia', 0))
                justificativa = payload.get('justificativa', '')
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
                """, (inst_id, req_id, status, pct, justificativa, responsavel, prazo, auditor, obs))

                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'ATUALIZAR_AVALIACAO', 'avaliacoes', ?, ?);
                """, (user['email'], req_id, f"Status atualizado para '{status}' com {pct}% de aderência por {user['nome']} ({role})."))
                conn.commit()
                self.send_json({"success": True, "requisito_id": req_id})
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
                conn.commit()
                self.send_json({"success": True, "id": p_id})
                return

            # 6. ATUALIZAR NUVEM (Admin Geral, Gestor)
            elif path.startswith("/api/fornecedores_nuvem/"):
                ok, code, err, _, role = self.check_auth(cursor, inst_id, ['admin_geral', 'gestor'])
                if not ok:
                    self.send_json({"error": err}, code)
                    return

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
                return

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
            token = self.get_token()
            user = get_authenticated_user(cursor, token)
            if not user or (user.get('mfa_habilitado') and not user.get('mfa_verificado')):
                self.send_json({"error": "Não autenticado ou MFA pendente."}, 401)
                return

            inst_id = get_active_institution_id(cursor, user)

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
                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'EXCLUIR_USUARIO', 'usuarios', ?, 'Usuário removido pelo Administrador Geral.');
                """, (user['email'], del_user_id))
                conn.commit()
                self.send_json({"success": True, "deleted_id": del_user_id})
                return

            # 2. EXCLUIR EVIDÊNCIA (Admin Geral e Gestor - Analista e Auditor BLOQUEADOS)
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
                cursor.execute("""
                INSERT INTO auditoria_log (usuario, acao, entidade, entidade_id, detalhes)
                VALUES (?, 'EXCLUIR_EVIDENCIA', 'evidencias', ?, ?);
                """, (user['email'], ev_id, f"Evidência ID {ev_id} removida."))
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
                conn.commit()
                self.send_json({"success": True, "deleted_id": p_id})
                return

            # 4. EXCLUIR INSTITUIÇÃO (Admin Geral ONLY)
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
    print(f"  RBAC & Least Privilege Engine Active")
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
