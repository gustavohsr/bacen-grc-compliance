"""
Integration Test Suite for BACEN CMN 4.893/2021 & CMN 5.274/2025 Compliance GRC System.
Covers:
1. Multi-tenancy & Context Switching (X-Company-ID & query parameter)
2. Role-Based Access Control (RBAC) & Principle of Least Privilege across financial institutions
3. Data isolation across institutions:
   - Compliance Matrix (32 requirements Res. 4.893 & 14 controls Res. 5.274)
   - PARI (Plano de Ação e Resposta a Incidentes) & Tabletop Drills
   - Evidence Vault (REQ-5274-11 Certificados Digitais linkage)
   - Incidents & MTTD/MTTR metrics
   - Pentests / Vulnerabilities (auditorias_fragilidades)
   - Action Plans 5W2H & Cloud Service Providers (Art. 17)
   - Audit Trail (auditoria_log)
4. Art. 8º Annual Report (all 8 mandatory regulatory sections + electronic signature + SHA-256 hash)
5. JSON Export
"""
import unittest
import threading
import socketserver
import json
import urllib.request
import urllib.error
import urllib.parse
import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from server import ComplianceAPIHandler, get_db
from auth import get_totp_code

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class TestMultiTenancyAndArt8(unittest.TestCase):
    server = None
    server_thread = None
    port = None
    base_url = None

    tokens = {}

    @classmethod
    def setUpClass(cls):
        # Start server on dynamic port
        cls.server = ThreadingTCPServer(('127.0.0.1', 0), ComplianceAPIHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def request(self, method, path, data=None, token=None, company_id=None, expect_status=200):
        url = self.base_url + path
        headers = {}
        if token:
            headers['Authorization'] = f"Bearer {token}"
        if company_id is not None:
            headers['X-Company-ID'] = str(company_id)

        req_data = None
        if data is not None:
            req_data = json.dumps(data).encode('utf-8')
            headers['Content-Type'] = 'application/json'

        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                body = resp.read()
                content_type = resp.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    return status, json.loads(body.decode('utf-8')), resp.headers
                return status, body, resp.headers
        except urllib.error.HTTPError as e:
            err_body = e.read()
            try:
                parsed_err = json.loads(err_body.decode('utf-8'))
            except Exception:
                parsed_err = err_body.decode('utf-8')
            return e.code, parsed_err, e.headers

    def login_and_mfa(self, email, password):
        # Step 1: Login
        status, body, _ = self.request('POST', '/api/auth/login', {
            'email': email,
            'password': password
        })
        self.assertEqual(status, 200, f"Login failed for {email}: {body}")
        token = body['token']
        mfa_secret = body['mfa_secret']

        # Step 2: MFA TOTP
        code = get_totp_code(mfa_secret)
        status, body, _ = self.request('POST', '/api/auth/mfa', {
            'token': token,
            'code': code
        })
        self.assertEqual(status, 200, f"MFA failed for {email}: {body}")
        return token

    def test_01_authentication_and_mfa_all_roles(self):
        """Validates login and MFA for all seeded roles."""
        # 1. Admin Geral
        admin_token = self.login_and_mfa('admin@bacen.local', 'Admin@Bacen2026!')
        self.assertTrue(admin_token)
        self.tokens['admin'] = admin_token

        # 2. Gestor 1 (Alpha Bank only)
        gestor1_token = self.login_and_mfa('gestor@alphabank.com.br', 'Gestor@2026!')
        self.assertTrue(gestor1_token)
        self.tokens['gestor1'] = gestor1_token

        # 3. Gestor 2 (Torra SCD only)
        gestor2_token = self.login_and_mfa('gestor@torrascd.com.br', 'Gestor@Torra2026!')
        self.assertTrue(gestor2_token)
        self.tokens['gestor2'] = gestor2_token

        # 4. Analista (Alpha Bank + Torra SCD)
        analista_token = self.login_and_mfa('analista@alphabank.com.br', 'Analista@2026!')
        self.assertTrue(analista_token)
        self.tokens['analista'] = analista_token

        # 5. Auditor (Alpha Bank + Torra SCD)
        auditor_token = self.login_and_mfa('auditor@bacen.gov.br', 'Auditor@2026!')
        self.assertTrue(auditor_token)
        self.tokens['auditor'] = auditor_token

    def test_02_admin_context_switching_alpha_and_torra(self):
        """Admin Geral can switch contexts between Alpha Bank (S3) and Torra SCD (S4)."""
        admin_token = self.tokens['admin']

        # Alpha Bank Context (ID 1)
        status, body, _ = self.request('GET', '/api/empresa', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertEqual(body['id'], 1)
        self.assertIn("Alpha", body['razao_social'])
        self.assertEqual(body['cnpj'], "00.123.456/0001-78")
        self.assertEqual(body.get('segmento_bacen', body.get('segmento')), "S3")
        self.assertIn("Roberto Silveira Mello", body['diretor_responsavel'])

        # Torra SCD Context (ID 2)
        status, body, _ = self.request('GET', '/api/empresa', token=admin_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertEqual(body['id'], 2)
        self.assertIn("Torra", body['razao_social'])
        self.assertEqual(body['cnpj'], "12.345.678/0001-90")
        self.assertEqual(body.get('segmento_bacen', body.get('segmento')), "S4")
        self.assertIn("Sílvio Cavalcanti", body['diretor_responsavel'])

        # Admin gets all companies in multi-tenant management view
        status, body, _ = self.request('GET', '/api/empresas', token=admin_token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(body), 2)
        company_ids = [c['id'] for c in body]
        self.assertIn(1, company_ids)
        self.assertIn(2, company_ids)

    def test_03_tenant_isolation_least_privilege_enforcement(self):
        """Gestor 1 cannot access Torra SCD (inst 2), Gestor 2 cannot access Alpha Bank (inst 1)."""
        gestor1_token = self.tokens['gestor1']
        gestor2_token = self.tokens['gestor2']

        # Gestor 1 accessing Alpha Bank -> SUCCESS
        status, body, _ = self.request('GET', '/api/empresa', token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertEqual(body['id'], 1)

        # Gestor 1 attempting to access Torra SCD -> 403 FORBIDDEN
        status, body, _ = self.request('GET', '/api/empresa', token=gestor1_token, company_id=2)
        self.assertEqual(status, 403)
        self.assertIn("Acesso negado", str(body))

        # Gestor 2 accessing Torra SCD -> SUCCESS
        status, body, _ = self.request('GET', '/api/empresa', token=gestor2_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertEqual(body['id'], 2)

        # Gestor 2 attempting to access Alpha Bank -> 403 FORBIDDEN
        status, body, _ = self.request('GET', '/api/empresa', token=gestor2_token, company_id=1)
        self.assertEqual(status, 403)
        self.assertIn("Acesso negado", str(body))

    def test_04_compliance_evaluations_segregation(self):
        """Compliance evaluations are strictly isolated per institution."""
        admin_token = self.tokens['admin']

        # Evaluations for Alpha Bank (1)
        status, evals1, _ = self.request('GET', '/api/avaliacoes', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(all(e['instituicao_id'] == 1 for e in evals1))

        # Evaluations for Torra SCD (2)
        status, evals2, _ = self.request('GET', '/api/avaliacoes', token=admin_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertTrue(all(e['instituicao_id'] == 2 for e in evals2))

        # Update evaluation on Alpha Bank
        status, resp, _ = self.request('PUT', '/api/avaliacoes/REQ-4893-01', {
            'status': 'atendido',
            'aderencia_percentual': 100,
            'comentarios': 'Atualização de teste multi-tenant Alpha Bank'
        }, token=admin_token, company_id=1)
        self.assertEqual(status, 200)

        # Verify Alpha Bank updated
        status, evals1_after, _ = self.request('GET', '/api/avaliacoes', token=admin_token, company_id=1)
        req1_alpha = next(e for e in evals1_after if e.get('requisito_codigo') in ('REQ-01', 'REQ-4893-01'))
        self.assertEqual(req1_alpha['status'], 'atendido')
        self.assertEqual(req1_alpha.get('percentual_aderencia', req1_alpha.get('aderencia_percentual')), 100)

        # Verify Torra SCD untouched
        status, evals2_after, _ = self.request('GET', '/api/avaliacoes', token=admin_token, company_id=2)
        req1_torra = next(e for e in evals2_after if e.get('requisito_codigo') in ('REQ-01', 'REQ-4893-01'))
        self.assertNotEqual(req1_torra.get('comentarios', req1_torra.get('justificativa')), 'Atualização de teste multi-tenant Alpha Bank')

    def test_05_pari_and_tabletop_drills_segregation(self):
        """PARI playbooks and crisis tabletop drills are segregated per institution."""
        admin_token = self.tokens['admin']

        # Alpha Bank PARI
        status, pari1, _ = self.request('GET', '/api/pari', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertEqual(len(pari1['playbooks']), 5) # 5 playbooks seeded for Alpha Bank

        # Torra SCD PARI
        status, pari2, _ = self.request('GET', '/api/pari', token=admin_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertEqual(len(pari2['playbooks']), 4) # 4 playbooks seeded for Torra SCD

        # Tabletop drills segregation
        status, drills1, _ = self.request('GET', '/api/pari/simulados', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        status, drills2, _ = self.request('GET', '/api/pari/simulados', token=admin_token, company_id=2)
        self.assertEqual(status, 200)

        drill_names1 = {d['titulo_simulado'] for d in drills1}
        drill_names2 = {d['titulo_simulado'] for d in drills2}
        self.assertTrue(all(d['instituicao_id'] == 1 for d in drills1))
        self.assertTrue(all(d['instituicao_id'] == 2 for d in drills2))
        self.assertNotEqual(drill_names1, drill_names2)

    def test_06_evidence_vault_coherence_and_res5274_link(self):
        """Evidence uploaded for REQ-5274-11 (Certificados Digitais) binds strictly to active company."""
        admin_token = self.tokens['admin']

        # Register evidence for REQ-5274-11 on Alpha Bank
        status, body, _ = self.request('POST', '/api/evidencias', {
            'requisito_id': 'REQ-5274-11',
            'nome_arquivo': 'politica_certificados_digitais_v4.pdf',
            'caminho_arquivo': 'uploads/politica_certificados_digitais_v4.pdf',
            'hash_sha256': 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
            'descricao': 'Procedimento Operacional de Gestão e Renovação de Certificados ICP-Brasil e mTLS (Controle 11 Res. 5.274)',
            'categoria': 'Criptografia e Certificados'
        }, token=admin_token, company_id=1)
        self.assertIn(status, (200, 201))
        evidence_id = body.get('id')
        self.assertTrue(evidence_id)

        # Verify evidence exists in Alpha Bank vault
        status, evid1, _ = self.request('GET', '/api/evidencias', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(any(e['id'] == evidence_id and (e.get('requisito_codigo') == 'REQ-5274-11' or str(e.get('requisito_id')) == 'REQ-5274-11') for e in evid1))

        # Verify evidence does NOT exist in Torra SCD vault
        status, evid2, _ = self.request('GET', '/api/evidencias', token=admin_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertFalse(any(e['id'] == evidence_id for e in evid2))

    def test_07_incident_metrics_and_mttd_mttr(self):
        """Incidents record MTTD and MTTR and are segregated per institution."""
        admin_token = self.tokens['admin']

        status, inc1, _ = self.request('GET', '/api/incidentes', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(all(i['instituicao_id'] == 1 for i in inc1))
        self.assertTrue(any('tempo_deteccao_minutos' in i for i in inc1))

        status, inc2, _ = self.request('GET', '/api/incidentes', token=admin_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertTrue(all(i['instituicao_id'] == 2 for i in inc2))

    def test_08_auditorias_fragilidades_pentests(self):
        """Vulnerabilities & Pentest tracking is isolated per institution."""
        admin_token = self.tokens['admin']

        status, v1, _ = self.request('GET', '/api/auditorias_fragilidades', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(all(v['instituicao_id'] == 1 for v in v1))

        status, v2, _ = self.request('GET', '/api/auditorias_fragilidades', token=admin_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertTrue(all(v['instituicao_id'] == 2 for v in v2))

        # Add new pentest finding to Alpha Bank
        status, body, _ = self.request('POST', '/api/auditorias_fragilidades', {
            'tipo_auditoria': 'pentest_interno',
            'entidade_auditora': 'CyberSec Audits Ltd',
            'data_conclusao': '2025-10-15',
            'vulnerabilidade': 'API GraphQL sem limitação de taxa (Rate Limiting)',
            'severidade': 'media',
            'plano_remediacao': 'Implementar Bucket Token no API Gateway',
            'prazo_remediacao': '2025-11-30',
            'status': 'em_andamento'
        }, token=admin_token, company_id=1)
        self.assertIn(status, (200, 201))

        # Check it is in 1 and not in 2
        status, v1_after, _ = self.request('GET', '/api/auditorias_fragilidades', token=admin_token, company_id=1)
        self.assertTrue(any('GraphQL' in (v.get('vulnerabilidade') or v.get('titulo') or '') for v1 in [v1_after] for v in v1))
        status, v2_after, _ = self.request('GET', '/api/auditorias_fragilidades', token=admin_token, company_id=2)
        self.assertFalse(any('GraphQL' in (v.get('vulnerabilidade') or v.get('titulo') or '') for v2 in [v2_after] for v in v2))

    def test_09_art8_annual_report_all_mandatory_sections(self):
        """Validates all 8 regulatory sections of the Annual Report per Art. 8º."""
        admin_token = self.tokens['admin']

        status, rep, _ = self.request('GET', '/api/relatorio_anual', token=admin_token, company_id=1)
        self.assertEqual(status, 200)

        # 1. Identificação Regulatória
        s1 = rep['secao_1_identificacao_regulatoria']
        self.assertIn("Alpha", s1['razao_social'])
        self.assertEqual(s1['cnpj'], "00.123.456/0001-78")
        self.assertEqual(s1['segmento_bacen'], "S3")
        self.assertIn("Roberto Silveira Mello", s1['diretor_responsavel'])

        # 2. Avaliação da Efetividade
        s2 = rep['secao_2_efetividade_politica']
        self.assertIn('taxa_conformidade_geral', s2)
        self.assertIn('res_4893_32_requisitos', s2)
        self.assertIn('res_5274_14_controles', s2)
        self.assertEqual(s2['res_5274_14_controles']['total_controles'], 14)

        # 3. Consolidado de Incidentes
        s3 = rep['secao_3_incidentes_relevantes']
        self.assertIn('total_incidentes', s3)
        self.assertIn('mttd_medio_minutos', s3)
        self.assertIn('mttr_medio_minutos', s3)
        self.assertIn('tipologias', s3)

        # 4. Testes e Simulados PARI
        s4 = rep['secao_4_testes_continuidade_pari']
        self.assertIn('total_simulados_realizados', s4)
        self.assertIn('simulados', s4)

        # 5. Auditorias e Fragilidades
        s5 = rep['secao_5_auditorias_fragilidades']
        self.assertIn('total_fragilidades_identificadas', s5)
        self.assertIn('vulnerabilidades', s5)

        # 6. Planos de Ação 5W2H e Nuvem
        s6 = rep['secao_6_planos_acao_terceiros']
        self.assertIn('total_planos_5w2h', s6)
        self.assertIn('provedores_nuvem_relevantes', s6)

        # 7. Parecer do Diretor Estatutário
        s7 = rep['secao_7_parecer_diretor']
        self.assertIn('diretor_nome', s7)
        self.assertIn('assinado_digitalmente', s7)

        # 8. Exportação e Integridade Documental
        s8 = rep['secao_8_exportacao_metadados']
        self.assertEqual(s8['instituicao_id'], 1)
        self.assertTrue(s8['hash_sha256_integridade'])
        self.assertEqual(len(s8['hash_sha256_integridade']), 64)

    def test_10_art8_director_electronic_signature(self):
        """Tests electronic signature submission by the director and formal manifestation."""
        gestor1_token = self.tokens['gestor1']

        opinion_text = (
            "Na qualidade de Diretor Estatutário responsável pela Política de Segurança Cibernética "
            "perante o Banco Central do Brasil (Art. 7º da Resolução CMN nº 4.893/2021), manifesto "
            "que as medidas de salvaguarda, os 14 controles mandatórios da Res. CMN nº 5.274/2025 "
            "e os simulados de continuidade foram executados com nível de aderência compatível com o segmento S3."
        )

        status, body, _ = self.request('POST', '/api/relatorio_anual/parecer', {
            'parecer_conclusivo': opinion_text,
            'assinar_digitalmente': True,
            'ano_base': '2025'
        }, token=gestor1_token, company_id=1)

        self.assertEqual(status, 200)
        self.assertTrue(body.get('success'))
        self.assertTrue(body.get('hash_sha256'))

        # Fetch report again and confirm signature is persisted
        status, rep, _ = self.request('GET', '/api/relatorio_anual', token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)
        s7 = rep['secao_7_parecer_diretor']
        self.assertTrue(s7['assinado_digitalmente'])
        self.assertEqual(s7['parecer_conclusivo'], opinion_text)
        self.assertTrue(s7['hash_sha256_parecer'])

    def test_11_art8_export_json_endpoint(self):
        """Tests GET /api/relatorio_anual/export/json downloads complete regulatory report."""
        admin_token = self.tokens['admin']
        status, body, headers = self.request('GET', '/api/relatorio_anual/export/json', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertIn('application/json', headers.get('Content-Type', ''))
        self.assertIn('attachment', headers.get('Content-Disposition', ''))
        self.assertIn('secao_1_identificacao_regulatoria', body)
        self.assertIn('secao_8_exportacao_metadados', body)

    def test_12_audit_trail_isolation(self):
        """Audit trail entries are segregated strictly per institution."""
        admin_token = self.tokens['admin']

        status, logs1, _ = self.request('GET', '/api/auditoria_log', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(all(l['instituicao_id'] == 1 for l in logs1))

        status, logs2, _ = self.request('GET', '/api/auditoria_log', token=admin_token, company_id=2)
        self.assertEqual(status, 200)
        self.assertTrue(all(l['instituicao_id'] == 2 for l in logs2))

    def test_13_pari_playbooks_crud_and_tenant_isolation(self):
        """Tests edit (PUT) and delete (DELETE) on PARI playbooks with multi-tenant least privilege."""
        gestor1_token = self.tokens['gestor1']
        gestor2_token = self.tokens['gestor2']

        # 1. Gestor 1 creates a playbook on Alpha Bank (inst 1)
        status, body, _ = self.request('POST', '/api/pari/playbooks', {
            'codigo': 'PB-TEST-99',
            'categoria': 'Ransomware',
            'titulo_cenario': 'Playbook de Teste de Exfiltração de Chaves',
            'etapa_deteccao': 'Detecção via SIEM / EDR',
            'etapa_contencao': 'Isolamento de VLAN de servidores',
            'etapa_erradicacao': 'Revogação de certificados e senhas',
            'etapa_recuperacao': 'Restauração a partir de backup imutável',
            'etapa_comunicacao_bacen': 'Notificação SISBACEN imediata',
            'tempo_estimado_resposta': '30 minutos'
        }, token=gestor1_token, company_id=1)
        self.assertIn(status, (200, 201))
        pb_id = body.get('id')
        self.assertTrue(pb_id)

        # 2. Gestor 1 updates the playbook (PUT)
        status, put_resp, _ = self.request('PUT', f'/api/pari/playbooks/{pb_id}', {
            'codigo': 'PB-TEST-99',
            'categoria': 'Ransomware',
            'titulo_cenario': 'Playbook de Teste de Exfiltração de Chaves - ATUALIZADO',
            'etapa_deteccao': 'Detecção via SIEM e telemetria SOC 24x7',
            'etapa_contencao': 'Isolamento imediato de endpoint',
            'etapa_erradicacao': 'Revogação de chaves',
            'etapa_recuperacao': 'Subida de cluster secundário',
            'etapa_comunicacao_bacen': 'Notificação via SISBACEN em até 2h',
            'tempo_estimado_resposta': '15 minutos'
        }, token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(put_resp.get('success'))

        # Verify update on Alpha Bank
        status, pari1, _ = self.request('GET', '/api/pari', token=gestor1_token, company_id=1)
        updated_pb = next((p for p in pari1['playbooks'] if p['id'] == pb_id), None)
        self.assertIsNotNone(updated_pb)
        self.assertIn("ATUALIZADO", updated_pb['titulo_cenario'])

        # 3. Gestor 2 (Torra SCD) attempting to update or delete Alpha Bank's playbook is FORBIDDEN (403)
        status, _, _ = self.request('PUT', f'/api/pari/playbooks/{pb_id}', {
            'codigo': 'PB-HACK',
            'titulo_cenario': 'Cross Tenant Tampering'
        }, token=gestor2_token, company_id=1)
        self.assertEqual(status, 403)

        status, _, _ = self.request('DELETE', f'/api/pari/playbooks/{pb_id}', token=gestor2_token, company_id=1)
        self.assertEqual(status, 403)

        # 4. Gestor 1 deletes the playbook (DELETE)
        status, del_resp, _ = self.request('DELETE', f'/api/pari/playbooks/{pb_id}', token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(del_resp.get('success'))

        # Verify removal
        status, pari1_after, _ = self.request('GET', '/api/pari', token=gestor1_token, company_id=1)
        self.assertFalse(any(p['id'] == pb_id for p in pari1_after['playbooks']))

    def test_14_pari_simulados_crud_and_tenant_isolation(self):
        """Tests edit (PUT) and delete (DELETE) on crisis drills (simulados) with tenant isolation."""
        gestor1_token = self.tokens['gestor1']
        gestor2_token = self.tokens['gestor2']

        # 1. Create a crisis drill
        status, body, _ = self.request('POST', '/api/pari/simulados', {
            'titulo_simulado': 'Simulado Mesa de Crise Ransomware 2026',
            'data_realizacao': '2026-03-10',
            'cenario_testado': 'Criptografia em massa do storage de homologação',
            'participantes': 'Diretoria, CISO, CSIRT, Jurídico',
            'tempo_resposta_alcancado': '25 minutos',
            'pontos_fortes': 'Rapidez no isolamento do storage',
            'gargalos_identificados': 'Comunicação inicial com stakeholders externos',
            'acoes_melhoria': 'Atualizar matriz de contatos externos do PARI',
            'status': 'Concluido'
        }, token=gestor1_token, company_id=1)
        self.assertIn(status, (200, 201))
        sim_id = body.get('id')
        self.assertTrue(sim_id)

        # 2. Update the drill (PUT)
        status, put_resp, _ = self.request('PUT', f'/api/pari/simulados/{sim_id}', {
            'titulo_simulado': 'Simulado Mesa de Crise Ransomware 2026 - REVISADO',
            'data_realizacao': '2026-03-10',
            'cenario_testado': 'Criptografia em massa do storage',
            'participantes': 'Diretoria Executiva, CISO e CSIRT',
            'tempo_resposta_alcancado': '20 minutos',
            'pontos_fortes': 'Isolamento exemplar',
            'gargalos_identificados': 'Nenhum gargalo crítico',
            'acoes_melhoria': 'Revisão periódica',
            'status': 'Concluido'
        }, token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)

        # 3. Cross-tenant attempt from Gestor 2 -> 403
        status, _, _ = self.request('DELETE', f'/api/pari/simulados/{sim_id}', token=gestor2_token, company_id=1)
        self.assertEqual(status, 403)

        # 4. Delete the drill
        status, del_resp, _ = self.request('DELETE', f'/api/pari/simulados/{sim_id}', token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)

    def test_15_incidentes_crud_and_status_audit(self):
        """Tests incident registration, edit with SISBACEN flag and status change to Encerrado with audit log."""
        gestor1_token = self.tokens['gestor1']
        admin_token = self.tokens['admin']

        # 1. Register a new incident
        status, body, _ = self.request('POST', '/api/incidentes', {
            'protocolo': 'INC-2026-999',
            'titulo': 'Indisponibilidade momentânea no gateway de pagamentos',
            'categoria': 'Indisponibilidade de API / Nuvem',
            'criticidade': 'Alta',
            'sistemas_afetados': 'API Gateway e Mensageria PIX',
            'impacto_operacional': 'Lentidão em requisições de pagamentos durante 12 minutos',
            'status': 'Em Investigação',
            'notificado_bacen': 0,
            'tempo_deteccao_minutos': 5,
            'tempo_resolucao_minutos': 20
        }, token=gestor1_token, company_id=1)
        self.assertIn(status, (200, 201))
        inc_id = body.get('id')
        self.assertTrue(inc_id)

        # 2. Update incident (status to Encerrado, SISBACEN notified)
        status, put_resp, _ = self.request('PUT', f'/api/incidentes/{inc_id}', {
            'titulo': 'Indisponibilidade momentânea no gateway de pagamentos - MITIGADO',
            'categoria': 'Indisponibilidade de API / Nuvem',
            'criticidade': 'Alta',
            'sistemas_afetados': 'API Gateway e Mensageria PIX',
            'impacto_operacional': 'Restabelecimento completo após chaveamento de contingência',
            'status': 'Encerrado',
            'notificado_bacen': 1,
            'data_notificacao_bacen': '2026-03-15',
            'causa_raiz': 'Esgotamento de pool de conexões com o banco de dados réplica',
            'acoes_corretivas': 'Aumento da capacidade do pool e autoscaling configurado',
            'tempo_deteccao_minutos': 5,
            'tempo_resolucao_minutos': 18
        }, token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)

        # Verify audit trail for this incident
        status, logs, _ = self.request('GET', '/api/auditoria_log', token=admin_token, company_id=1)
        self.assertEqual(status, 200)
        self.assertTrue(any(l['entidade'] == 'incidentes' and l['acao'] == 'ATUALIZAR_INCIDENTE' for l in logs))

        # 3. Delete incident
        status, del_resp, _ = self.request('DELETE', f'/api/incidentes/{inc_id}', token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)

    def test_16_fornecedores_nuvem_crud_and_tenant_isolation(self):
        """Tests cloud provider creation, full update (PUT) and deletion (DELETE) with tenant isolation."""
        gestor1_token = self.tokens['gestor1']
        gestor2_token = self.tokens['gestor2']

        # 1. Register cloud provider on Alpha Bank (inst 1)
        status, body, _ = self.request('POST', '/api/fornecedores_nuvem', {
            'nome_provedor': 'Google Cloud Platform (GCP)',
            'servico_prestado': 'Data Lake Corporativo e BigQuery para análise de fraudes',
            'tipo_nuvem': 'PaaS',
            'pais_armazenamento': 'Brasil (São Paulo southamerica-east1)',
            'servico_relevante': 1,
            'notificado_bacen': 1,
            'data_notificacao_bacen': '2025-06-10',
            'convenio_bacen_pais': 1,
            'clausula_acesso_bacen': 1,
            'clausula_segregacao_dados': 1,
            'clausula_continuidade': 1,
            'clausula_reversibilidade': 1,
            'data_ultimo_teste_contingencia': '2026-01-20',
            'nivel_risco': 'Baixo',
            'observacoes': 'Certificação ISO 27001 e SOC 2 Type II atestadas.'
        }, token=gestor1_token, company_id=1)
        self.assertIn(status, (200, 201))
        f_id = body.get('id')
        self.assertTrue(f_id)

        # 2. Update cloud provider (PUT)
        status, put_resp, _ = self.request('PUT', f'/api/fornecedores_nuvem/{f_id}', {
            'nome_provedor': 'Google Cloud Platform (GCP) Enterprise',
            'servico_prestado': 'Data Lake Corporativo, BigQuery e Vertex AI para antifraude',
            'tipo_nuvem': 'PaaS',
            'pais_armazenamento': 'Brasil (São Paulo) e EUA',
            'servico_relevante': 1,
            'notificado_bacen': 1,
            'data_notificacao_bacen': '2025-06-10',
            'convenio_bacen_pais': 1,
            'clausula_acesso_bacen': 1,
            'clausula_segregacao_dados': 1,
            'clausula_continuidade': 1,
            'clausula_reversibilidade': 1,
            'data_ultimo_teste_contingencia': '2026-02-15',
            'nivel_risco': 'Baixo',
            'observacoes': 'Due diligence renovada sem ressalvas.'
        }, token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)

        # Verify update on Alpha Bank
        status, providers1, _ = self.request('GET', '/api/fornecedores_nuvem', token=gestor1_token, company_id=1)
        updated_f = next((p for p in providers1 if p['id'] == f_id), None)
        self.assertIsNotNone(updated_f)
        self.assertIn("Enterprise", updated_f['nome_provedor'])

        # 3. Gestor 2 attempting to delete Alpha Bank provider -> 403
        status, _, _ = self.request('DELETE', f'/api/fornecedores_nuvem/{f_id}', token=gestor2_token, company_id=1)
        self.assertEqual(status, 403)

        # 4. Gestor 1 deletes the provider
        status, del_resp, _ = self.request('DELETE', f'/api/fornecedores_nuvem/{f_id}', token=gestor1_token, company_id=1)
        self.assertEqual(status, 200)

        # Verify removal
        status, providers1_after, _ = self.request('GET', '/api/fornecedores_nuvem', token=gestor1_token, company_id=1)
        self.assertFalse(any(p['id'] == f_id for p in providers1_after))

if __name__ == '__main__':
    unittest.main()
