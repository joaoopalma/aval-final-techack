"""
Aplicação web (Flask) para visualizar e gerar relatórios do sistema.

Funcionalidades:
1. Análise de Logs de Servidor (Apache/Nginx)
2. Verificação de URLs contra Phishing

Endpoints:
 - GET / : Página inicial com menu de navegação
 - GET /logs : Interface de análise de logs
 - POST /upload : Upload e processamento de logs
 - GET /report.html, /report.json, /processed.csv : Relatórios de logs
 - GET /phishing : Interface de verificação de phishing
 - POST /check-phishing : Verifica URL contra phishing
 - GET /phishing-history : Histórico de verificações
"""

import os
import sys
import json
from flask import Flask, request, redirect, send_file, abort, render_template_string, url_for, jsonify

# Get the project root directory (parent of src/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
REPORTS_DIR = PROJECT_ROOT  # Reports are saved in project root

app = Flask(__name__)


# ============================================================================
# HTML TEMPLATES
# ============================================================================

HOME_HTML = """
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Detecção de Ameaças Cibernéticas</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 900px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .subtitle {
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 40px;
            font-size: 1.1em;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        .feature-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            padding: 30px;
            color: white;
            text-decoration: none;
            transition: transform 0.3s, box-shadow 0.3s;
            display: block;
        }
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }
        .feature-icon {
            font-size: 3em;
            margin-bottom: 15px;
            text-align: center;
        }
        .feature-title {
            font-size: 1.5em;
            font-weight: bold;
            margin-bottom: 10px;
            text-align: center;
        }
        .feature-desc {
            text-align: center;
            opacity: 0.9;
            line-height: 1.6;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Sistema de Detecção de Ameaças</h1>
        <p class="subtitle">Proteção completa contra ameaças cibernéticas</p>
        
        <div class="features">
            <a href="/logs" class="feature-card">
                <div class="feature-icon">📊</div>
                <div class="feature-title">Análise de Logs</div>
                <div class="feature-desc">
                    Analise logs de servidor Apache/Nginx, detecte padrões suspeitos e gere relatórios detalhados
                </div>
            </a>
            
            <a href="/phishing" class="feature-card">
                <div class="feature-icon">🎣</div>
                <div class="feature-title">Verificação de Phishing</div>
                <div class="feature-desc">
                    Verifique URLs contra listas de phishing conhecidas e detecte características suspeitas
                </div>
            </a>
        </div>
        
        <div class="footer">
            <p>Sistema desenvolvido para proteção e análise de segurança cibernética</p>
        </div>
    </div>
</body>
</html>
"""

LOGS_HTML = """
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Análise de Logs - Detector de Ameaças</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .nav {
            margin-bottom: 30px;
        }
        .nav a {
            color: #667eea;
            text-decoration: none;
            font-size: 1.1em;
        }
        .nav a:hover { text-decoration: underline; }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
        }
        .upload-form {
            border: 2px dashed #667eea;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            background-color: #f8f9ff;
        }
        input[type="file"] {
            margin: 20px 0;
            padding: 10px;
        }
        input[type="submit"] {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 40px;
            border-radius: 25px;
            font-size: 1.1em;
            cursor: pointer;
            transition: transform 0.2s;
        }
        input[type="submit"]:hover {
            transform: scale(1.05);
        }
        .reports {
            margin-top: 40px;
        }
        .reports h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        .reports ul {
            list-style: none;
        }
        .reports li {
            margin: 10px 0;
        }
        .reports a {
            color: #667eea;
            text-decoration: none;
            padding: 10px 15px;
            display: inline-block;
            border: 1px solid #667eea;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .reports a:hover {
            background-color: #667eea;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">← Voltar ao Menu Principal</a>
        </div>
        
        <h1>📊 Análise de Logs de Servidor</h1>
        <p class="subtitle">Upload de arquivo de log (formato Apache/Nginx Combined)</p>
        
        <div class="upload-form">
            <form action="/upload" method="post" enctype="multipart/form-data">
                <p>📁 Selecione o arquivo de log para análise</p>
                <input type="file" name="logfile" accept=".log,.txt" required />
                <br>
                <input type="submit" value="Enviar e Processar" />
            </form>
        </div>
        
        <div class="reports">
            <h3>📄 Relatórios Disponíveis</h3>
            <ul>
                <li><a href="/report.html">🌐 Relatório HTML Completo</a></li>
                <li><a href="/report.json">📋 Relatório JSON (Dados Estruturados)</a></li>
                <li><a href="/processed.csv">📊 Dados Processados (CSV)</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
"""

PHISHING_HTML = """
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verificação de Phishing - Detector de Ameaças</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .nav {
            margin-bottom: 30px;
        }
        .nav a {
            color: #667eea;
            text-decoration: none;
            font-size: 1.1em;
        }
        .nav a:hover { text-decoration: underline; }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
        }
        .check-form {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .check-form label {
            color: white;
            display: block;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        .check-form input[type="url"] {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 5px;
            font-size: 1em;
            margin-bottom: 15px;
        }
        .check-form input[type="submit"] {
            background: white;
            color: #667eea;
            border: none;
            padding: 15px 40px;
            border-radius: 25px;
            font-size: 1.1em;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .check-form input[type="submit"]:hover {
            transform: scale(1.05);
        }
        .history-link {
            text-align: center;
            margin-top: 20px;
        }
        .history-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 1.1em;
        }
        .history-link a:hover { text-decoration: underline; }
        .info {
            background-color: #e8f4f8;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .info h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .info ul {
            margin-left: 20px;
            line-height: 1.8;
            color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">← Voltar ao Menu Principal</a>
        </div>
        
        <h1>🎣 Verificação de URLs contra Phishing</h1>
        <p class="subtitle">Insira uma URL para verificar se é segura ou maliciosa</p>
        
        <div class="check-form">
            <form action="/check-phishing" method="post">
                <label for="url">🔗 URL para Verificar:</label>
                <input type="url" id="url" name="url" placeholder="https://exemplo.com" required />
                <input type="submit" value="🔍 Verificar URL" />
            </form>
        </div>
        
        <div class="history-link">
            <a href="/phishing-history">📜 Ver Histórico de Verificações</a>
        </div>
        
        <div class="info">
            <h3>ℹ️ O que verificamos:</h3>
            <ul>
                <li>✅ Domínio em listas de phishing conhecidas (PhishTank, OpenPhish)</li>
                <li>✅ Presença de números em substituição a letras no domínio</li>
                <li>✅ Uso excessivo de subdomínios</li>
                <li>✅ Presença de caracteres especiais suspeitos</li>
                <li>✅ Similaridade com marcas conhecidas</li>
                <li>✅ Certificado SSL (se HTTPS)</li>
                <li>✅ Redirects suspeitos</li>
                <li>✅ Formulários de login no conteúdo</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""



# ============================================================================
# FLASK ENDPOINTS
# ============================================================================

def ensure_dirs():
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)


@app.route('/', methods=['GET'])
def index():
    """Página inicial com menu de navegação"""
    return render_template_string(HOME_HTML)


@app.route('/logs', methods=['GET'])
def logs_page():
    """Página de análise de logs"""
    return render_template_string(LOGS_HTML)


@app.route('/phishing', methods=['GET'])
def phishing_page():
    """Página de verificação de phishing"""
    return render_template_string(PHISHING_HTML)


@app.route('/report.html')
def report_html():
    html_report = os.path.join(REPORTS_DIR, 'threat_report.html')
    if os.path.exists(html_report):
        return send_file(html_report)
    return redirect(url_for('logs_page'))


@app.route('/report.json')
def report_json():
    json_report = os.path.join(REPORTS_DIR, 'threat_report.json')
    if os.path.exists(json_report):
        return send_file(json_report)
    abort(404)


@app.route('/processed.csv')
def processed_csv():
    csv_file = os.path.join(REPORTS_DIR, 'processed_logs.csv')
    if os.path.exists(csv_file):
        return send_file(csv_file)
    abort(404)


@app.route('/upload', methods=['POST'])
def upload_and_process():
    ensure_dirs()

    if 'logfile' not in request.files:
        return 'Arquivo não enviado', 400

    f = request.files['logfile']
    if f.filename == '':
        return 'Arquivo inválido', 400

    upload_path = os.path.join(LOGS_DIR, 'uploaded.log')
    f.save(upload_path)

    # Run pipeline programmatically
    try:
        # Add parent directory to path to allow imports
        sys.path.insert(0, PROJECT_ROOT)
        
        from src.scanner import LogScanner
        from src.utils.preprocessor import DataPreprocessor
        from src.report_generator import ReportGenerator

        scanner = LogScanner()
        scanner.collect_logs_from_file(upload_path)
        df = scanner.get_dataframe()

        pre = DataPreprocessor()
        pre.load_data(df)
        cleaned = pre.clean_all()

        gen = ReportGenerator(cleaned)
        gen.generate_json_report(os.path.join(REPORTS_DIR, 'threat_report.json'))
        gen.generate_html_report(os.path.join(REPORTS_DIR, 'threat_report.html'))

        cleaned.to_csv(os.path.join(REPORTS_DIR, 'processed_logs.csv'), index=False)

    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        return f'Erro ao processar logs: {e}<br><pre>{error_detail}</pre>', 500

    return redirect(url_for('report_html'))


@app.route('/check-phishing', methods=['POST'])
def check_phishing():
    """Verifica uma URL contra phishing"""
    url_to_check = request.form.get('url', '').strip()
    
    if not url_to_check:
        return 'URL não fornecida', 400
    
    # Add parent directory to path to allow imports
    sys.path.insert(0, PROJECT_ROOT)
    
    try:
        from src.phishing.checker import check_url
        result = check_url(url_to_check)
        
        # Determinar se é segura ou maliciosa
        is_safe = not result.get('blacklisted', False) and result.get('suspicious_score', 0) == 0
        
        # Gerar HTML de resultado
        result_html = generate_phishing_result_html(result, is_safe)
        return result_html
        
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        return f'Erro ao verificar URL: {e}<br><pre>{error_detail}</pre>', 500


@app.route('/phishing-history', methods=['GET'])
def phishing_history():
    """Mostra histórico de verificações de phishing"""
    history_file = os.path.join(PROJECT_ROOT, 'data', 'phishing_checks.json')
    
    if not os.path.exists(history_file):
        history_data = []
    else:
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                history_data = json.load(f)
        except:
            history_data = []
    
    # Pegar últimas 20 verificações
    recent_history = history_data[-20:] if len(history_data) > 20 else history_data
    recent_history.reverse()  # Mais recentes primeiro
    
    return render_template_string(HISTORY_HTML, history=recent_history)


@app.route('/export-history-csv', methods=['GET'])
def export_history_csv():
    """Exporta histórico de verificações em formato CSV"""
    import csv
    from io import StringIO
    from flask import Response
    
    history_file = os.path.join(PROJECT_ROOT, 'data', 'phishing_checks.json')
    
    if not os.path.exists(history_file):
        return 'Nenhum histórico disponível', 404
    
    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            history_data = json.load(f)
    except:
        return 'Erro ao carregar histórico', 500
    
    # Criar CSV em memória
    si = StringIO()
    writer = csv.writer(si)
    
    # Cabeçalho
    writer.writerow(['URL', 'Domínio', 'Blacklisted', 'Score Suspeito', 'Motivos', 'DNS Dinâmico', 'SSL OK', 'Redirects Suspeitos'])
    
    # Dados
    for entry in history_data:
        writer.writerow([
            entry.get('url', ''),
            entry.get('domain', ''),
            'Sim' if entry.get('blacklisted') else 'Não',
            entry.get('suspicious_score', 0),
            ', '.join(entry.get('reasons', [])),
            'Sim' if entry.get('dynamic_dns', {}).get('is_dynamic_dns') else 'Não',
            'Sim' if entry.get('ssl', {}).get('domain_matches') else 'Não',
            'Sim' if entry.get('redirects', {}).get('is_suspicious') else 'Não'
        ])
    
    output = si.getvalue()
    si.close()
    
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=phishing_history.csv'}
    )


@app.route('/export-history-json', methods=['GET'])
def export_history_json():
    """Exporta histórico de verificações em formato JSON"""
    from flask import Response
    
    history_file = os.path.join(PROJECT_ROOT, 'data', 'phishing_checks.json')
    
    if not os.path.exists(history_file):
        return 'Nenhum histórico disponível', 404
    
    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            history_data = json.load(f)
    except:
        return 'Erro ao carregar histórico', 500
    
    return Response(
        json.dumps(history_data, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=phishing_history.json'}
    )
    
    return render_template_string(HISTORY_HTML, history=recent_history)


def generate_phishing_result_html(result, is_safe):
    """Gera HTML com o resultado da verificação - DASHBOARD DETALHADO CONCEITO B"""
    
    status_color = '#28a745' if is_safe else '#dc3545'
    status_icon = '✅' if is_safe else '⚠️'
    status_text = 'URL Segura' if is_safe else 'URL Suspeita/Maliciosa'
    
    # =====================================================
    # EXPLICAÇÕES EDUCATIVAS
    # =====================================================
    explanations = {
        'blacklist': {
            'title': 'Blacklist',
            'description': 'URL encontrada em bases de phishing conhecidas (OpenPhish, PhishTank)',
            'risk': 'CRÍTICO - Site confirmado como malicioso por comunidade de segurança'
        },
        'suspicious_patterns': {
            'title': 'Padrões Suspeitos',
            'description': 'Caracteres ou sequências maliciosas detectadas (SQL injection, XSS, etc.)',
            'risk': 'ALTO - Tentativas de exploração ou ofuscação de URL'
        },
        'login_form': {
            'title': 'Formulário de Login',
            'description': 'Página contém formulário solicitando senha',
            'risk': 'MÉDIO - Pode ser tentativa de roubo de credenciais'
        },
        'dynamic_dns': {
            'title': 'DNS Dinâmico',
            'description': 'Domínio usa serviço de DNS gratuito/dinâmico (no-ip, dyndns)',
            'risk': 'ALTO - Comum em campanhas de phishing temporárias'
        },
        'ssl_domain_mismatch': {
            'title': 'Certificado SSL Incompatível',
            'description': 'Certificado SSL não coincide com o domínio acessado',
            'risk': 'CRÍTICO - Possível ataque Man-in-the-Middle'
        },
        'ssl_self_signed': {
            'title': 'Certificado Auto-Assinado',
            'description': 'Certificado SSL não emitido por autoridade confiável',
            'risk': 'ALTO - Falta de validação de identidade'
        },
        'ssl_untrusted_ca': {
            'title': 'CA Não Confiável',
            'description': 'Certificado emitido por autoridade desconhecida',
            'risk': 'MÉDIO - Emissor não reconhecido entre CAs principais'
        },
        'suspicious_redirects': {
            'title': 'Redirecionamentos Suspeitos',
            'description': 'Múltiplos redirects ou mudança de domínio durante acesso',
            'risk': 'ALTO - Tentativa de ofuscar destino final'
        }
    }
    
    # =====================================================
    # CARD: MOTIVOS DE ALERTA
    # =====================================================
    reasons_html = ''
    if result.get('reasons'):
        reasons_html = '''
        <div class="card alert-card">
            <h3>🚨 Motivos de Alerta Detectados</h3>
            <div class="reasons-grid">
        '''
        for reason in result['reasons']:
            if reason in explanations:
                exp = explanations[reason]
                reasons_html += f'''
                <div class="reason-item">
                    <div class="reason-header">
                        <span class="reason-icon">⚠️</span>
                        <strong>{exp['title']}</strong>
                    </div>
                    <p class="reason-desc">{exp['description']}</p>
                    <p class="reason-risk"><strong>Risco:</strong> {exp['risk']}</p>
                </div>
                '''
        reasons_html += '</div></div>'
    
    # =====================================================
    # CARD: BLACKLIST
    # =====================================================
    blacklist_html = ''
    if result.get('blacklisted'):
        blacklist_html = f'''
        <div class="card danger-card">
            <h3>🛑 Verificação de Blacklist</h3>
            <p class="status-bad">❌ URL encontrada em blacklist de phishing</p>
            <p><strong>Fontes:</strong> OpenPhish, PhishTank</p>
            {f'<p><strong>Matches:</strong> {", ".join(result.get("blacklist_matches", []))}</p>' if result.get('blacklist_matches') else ''}
            <div class="help-text">
                <strong>O que significa:</strong> Este domínio foi reportado como phishing por bases de dados comunitárias de segurança.
            </div>
        </div>
        '''
    else:
        blacklist_html = '''
        <div class="card success-card">
            <h3>✅ Verificação de Blacklist</h3>
            <p class="status-good">✓ URL não encontrada em blacklists conhecidas</p>
            <p><strong>Fontes verificadas:</strong> OpenPhish, PhishTank</p>
        </div>
        '''
    
    # =====================================================
    # CARD: DNS DINÂMICO
    # =====================================================
    dns_html = ''
    if result.get('dynamic_dns'):
        dns_data = result['dynamic_dns']
        if dns_data.get('is_dynamic_dns'):
            dns_html = f'''
            <div class="card warning-card">
                <h3>🌐 Análise de DNS</h3>
                <p class="status-bad">⚠️ Domínio usa DNS dinâmico</p>
                <p><strong>Provider:</strong> {dns_data.get('provider', 'Desconhecido')}</p>
                <p><strong>Nível de Risco:</strong> {dns_data.get('risk_level', 'N/A').upper()}</p>
                <div class="help-text">
                    <strong>Por que é suspeito:</strong> Serviços de DNS dinâmico gratuitos são frequentemente usados em campanhas de phishing temporárias, pois permitem criar subdomínios rapidamente sem custo.
                </div>
            </div>
            '''
        else:
            dns_html = '''
            <div class="card success-card">
                <h3>🌐 Análise de DNS</h3>
                <p class="status-good">✓ Domínio não usa DNS dinâmico</p>
            </div>
            '''
    
    # =====================================================
    # CARD: CERTIFICADO SSL
    # =====================================================
    ssl_html = ''
    if result.get('ssl', {}).get('available'):
        ssl_data = result['ssl']
        domain_match = ssl_data.get('domain_matches', False)
        self_signed = ssl_data.get('is_self_signed', False)
        trusted_ca = ssl_data.get('is_trusted_ca', False)
        
        ssl_status_class = 'success-card' if (domain_match and not self_signed and trusted_ca) else 'warning-card'
        
        ssl_html = f'''
        <div class="card {ssl_status_class}">
            <h3>🔒 Certificado SSL/TLS</h3>
            <table class="details-table">
                <tr>
                    <td><strong>Domínio coincide:</strong></td>
                    <td>{'✅ Sim' if domain_match else '❌ Não'}</td>
                </tr>
                <tr>
                    <td><strong>Auto-assinado:</strong></td>
                    <td>{'⚠️ Sim' if self_signed else '✓ Não'}</td>
                </tr>
                <tr>
                    <td><strong>CA Confiável:</strong></td>
                    <td>{'✓ Sim' if trusted_ca else '⚠️ Não'}</td>
                </tr>
                <tr>
                    <td><strong>Emissor:</strong></td>
                    <td>{ssl_data.get('issuer_cn', 'N/A')}</td>
                </tr>
                <tr>
                    <td><strong>Common Name:</strong></td>
                    <td>{ssl_data.get('common_name', 'N/A')}</td>
                </tr>
                <tr>
                    <td><strong>Validade:</strong></td>
                    <td>{ssl_data.get('notBefore', 'N/A')} até {ssl_data.get('notAfter', 'N/A')}</td>
                </tr>
            </table>
            <div class="help-text">
                <strong>Importância:</strong> Certificados SSL válidos garantem que você está se comunicando com o servidor correto. Certificados auto-assinados ou incompatíveis são sinais de alerta.
            </div>
        </div>
        '''
    elif result.get('ssl', {}).get('reason') == 'not https':
        ssl_html = '''
        <div class="card warning-card">
            <h3>🔒 Certificado SSL/TLS</h3>
            <p class="status-bad">⚠️ Site não usa HTTPS</p>
            <div class="help-text">
                <strong>Risco:</strong> Comunicação não criptografada. Dados trafegam em texto plano e podem ser interceptados.
            </div>
        </div>
        '''
    
    # =====================================================
    # CARD: REDIRECIONAMENTOS
    # =====================================================
    redirect_html = ''
    if result.get('redirects', {}).get('available'):
        redir_data = result['redirects']
        is_suspicious = redir_data.get('is_suspicious', False)
        redirect_class = 'warning-card' if is_suspicious else 'success-card'
        
        redirect_html = f'''
        <div class="card {redirect_class}">
            <h3>🔄 Análise de Redirecionamentos</h3>
            <table class="details-table">
                <tr>
                    <td><strong>Total de redirects:</strong></td>
                    <td>{redir_data.get('redirect_count', 0)}</td>
                </tr>
                <tr>
                    <td><strong>Domínio mudou:</strong></td>
                    <td>{'⚠️ Sim' if redir_data.get('domain_changed') else '✓ Não'}</td>
                </tr>
                <tr>
                    <td><strong>Domínio original:</strong></td>
                    <td>{redir_data.get('original_domain', 'N/A')}</td>
                </tr>
                <tr>
                    <td><strong>Domínio final:</strong></td>
                    <td>{redir_data.get('final_domain', 'N/A')}</td>
                </tr>
                <tr>
                    <td><strong>Muitos redirects (>3):</strong></td>
                    <td>{'⚠️ Sim' if redir_data.get('too_many_redirects') else '✓ Não'}</td>
                </tr>
            </table>
            {f'<p class="status-bad">⚠️ Domínios suspeitos na chain: {", ".join(redir_data.get("suspicious_domains_in_chain", []))}</p>' if redir_data.get('suspicious_domains_in_chain') else ''}
            <div class="help-text">
                <strong>Atenção:</strong> Múltiplos redirecionamentos ou mudanças de domínio podem indicar tentativa de ofuscar o destino real da URL.
            </div>
        </div>
        '''
    
    # =====================================================
    # CARD: WHOIS / IDADE DO DOMÍNIO
    # =====================================================
    whois_html = ''
    if result.get('whois', {}).get('available'):
        whois_data = result['whois']
        whois_html = f'''
        <div class="card info-card">
            <h3>📅 Informações WHOIS</h3>
            <p><strong>Data de Criação:</strong> {whois_data.get('creation_date', 'N/A')}</p>
            <div class="help-text">
                <strong>Dica:</strong> Domínios muito novos (< 30 dias) são frequentemente usados em phishing. Atacantes criam domínios temporários para campanhas.
            </div>
        </div>
        '''
    
    # =====================================================
    # CARD: SIMILARIDADE COM MARCAS
    # =====================================================
    similarity_html = ''
    if result.get('similarity'):
        high_similarity = {k: v for k, v in result['similarity'].items() if v > 0.6}
        if high_similarity:
            similarity_html = '''
            <div class="card warning-card">
                <h3>🔍 Similaridade com Marcas Conhecidas</h3>
                <p class="status-bad">⚠️ Alta similaridade detectada:</p>
                <table class="details-table">
            '''
            for brand, score in sorted(high_similarity.items(), key=lambda x: x[1], reverse=True)[:5]:
                similarity_html += f'<tr><td><strong>{brand.capitalize()}</strong></td><td>{score:.1%}</td></tr>'
            similarity_html += '''
                </table>
                <div class="help-text">
                    <strong>Typosquatting:</strong> Atacantes registram domínios similares a marcas famosas (ex: paypa1.com em vez de paypal.com) para enganar vítimas.
                </div>
            </div>
            '''
    
    # =====================================================
    # CARD: ANÁLISE DE CONTEÚDO
    # =====================================================
    content_html = ''
    if result.get('content_analysis', {}).get('available'):
        content_data = result['content_analysis']
        forms_count = content_data.get('forms_found', 0)
        
        if forms_count > 0:
            has_password = any(f.get('has_password') for f in content_data.get('forms', []))
            content_class = 'warning-card' if has_password else 'info-card'
            
            content_html = f'''
            <div class="card {content_class}">
                <h3>📝 Análise de Conteúdo</h3>
                <p><strong>Formulários encontrados:</strong> {forms_count}</p>
                <p><strong>Formulários com senha:</strong> {'⚠️ Sim' if has_password else '✓ Não'}</p>
                <div class="help-text">
                    <strong>Atenção:</strong> Sites de phishing frequentemente usam formulários falsos para coletar credenciais. Verifique sempre a URL antes de inserir dados sensíveis.
                </div>
            </div>
            '''
        else:
            content_html = '''
            <div class="card success-card">
                <h3>📝 Análise de Conteúdo</h3>
                <p class="status-good">✓ Nenhum formulário detectado</p>
            </div>
            '''
    
    # =====================================================
    # HTML TEMPLATE COMPLETO COM CHART.JS
    # =====================================================
    
    html = f"""
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard de Análise - Phishing Detection</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .nav {{
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }}
        .nav a {{
            color: #667eea;
            text-decoration: none;
            font-size: 1.1em;
            font-weight: 500;
        }}
        .nav a:hover {{ text-decoration: underline; }}
        
        .status-header {{
            background: linear-gradient(135deg, {status_color} 0%, {status_color}dd 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 40px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }}
        .status-icon {{ font-size: 4em; margin-bottom: 10px; display: block; }}
        .status-text {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        .status-url {{
            background-color: rgba(255,255,255,0.2);
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            word-break: break-all;
            font-size: 1.1em;
        }}
        
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            border-left: 5px solid #3498db;
        }}
        .card h3 {{
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.4em;
        }}
        .success-card {{ border-left-color: #28a745; }}
        .warning-card {{ border-left-color: #ffc107; background-color: #fffbf0; }}
        .danger-card {{ border-left-color: #dc3545; background-color: #fff5f5; }}
        .alert-card {{ border-left-color: #ff6b6b; background-color: #fff0f0; }}
        .info-card {{ border-left-color: #17a2b8; }}
        
        .status-good {{ color: #28a745; font-weight: 600; font-size: 1.1em; }}
        .status-bad {{ color: #dc3545; font-weight: 600; font-size: 1.1em; }}
        
        .details-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        .details-table td {{
            padding: 10px 5px;
            border-bottom: 1px solid #eee;
        }}
        .details-table td:first-child {{
            width: 50%;
            color: #666;
        }}
        
        .help-text {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            font-size: 0.95em;
            border-left: 3px solid #667eea;
        }}
        .help-text strong {{ color: #667eea; }}
        
        .reasons-grid {{
            display: grid;
            gap: 15px;
            margin-top: 15px;
        }}
        .reason-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #ffdddd;
        }}
        .reason-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        .reason-icon {{ font-size: 1.5em; }}
        .reason-desc {{ color: #555; margin: 5px 0; }}
        .reason-risk {{
            color: #dc3545;
            font-size: 0.9em;
            margin-top: 8px;
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
            margin: 20px 0;
        }}
        
        @media (max-width: 768px) {{
            .cards-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">← Voltar ao Início</a> |
            <a href="/phishing">Nova Verificação</a> |
            <a href="/phishing-history">Histórico</a>
        </div>
        
        <div class="status-header">
            <span class="status-icon">{status_icon}</span>
            <div class="status-text">{status_text}</div>
            <div class="status-url">
                <strong>URL Analisada:</strong><br>
                {result.get('url', 'N/A')}
            </div>
        </div>
        
        <div class="cards-grid">
            {reasons_html}
            {blacklist_html}
            {dns_html}
            {ssl_html}
            {redirect_html}
            {whois_html}
            {similarity_html}
            {content_html}
        </div>
        
        <div class="card">
            <h3>📊 Resumo da Análise</h3>
            <p><strong>Total de verificações realizadas:</strong> {len(result.get('reasons', [])) + 6}</p>
            <p><strong>Indicadores de risco detectados:</strong> {len(result.get('reasons', []))}</p>
            <p><strong>Domínio:</strong> {result.get('domain', 'N/A')}</p>
        </div>
        
        <div class="card info-card" style="margin-top: 30px;">
            <h3>💡 Dicas de Segurança</h3>
            <ul style="padding-left: 20px; line-height: 1.8;">
                <li>Sempre verifique o domínio completo da URL antes de clicar</li>
                <li>Desconfie de e-mails urgentes solicitando dados pessoais</li>
                <li>Use gerenciadores de senhas para detectar sites falsos</li>
                <li>Ative autenticação em dois fatores quando disponível</li>
                <li>Mantenha seu navegador e antivírus atualizados</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
    
    return html


# Template para histórico
HISTORY_HTML = """
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Histórico de Verificações - Phishing</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .nav {
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }
        .nav a {
            color: #667eea;
            text-decoration: none;
            font-size: 1.1em;
            margin-right: 20px;
        }
        .nav a:hover { text-decoration: underline; }
        h1 {
            color: #2c3e50;
            margin-bottom: 30px;
            text-align: center;
        }
        .export-buttons {
            text-align: center;
            margin: 30px 0;
        }
        .btn-export {
            display: inline-block;
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            padding: 12px 30px;
            border-radius: 25px;
            text-decoration: none;
            margin: 0 10px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        .btn-export:hover {
            transform: scale(1.05);
        }
        .btn-export.json {
            background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
        }
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin: 40px 0;
        }
        .chart-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        .chart-card h3 {
            color: #2c3e50;
            margin-bottom: 20px;
            text-align: center;
        }
        .chart-container {
            position: relative;
            height: 300px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 30px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            position: sticky;
            top: 0;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        .safe {
            color: #28a745;
            font-weight: bold;
        }
        .unsafe {
            color: #dc3545;
            font-weight: bold;
        }
        .url-cell {
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            font-size: 1.1em;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/phishing">← Nova Verificação</a>
            <a href="/">🏠 Menu Principal</a>
        </div>
        
        <h1>📜 Histórico de Verificações de Phishing</h1>
        
        <div class="export-buttons">
            <a href="/export-history-csv" class="btn-export">📊 Exportar CSV</a>
            <a href="/export-history-json" class="btn-export json">📋 Exportar JSON</a>
        </div>
        
        {% if history %}
        
        <!-- Estatísticas -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total de Verificações</div>
                <div class="stat-value">{{ history|length }}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%);">
                <div class="stat-label">URLs Seguras</div>
                <div class="stat-value">{{ history|selectattr('blacklisted', 'equalto', false)|list|length }}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);">
                <div class="stat-label">URLs Suspeitas</div>
                <div class="stat-value">{{ history|selectattr('blacklisted', 'equalto', true)|list|length }}</div>
            </div>
        </div>
        
        <!-- Gráficos -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3>📊 Distribuição: Seguras vs Suspeitas</h3>
                <div class="chart-container">
                    <canvas id="pieChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>📈 Top Características Detectadas</h3>
                <div class="chart-container">
                    <canvas id="barChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Tabela -->
        <h2 style="margin-top: 40px; color: #2c3e50;">🔍 Detalhamento</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Domínio</th>
                    <th>Status</th>
                    <th>Score Suspeito</th>
                    <th>Blacklist</th>
                </tr>
            </thead>
            <tbody>
                {% for item in history %}
                <tr>
                    <td class="url-cell" title="{{ item.url }}">{{ item.url }}</td>
                    <td>{{ item.domain }}</td>
                    <td class="{% if item.blacklisted or item.suspicious_score > 0 %}unsafe{% else %}safe{% endif %}">
                        {% if item.blacklisted or item.suspicious_score > 0 %}
                            ⚠️ Suspeita
                        {% else %}
                            ✅ Segura
                        {% endif %}
                    </td>
                    <td>{{ item.suspicious_score }}</td>
                    <td>{% if item.blacklisted %}❌ SIM{% else %}✅ NÃO{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p style="text-align: center; color: #7f8c8d; padding: 40px;">
            Nenhuma verificação realizada ainda.
        </p>
        {% endif %}
    </div>
    
    {% if history %}
    <script>
        // Dados do histórico
        const historyData = {{ history|tojson|safe }};
        
        // ============ GRÁFICO DE PIZZA: Seguras vs Suspeitas ============
        const safeCount = historyData.filter(item => !item.blacklisted && item.suspicious_score === 0).length;
        const suspiciousCount = historyData.length - safeCount;
        
        const pieCtx = document.getElementById('pieChart').getContext('2d');
        new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: ['URLs Seguras', 'URLs Suspeitas'],
                datasets: [{
                    data: [safeCount, suspiciousCount],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            font: {
                                size: 14,
                                family: "'Segoe UI', sans-serif"
                            },
                            padding: 20
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
        
        // ============ GRÁFICO DE BARRAS: Top Características ============
        const reasonCounts = {};
        historyData.forEach(item => {
            if (item.reasons && Array.isArray(item.reasons)) {
                item.reasons.forEach(reason => {
                    reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
                });
            }
        });
        
        const reasonLabels = Object.keys(reasonCounts);
        const reasonValues = Object.values(reasonCounts);
        
        // Mapear nomes amigáveis
        const friendlyNames = {
            'blacklist': 'Blacklist',
            'suspicious_patterns': 'Padrões Suspeitos',
            'login_form': 'Form de Login',
            'dynamic_dns': 'DNS Dinâmico',
            'ssl_domain_mismatch': 'SSL Incompatível',
            'ssl_self_signed': 'SSL Auto-Assinado',
            'ssl_untrusted_ca': 'CA Não Confiável',
            'suspicious_redirects': 'Redirects Suspeitos'
        };
        
        const barLabels = reasonLabels.map(r => friendlyNames[r] || r);
        
        const barCtx = document.getElementById('barChart').getContext('2d');
        new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: barLabels,
                datasets: [{
                    label: 'Ocorrências',
                    data: reasonValues,
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
    {% endif %}
</body>
</html>
"""


if __name__ == '__main__':
    ensure_dirs()
    # Porta 8080 para compatibilidade com Dockerfile
    app.run(host='0.0.0.0', port=8080, debug=True)

