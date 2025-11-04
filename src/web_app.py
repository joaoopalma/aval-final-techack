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


def generate_phishing_result_html(result, is_safe):
    """Gera HTML com o resultado da verificação"""
    
    status_color = '#28a745' if is_safe else '#dc3545'
    status_icon = '✅' if is_safe else '⚠️'
    status_text = 'URL Segura' if is_safe else 'URL Suspeita/Maliciosa'
    
    reasons_html = ''
    if result.get('reasons'):
        reasons_html = '<h3>🚨 Motivos de Alerta:</h3><ul>'
        for reason in result['reasons']:
            if reason == 'blacklist':
                reasons_html += '<li><strong>Blacklist:</strong> URL encontrada em lista de phishing conhecida</li>'
            elif reason == 'suspicious_patterns':
                reasons_html += '<li><strong>Padrões Suspeitos:</strong> Caracteres ou padrões maliciosos detectados</li>'
            elif reason == 'login_form':
                reasons_html += '<li><strong>Formulário de Login:</strong> Página contém formulário solicitando senha</li>'
        reasons_html += '</ul>'
    
    blacklist_html = ''
    if result.get('blacklist_matches'):
        blacklist_html = f'<p><strong>Blacklist Matches:</strong> {", ".join(result["blacklist_matches"])}</p>'
    
    similarity_html = '<h3>🔍 Similaridade com Marcas Conhecidas:</h3><table>'
    if result.get('similarity'):
        for brand, score in sorted(result['similarity'].items(), key=lambda x: x[1], reverse=True)[:5]:
            if score > 0.6:
                similarity_html += f'<tr><td>{brand}</td><td>{score:.2%}</td></tr>'
    similarity_html += '</table>'
    
    html = f"""
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resultado da Verificação - Phishing</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .nav {{
            margin-bottom: 30px;
        }}
        .nav a {{
            color: #667eea;
            text-decoration: none;
            font-size: 1.1em;
        }}
        .nav a:hover {{ text-decoration: underline; }}
        .status {{
            background-color: {status_color};
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }}
        .status-icon {{
            font-size: 4em;
            margin-bottom: 10px;
        }}
        .status-text {{
            font-size: 2em;
            font-weight: bold;
        }}
        .url-box {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            word-break: break-all;
            border-left: 4px solid {status_color};
        }}
        .details {{
            margin-top: 30px;
        }}
        h3 {{
            color: #2c3e50;
            margin: 20px 0 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        table th, table td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        table th {{
            background-color: #667eea;
            color: white;
        }}
        ul {{
            margin-left: 20px;
            line-height: 1.8;
        }}
        .metric {{
            display: inline-block;
            background-color: #e9ecef;
            padding: 10px 20px;
            margin: 5px;
            border-radius: 5px;
        }}
        .metric-label {{
            font-size: 0.9em;
            color: #6c757d;
        }}
        .metric-value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .btn {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            border-radius: 25px;
            text-decoration: none;
            margin-top: 20px;
            transition: transform 0.2s;
        }}
        .btn:hover {{
            transform: scale(1.05);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/phishing">← Nova Verificação</a> | 
            <a href="/phishing-history">📜 Histórico</a> |
            <a href="/">🏠 Menu Principal</a>
        </div>
        
        <div class="status">
            <div class="status-icon">{status_icon}</div>
            <div class="status-text">{status_text}</div>
        </div>
        
        <div class="url-box">
            <strong>URL Verificada:</strong><br>
            {result['url']}
        </div>
        
        <div class="details">
            <h3>📊 Resumo da Análise</h3>
            <div class="metric">
                <div class="metric-label">Domínio</div>
                <div class="metric-value">{result.get('domain', 'N/A')}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Score Suspeito</div>
                <div class="metric-value">{result.get('suspicious_score', 0)}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Blacklist</div>
                <div class="metric-value">{'❌ SIM' if result.get('blacklisted') else '✅ NÃO'}</div>
            </div>
            
            {reasons_html}
            {blacklist_html}
            {similarity_html if result.get('similarity') else ''}
            
            <h3>🔒 Informações SSL</h3>
            <p>SSL Disponível: {result.get('ssl', {}).get('available', False)}</p>
            
            <h3>📋 Detalhes Completos (JSON)</h3>
            <pre style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto;">
{json.dumps(result, indent=2, ensure_ascii=False)}
            </pre>
        </div>
        
        <div style="text-align: center;">
            <a href="/phishing" class="btn">🔍 Verificar Outra URL</a>
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
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
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
            margin-bottom: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
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
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/phishing">← Nova Verificação</a> | 
            <a href="/">🏠 Menu Principal</a>
        </div>
        
        <h1>📜 Histórico de Verificações de Phishing</h1>
        
        {% if history %}
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
</body>
</html>
"""


if __name__ == '__main__':
    ensure_dirs()
    # Porta 8080 para compatibilidade com Dockerfile
    app.run(host='0.0.0.0', port=8080, debug=True)

