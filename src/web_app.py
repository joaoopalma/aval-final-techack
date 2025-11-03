"""
Aplicação web (Flask) para visualizar e gerar relatórios do sistema.
Endpoints:
 - GET / : Exibe `threat_report.html` se existir, senão mostra formulário de upload
 - POST /upload : Faz upload de um arquivo de log, processa e gera relatórios
 - GET /report.json : Retorna `threat_report.json` se existir
 - GET /processed.csv : Retorna `processed_logs.csv` se existir
"""

import os
from flask import Flask, request, redirect, send_file, abort, render_template_string, url_for

app = Flask(__name__)


INDEX_HTML = """
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Detector de Ameaças - Relatórios</title></head>
  <body>
    <h1>Sistema de Detecção de Ameaças</h1>
    <p>Use este formulário para subir um arquivo de log (formato Apache/Nginx Combined) e gerar relatórios.</p>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <input type="file" name="logfile" accept="text/plain" required />
      <input type="submit" value="Enviar e Processar" />
    </form>
    <hr>
    <p>Arquivos disponíveis (se gerados):</p>
    <ul>
      <li><a href="/report.html">Relatório HTML</a></li>
      <li><a href="/report.json">Relatório JSON</a></li>
      <li><a href="/processed.csv">Dados processados (CSV)</a></li>
    </ul>
  </body>
</html>
"""


def ensure_dirs():
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports', exist_ok=True)


@app.route('/', methods=['GET'])
def index():
    # If HTML report exists, serve it
    if os.path.exists('threat_report.html'):
        return send_file('threat_report.html')
    return render_template_string(INDEX_HTML)


@app.route('/report.html')
def report_html():
    if os.path.exists('threat_report.html'):
        return send_file('threat_report.html')
    return redirect(url_for('index'))


@app.route('/report.json')
def report_json():
    if os.path.exists('threat_report.json'):
        return send_file('threat_report.json')
    abort(404)


@app.route('/processed.csv')
def processed_csv():
    if os.path.exists('processed_logs.csv'):
        return send_file('processed_logs.csv')
    abort(404)


@app.route('/upload', methods=['POST'])
def upload_and_process():
    ensure_dirs()

    if 'logfile' not in request.files:
        return 'Arquivo não enviado', 400

    f = request.files['logfile']
    if f.filename == '':
        return 'Arquivo inválido', 400

    upload_path = os.path.join('logs', 'uploaded.log')
    f.save(upload_path)

    # Run pipeline programmatically
    try:
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
        gen.generate_json_report('threat_report.json')
        gen.generate_html_report('threat_report.html')

        cleaned.to_csv('processed_logs.csv', index=False)

    except Exception as e:
        return f'Erro ao processar logs: {e}', 500

    return redirect(url_for('report_html'))


if __name__ == '__main__':
    ensure_dirs()
    # Porta 8080 para compatibilidade com Dockerfile
    app.run(host='0.0.0.0', port=8080)
