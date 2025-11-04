# Dockerfile para Sistema de Detecção de Ameaças Cibernéticas
FROM python:3.11-slim

# Definir diretório de trabalho
WORKDIR /app

# Copiar requirements
COPY src/requirements.txt .

# Instalar dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fonte
COPY src/ ./src/

# Copiar dados de blacklist para verificação de phishing
COPY data/ ./data/

# Criar diretórios necessários
RUN mkdir -p /app/logs /app/reports

# Variáveis de ambiente
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expor porta do servidor web
EXPOSE 8080

# Iniciar aplicação Flask (web_app.py serve relatórios e permite upload)
CMD ["python3", "src/web_app.py"]
