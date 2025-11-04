#  Sistema de Detecção de Ameaças Cibernéticas em Servidores Web

Sistema desenvolvido para identificar e classificar ameaças cibernéticas em servidores web através da análise de logs de acesso.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

##  Descrição

Este projeto implementa um sistema completo de detecção de ameaças que:

###  **1. Análise de Logs de Servidor**
-  Coleta logs detalhados de acesso ao servidor web (formato Apache/Nginx Combined)
-  Realiza pré-processamento e limpeza de dados
-  Identifica padrões potencialmente suspeitos (SQL Injection, XSS, Path Traversal, etc.)
-  Gera relatórios detalhados de segurança (HTML, JSON, CSV)
-  Interface web para upload de logs e visualização de relatórios

###  **2. Verificação de URLs contra Phishing**
-  Verifica domínios em listas de phishing conhecidas (PhishTank, OpenPhish)
-  Detecta características suspeitas:
  - Presença de números em substituição a letras no domínio
  - Uso excessivo de subdomínios
  - Presença de caracteres especiais na URL
  - Similaridade com marcas conhecidas (PayPal, Google, Facebook, etc.)
-  Interface web simples com:
  - Campo de entrada para URLs
  - Resultados em formato de tabela
  - **Indicador visual**  Verde/ Vermelho para URLs seguras/maliciosas
-  Análise avançada:
  - Certificado SSL (se HTTPS)
  - Redirects suspeitos
  - Formulários de login no conteúdo HTML
  - Histórico de verificações

###  **3. Containerização**
-  Containerização completa com Docker
-  Pronto para deploy em produção

---

##  Estrutura Completa do Projeto

```
aval-final-techack/
├── src/                           # Código-fonte principal
│   ├── scanner.py                 #  Módulo de coleta e parsing de logs
│   ├── report_generator.py        #  Gerador de relatórios (HTML/JSON)
│   ├── web_app.py                 #  Aplicação web Flask
│   ├── requirements.txt           #  Dependências Python do projeto
│   ├── __init__.py               # Inicialização do módulo src
│   │
│   ├── utils/                     # Utilitários
│   │   ├── __init__.py
│   │   └── preprocessor.py        # Limpeza e feature engineering
│   │
│   ├── tests/                     # Testes unitários
│   │   ├── __init__.py
│   │   ├── test_scanner.py        #  Testes do scanner
│   │   └── test_preprocessor.py   #  Testes do preprocessor
│   │
│   └── phishing/                  # Módulo adicional de phishing
│       └── checker.py             # Verificador de URLs phishing
│
├── docs/                          # Documentação
│   ├── architecture.md            # Descrição da arquitetura
│   ├── architecture_diagram.png.placeholder
│   └── flowchart.pdf.placeholder
│
├── data/                          # Dados auxiliares
│   ├── phishing_checks.json
│   └── blacklists/
│       ├── openphish_feed.txt     # Blacklist OpenPhish (16KB)
│       └── phishtank_feed.txt     # Blacklist PhishTank (10+ URLs)
│
├── .github/                       # Configurações GitHub
│   └── workflows/
│       └── security_scan.yml      #  CI/CD para análise de segurança
│
├── logs/                          # Diretório para logs uploaded
├── reports/                       # Diretório para relatórios gerados
│
├── Dockerfile                     #  Containerização
├── requirements.txt               # Dependências gerais
├── .gitignore                    # Arquivos ignorados pelo Git
└── README.md                      # Este arquivo
```

---

##  Descrição Detalhada dos Arquivos

###  `src/scanner.py`
**Módulo principal de coleta de logs**

Responsável por:
- Parsing de logs no formato Apache/Nginx Combined Log
- Extração de campos: IP, timestamp, método HTTP, URL, status, bytes
- Conversão para DataFrame pandas para análise
- Geração de estatísticas básicas

**Classe principal:**
```python
class LogScanner:
    def parse_log_line(line)              # Parse de uma linha de log
    def collect_logs_from_file(filepath)  # Coleta de arquivo
    def collect_logs_from_text(text)      # Coleta de string
    def get_dataframe()                   # Retorna pandas DataFrame
    def get_statistics()                  # Retorna estatísticas básicas
```

---

### `src/utils/preprocessor.py`
**Módulo de pré-processamento e feature engineering**

Responsável por:
- Remoção de valores ausentes e duplicatas
- Detecção e remoção de outliers (Z-score)
- Geração de atributos para análise de segurança

**Atributos gerados:**
- `request_size`: Tamanho total da requisição
- `path_length`: Comprimento do caminho da URL
- `path_depth`: Profundidade do caminho
- `has_extension`: Booleano indicando presença de extensão
- `status_category`: Categorização do status HTTP
- `has_params`: Booleano indicando parâmetros na URL
- `params_length`, `num_params`: Informações sobre parâmetros
- `suspicious_chars`: Contagem de caracteres suspeitos

**Padrões suspeitos detectados:**
- `..` → Path Traversal
- `<script>` → XSS (Cross-Site Scripting)
- `union`, `select`, `drop` → SQL Injection
- `exec` → Command Injection
- `%`, `\x` → Encoding suspeito

**Classe principal:**
```python
class DataPreprocessor:
    def load_data(df)                  # Carrega DataFrame
    def remove_missing_values()        # Remove NaN
    def remove_duplicates()            # Remove duplicatas
    def remove_outliers(columns)       # Remove outliers por Z-score
    def generate_features()            # Gera todos os atributos
    def clean_all()                    # Pipeline completo
    def get_summary()                  # Resumo do processamento
```

---

###  `src/report_generator.py`
**Gerador de relatórios de segurança**

Responsável por:
- Geração de relatórios de resumo e segurança
- Exportação em múltiplos formatos (HTML, JSON, CSV)
- Visualização de métricas e alertas

**Classe principal:**
```python
class ReportGenerator:
    def generate_summary_report()       # Relatório de estatísticas
    def generate_security_report()      # Relatório de segurança
    def generate_html_report(filepath)  # Exporta HTML
    def generate_json_report(filepath)  # Exporta JSON
    def print_console_report()          # Imprime no console
```

**Formato do relatório HTML:**
- Design responsivo e moderno
- Métricas destacadas (total de requisições, IPs únicos, taxa de erro)
- Tabelas de distribuição de status codes
- Alertas de segurança destacados

---

###  `src/web_app.py`
**Aplicação web Flask para interface do usuário**

Responsável por:
- Servir interface web para upload de logs
- Processar logs uploadados automaticamente
- Gerar relatórios em tempo real
- Servir relatórios HTML, JSON e CSV
- **NOVO:** Interface de verificação de URLs contra phishing

**Endpoints - Análise de Logs:**
- `GET /` → Página inicial com menu de navegação
- `GET /logs` → Interface de análise de logs
- `POST /upload` → Upload de arquivo de log
- `GET /report.html` → Relatório HTML
- `GET /report.json` → Relatório JSON
- `GET /processed.csv` → Dados processados CSV

**Endpoints - Verificação de Phishing:**
- `GET /phishing` → Interface de verificação de URLs
- `POST /check-phishing` → Verifica URL contra phishing
- `GET /phishing-history` → Histórico de verificações

**Porta:** 8080 (compatível com Docker)

**Fluxo de processamento de logs:**
1. Usuário faz upload de arquivo `.log`
2. App salva em `logs/uploaded.log`
3. Scanner processa o arquivo
4. Preprocessor limpa e gera features
5. ReportGenerator cria relatórios
6. Arquivos salvos em `reports/`
7. Redirect para visualização do relatório HTML

**Fluxo de verificação de phishing:**
1. Usuário insere URL no formulário
2. Sistema verifica em blacklists (PhishTank, OpenPhish)
3. Analisa características suspeitas (subdomínios, caracteres, similaridade)
4. Verifica SSL, redirects e conteúdo HTML
5. Exibe resultado com **indicador visual**  Verde/ Vermelho
6. Salva no histórico (`data/phishing_checks.json`)

---

###  `src/phishing/checker.py`
**Módulo de verificação de URLs contra phishing**

Responsável por:
- Carregar e verificar blacklists (OpenPhish, PhishTank)
- Detectar características suspeitas em URLs
- Analisar certificados SSL
- Verificar redirects HTTP
- Analisar conteúdo HTML para formulários de login
- Calcular similaridade com marcas conhecidas

**Funções principais:**
```python
check_url(url: str) -> Dict[str, Any]
    # Executa todas as verificações e retorna resultados

_load_blacklist() -> List[str]
    # Carrega lista de URLs maliciosas conhecidas

_detect_suspicious_chars(url: str) -> int
    # Detecta padrões suspeitos (SQL injection, XSS, etc.)

_domain_similarity(domain: str) -> Dict[str, float]
    # Calcula similaridade com marcas conhecidas

_check_ssl_cert(domain: str) -> Dict[str, Any]
    # Verifica certificado SSL

_check_redirects(url: str) -> Dict[str, Any]
    # Verifica redirects HTTP

_analyze_content_for_forms(url: str) -> Dict[str, Any]
    # Analisa HTML procurando formulários de login
```

**Características detectadas:**
-  URL em blacklist (PhishTank, OpenPhish)
-  Números substituindo letras no domínio (g00gle, paypa1)
-  Subdomínios excessivos (conta >= 4)
-  Caracteres especiais suspeitos (`..`, `<script>`, `union`, `exec`, `%`, etc.)
-  Similaridade com marcas conhecidas (PayPal, Google, Facebook, Apple, Microsoft, Amazon, etc.)
-  Certificado SSL ausente ou inválido
-  Redirects suspeitos
-  Formulários solicitando senhas

**Resultado exemplo:**
```json
{
  "url": "http://paypa1-secure.com",
  "domain": "paypa1-secure.com",
  "blacklisted": false,
  "suspicious_score": 2,
  "similarity": {"paypal": 0.85, "google": 0.2},
  "ssl": {"available": false, "reason": "not https"},
  "reasons": ["suspicious_patterns"]
}
```

---

###  `src/tests/`
**Testes unitários**

**test_scanner.py** - Testes do módulo scanner:
- Inicialização correta
- Parse de linha válida/inválida
- Parse de URL com parâmetros
- Coleta de logs
- Geração de estatísticas

**test_preprocessor.py** - Testes do módulo preprocessor:
- Carregamento de DataFrame
- Remoção de duplicatas
- Categorização de status HTTP
- Detecção de caracteres suspeitos
- Geração de features

---

###  `Dockerfile`
**Containerização da aplicação**

**Características:**
- Baseado em `python:3.11-slim`
- Instala dependências de `src/requirements.txt`
- Copia código-fonte para `/app/src/`
- Cria diretórios `logs/` e `reports/`
- Define `PYTHONPATH=/app` para imports corretos
- Expõe porta 8080
- Executa `python3 src/web_app.py`

---

###  `.github/workflows/security_scan.yml`
**Pipeline CI/CD para análise de segurança**

**Ferramentas configuradas:**
- **Bandit**: Análise de segurança em código Python
- **Safety**: Verificação de vulnerabilidades em dependências

**Triggers:**
- Push para branch `main`
- Pull requests
- Agendamento semanal

---

##  Instalação

### Requisitos
- Python 3.11+
- pip
- Docker (opcional, para containerização)

### Instalação Local

```bash
# Clone o repositório
git clone https://github.com/joaoopalma/aval-final-techack.git
cd aval-final-techack

# Instale as dependências
pip install -r src/requirements.txt
```

###  Usando Docker (Recomendado)

```bash
# Build da imagem
docker build -t threat-detection-system .

# Executar container com servidor web
docker run -p 8080:8080 threat-detection-system

# Acesse no navegador
# http://localhost:8080
```

---

## � **Runbook Docker - Guia Completo**

###  **Pré-requisitos**
- Docker instalado (versão 20.10+)
- Porta 8080 disponível

### **1. Build da Imagem**

```bash

# Build da imagem Docker
docker build -t threat-detection-system:latest .

# Verificar imagem criada
docker images | grep threat-detection-system
```

**Saída esperada:**
```
threat-detection-system   latest    <image-id>   X seconds ago   XXX MB
```

---

###  **2. Executar Container**

#### Modo Básico (Foreground)
```bash
docker run -p 8080:8080 threat-detection-system:latest
```

#### Modo Detached (Background)
```bash
docker run -d \
  --name threat-detector \
  -p 8080:8080 \
  threat-detection-system:latest
```

#### Com Volume Montado (Persistir Dados)
```bash
docker run -d \
  --name threat-detector \
  -p 8080:8080 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/data:/app/data \
  threat-detection-system:latest
```

---

###  **3. Verificar Status**

```bash
# Listar containers em execução
docker ps

# Ver logs do container
docker logs threat-detector

# Ver logs em tempo real
docker logs -f threat-detector

# Verificar uso de recursos
docker stats threat-detector
```

---

###  **4. Acessar a Aplicação**

Abra seu navegador em:
```
http://localhost:8080
```

Você verá a página inicial com duas opções:
-  **Análise de Logs**
-  **Verificação de Phishing**

---

###  **5. Parar e Remover Container**

```bash
# Parar container
docker stop threat-detector

# Remover container
docker rm threat-detector

# Parar e remover em um comando
docker rm -f threat-detector
```

---

### **6. Limpar Recursos**

```bash
# Remover imagem
docker rmi threat-detection-system:latest

# Remover todos os containers parados
docker container prune

# Remover imagens não utilizadas
docker image prune

# Limpeza completa (cuidado!)
docker system prune -a
```

---

###  **7. Troubleshooting**

#### Porta 8080 já está em uso
```bash
# Verificar o que está usando a porta
sudo lsof -i :8080

# Usar outra porta
docker run -p 8081:8080 threat-detection-system:latest
# Acesse em http://localhost:8081
```

#### Container não inicia
```bash
# Ver logs de erro
docker logs threat-detector

# Executar em modo interativo para debug
docker run -it --rm threat-detection-system:latest /bin/bash
```

#### Atualizar blacklists dentro do container
```bash
# Entrar no container em execução
docker exec -it threat-detector /bin/bash

# Atualizar OpenPhish
curl https://openphish.com/feed.txt > /app/data/blacklists/openphish_feed.txt

# Sair do container
exit
```

---

### **8. Build Otimizado para Produção**

```bash
# Build com cache otimizado
docker build \
  --no-cache \
  -t threat-detection-system:v1.0.0 \
  .

# Tag para registry (se usar Docker Hub)
docker tag threat-detection-system:v1.0.0 seuusuario/threat-detection-system:v1.0.0

# Push para registry
docker push seuusuario/threat-detection-system:v1.0.0
```

---

###  **9. Docker Compose (Opcional)**

Crie um arquivo `docker-compose.yml`:

```yaml
version: '3.8'

services:
  threat-detector:
    build: .
    container_name: threat-detection-system
    ports:
      - "8080:8080"
    volumes:
      - ./logs:/app/logs
      - ./reports:/app/reports
      - ./data:/app/data
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

**Comandos Docker Compose:**
```bash
# Iniciar
docker-compose up -d

# Ver logs
docker-compose logs -f

# Parar
docker-compose down

# Rebuild e iniciar
docker-compose up -d --build
```

---

###  **10. Verificação Rápida de Funcionamento**

```bash
# Testar se o servidor está respondendo
curl http://localhost:8080

# Testar endpoint de phishing (via CLI)
curl -X POST \
  -d "url=http://example.com" \
  http://localhost:8080/check-phishing

# Testar upload de log (com arquivo)
curl -X POST \
  -F "logfile=@/path/to/your/access.log" \
  http://localhost:8080/upload
```

---

## Uso

### 1. Interface Web (Modo Recomendado)

**Iniciar servidor local:**
```bash
python3 src/web_app.py
```

**Acesse:** http://localhost:8080

####  **Análise de Logs:**
1. Na página inicial, clique em **"Análise de Logs"**
2. Clique em "Choose File" e selecione seu arquivo `.log`
3. Clique em "Enviar e Processar"
4. Aguarde o processamento
5. Visualize o relatório HTML automaticamente

**Links disponíveis:**
- **Relatório HTML**: Visualização completa
- **Relatório JSON**: Dados estruturados
- **CSV Processado**: Dados limpos para análise

####  **Verificação de Phishing:**
1. Na página inicial, clique em **"Verificação de Phishing"**
2. Digite a URL a ser verificada (ex: `http://suspicious-site.com`)
3. Clique em " Verificar URL"
4. Aguarde a análise (pode demorar alguns segundos)
5. Visualize o resultado com:
   - **Indicador visual**  Verde (segura) ou  Vermelho (suspeita/maliciosa)
   - Tabela de características detectadas
   - Score de suspeita
   - Verificação em blacklists
   - Similaridade com marcas conhecidas
   - Detalhes de SSL, redirects e formulários
6. Acesse o **histórico** de verificações anteriores

---

### 2. Uso Programático (Python)

#### Análise de Logs

```python
from src.scanner import LogScanner

# Criar scanner
scanner = LogScanner()

# Coletar logs de arquivo
scanner.collect_logs_from_file('/var/log/apache2/access.log')

# Obter estatísticas
stats = scanner.get_statistics()
print(f"Total de requisições: {stats['total_requests']}")
print(f"IPs únicos: {stats['unique_ips']}")

# Obter dados como DataFrame
df = scanner.get_dataframe()
```

#### Pré-processamento

```python
from src.utils.preprocessor import DataPreprocessor

# Criar preprocessador
preprocessor = DataPreprocessor()
preprocessor.load_data(df)

# Executar limpeza completa (recomendado)
cleaned_data = preprocessor.clean_all()

# Ou executar etapas individuais
preprocessor.remove_missing_values()
preprocessor.remove_duplicates()
preprocessor.remove_outliers(columns=['bytes'])
preprocessor.generate_features()

# Obter resumo
summary = preprocessor.get_summary()
```

#### Geração de Relatórios

```python
from src.report_generator import ReportGenerator

# Criar gerador
generator = ReportGenerator(cleaned_data)

# Relatório no console
generator.print_console_report()

# Relatório HTML
generator.generate_html_report('reports/relatorio.html')

# Relatório JSON
generator.generate_json_report('reports/relatorio.json')

# Salvar CSV
cleaned_data.to_csv('reports/dados_limpos.csv', index=False)
```

#### Pipeline Completo (End-to-End)

```python
from src.scanner import LogScanner
from src.utils.preprocessor import DataPreprocessor
from src.report_generator import ReportGenerator

# 1. Coletar dados
scanner = LogScanner()
scanner.collect_logs_from_file('access.log')
df = scanner.get_dataframe()

# 2. Pré-processar
preprocessor = DataPreprocessor()
preprocessor.load_data(df)
cleaned_data = preprocessor.clean_all()

# 3. Gerar relatórios
generator = ReportGenerator(cleaned_data)
generator.print_console_report()
generator.generate_html_report('threat_report.html')
generator.generate_json_report('threat_report.json')

print(" Pipeline de logs completo executado!")
```

#### Verificação de Phishing

```python
from src.phishing.checker import check_url
import json

# Verificar uma URL
url_to_check = 'http://suspicious-paypal-login.com'
result = check_url(url_to_check)

# Exibir resultado
print(f"URL: {result['url']}")
print(f"Domínio: {result['domain']}")
print(f"Blacklisted: {result['blacklisted']}")
print(f"Score Suspeito: {result['suspicious_score']}")
print(f"Motivos: {result['reasons']}")

# Verificar se é segura
is_safe = not result['blacklisted'] and result['suspicious_score'] == 0
print(f"\n{' URL SEGURA' if is_safe else ' URL SUSPEITA/MALICIOSA'}")

# Exibir JSON completo
print(json.dumps(result, indent=2, ensure_ascii=False))
```

**Resultado exemplo:**
```
URL: http://suspicious-paypal-login.com
Domínio: suspicious-paypal-login.com
Blacklisted: False
Score Suspeito: 2
Motivos: ['suspicious_patterns']

 URL SUSPEITA/MALICIOSA
```

---

##  Testes

### Executar Todos os Testes

```bash
# Testes do Scanner
python3 src/tests/test_scanner.py

# Testes do Preprocessor
python3 src/tests/test_preprocessor.py
```

### Cobertura de Testes

**test_scanner.py** (6 testes):
-  Inicialização do scanner
-  Parse de linha válida
-  Parse de linha inválida
-  Parse de URL com parâmetros
-  Coleta de logs de texto
-  Geração de estatísticas

**test_preprocessor.py** (5 testes):
-  Carregamento de dados
-  Remoção de duplicatas
-  Categorização de status HTTP
-  Detecção de caracteres suspeitos
-  Geração de features

**Resultado esperado:**
```
Ran 6 tests in 0.011s
OK

Ran 5 tests in 0.047s
OK
```

---

##  Atributos Gerados (Features)

| Atributo | Tipo | Descrição |
|----------|------|-----------|
| `request_size` | int | Tamanho total da requisição (método + URL) |
| `path_length` | int | Comprimento do caminho da URL |
| `path_depth` | int | Número de níveis no caminho (/) |
| `has_extension` | bool | Indica se há extensão de arquivo |
| `status_category` | str | Categoria do status (success, redirect, client_error, server_error) |
| `has_params` | bool | Indica presença de parâmetros na URL |
| `params_length` | int | Tamanho dos parâmetros |
| `num_params` | int | Quantidade de parâmetros |
| `suspicious_chars` | int | Contagem de padrões suspeitos |

---

## 🚨 Padrões Suspeitos Detectados

| Padrão | Tipo de Ataque | Exemplo |
|--------|----------------|---------|
| `..` | Path Traversal | `/../../etc/passwd` |
| `<script>` | XSS | `?q=<script>alert(1)</script>` |
| `union`, `select`, `drop` | SQL Injection | `?id=1 UNION SELECT *` |
| `exec` | Command Injection | `?cmd=exec('ls')` |
| `%`, `\x` | Encoding Suspeito | `?q=%3Cscript%3E` |

---

## � Blacklists de Phishing

O sistema utiliza listas de phishing conhecidas para verificação de URLs:

### `data/blacklists/openphish_feed.txt`
- Feed do OpenPhish Community
- Lista de URLs confirmadas de phishing
- Formato: TXT (uma URL por linha)
- Atualização recomendada: diária
- Fonte: https://openphish.com/feed.txt

### `data/blacklists/phishtank_feed.txt`
- Banco de dados PhishTank
- URLs de phishing verificadas pela comunidade
- Formato: TXT (uma URL por linha, comentários com #)
- Atualização recomendada: semanal
- Fonte: https://www.phishtank.com/

** Nota:** As blacklists devem ser atualizadas regularmente para melhor proteção.

**Atualizar manualmente:**
```bash
# OpenPhish (atualização diária)
curl https://openphish.com/feed.txt > data/blacklists/openphish_feed.txt

# PhishTank (requer registro e processamento)
# 1. Baixe o feed: https://www.phishtank.com/developer_info.php
# 2. Extraia apenas as URLs para TXT
# 3. Salve em: data/blacklists/phishtank_feed.txt
```

**Formato dos arquivos TXT:**
```
# Comentários começam com #
http://malicious-url1.com
http://phishing-site2.com
http://fake-paypal3.com
```

---

## � Formato de Log Suportado

**Apache/Nginx Combined Log Format:**
```
IP - - [timestamp] "METHOD /path PROTOCOL" STATUS SIZE
```

**Exemplo:**
```
192.168.1.100 - - [28/Oct/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
```

**Campos extraídos:**
- `ip`: Endereço IP do cliente
- `timestamp`: Data e hora da requisição
- `method`: Método HTTP (GET, POST, etc.)
- `path`: Caminho da URL requisitada
- `protocol`: Protocolo (HTTP/1.1, HTTP/2, etc.)
- `status`: Código de status HTTP
- `bytes`: Tamanho da resposta em bytes

---

## 🔐 Segurança

-  Pipeline CI/CD com análise de segurança automática (Bandit)
-  Verificação de vulnerabilidades em dependências (Safety)
-  Workflow GitHub Actions para scans periódicos
-  Containerização com Docker para isolamento
-  Validação de inputs e sanitização
-  Verificação de URLs contra blacklists de phishing
-  Análise de certificados SSL
-  Detecção de padrões maliciosos em URLs

---

## 📚 Documentação Adicional

- [`docs/architecture.md`](docs/architecture.md) - Arquitetura detalhada do sistema
- [`.github/workflows/security_scan.yml`](.github/workflows/security_scan.yml) - Configuração do CI/CD

---

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

---

## 📜 Licença

Este projeto foi desenvolvido como parte de uma avaliação acadêmica.

---

## ✨ Autor

**João Palma** - [@joaoopalma](https://github.com/joaoopalma)

---

## 🙏 Agradecimentos

- Universidade Federal de São Paulo (UNIFESP)
- Professores e colegas do curso
- Comunidade Python e Flask

---

** Se este projeto foi útil para você, considere dar uma estrela!**
