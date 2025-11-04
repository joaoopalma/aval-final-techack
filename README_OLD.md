# Sistema de Detecção de Ameaças Cibernéticas em Servidores Web

Sistema desenvolvido para identificar e classificar ameaças cibernéticas em servidores web através da análise de logs de acesso.

## 📋 Descrição

Este projeto implementa um sistema completo de detecção de ameaças que:
- ✅ Coleta logs detalhados de acesso ao servidor web (formato Apache/Nginx Combined)
- ✅ Realiza pré-processamento e limpeza de dados
- ✅ Identifica padrões potencialmente suspeitos (SQL Injection, XSS, Path Traversal, etc.)
- ✅ Gera relatórios detalhados de segurança (HTML, JSON, CSV)
- ✅ Interface web para upload de logs e visualização de relatórios
- ✅ Containerização completa com Docker

## 📁 Estrutura Completa do Projeto

```
aval-final-techack/
├── src/                           # Código-fonte principal
│   ├── scanner.py                 # 🔍 Módulo de coleta e parsing de logs
│   ├── report_generator.py        # 📊 Gerador de relatórios (HTML/JSON)
│   ├── web_app.py                 # 🌐 Aplicação web Flask
│   ├── requirements.txt           # 📦 Dependências Python do projeto
│   ├── __init__.py               # Inicialização do módulo src
│   │
│   ├── utils/                     # Utilitários
│   │   ├── __init__.py
│   │   └── preprocessor.py        # 🧹 Limpeza e feature engineering
│   │
│   ├── tests/                     # Testes unitários
│   │   ├── __init__.py
│   │   ├── test_scanner.py        # ✅ Testes do scanner
│   │   └── test_preprocessor.py   # ✅ Testes do preprocessor
│   │
│   └── phishing/                  # Módulo adicional de phishing
│       └── checker.py             # Verificador de URLs phishing
│
├── docs/                          # Documentação
│   ├── architecture.md            # 📐 Descrição da arquitetura
│   ├── architecture_diagram.png.placeholder
│   └── flowchart.pdf.placeholder
│
├── data/                          # Dados auxiliares
│   ├── phishing_checks.json
│   └── blacklists/
│       ├── phishtank_online.csv
│       └── openphish_feed.txt
│
├── .github/                       # Configurações GitHub
│   └── workflows/
│       └── security_scan.yml      # 🔒 CI/CD para análise de segurança
│
├── logs/                          # Diretório para logs uploaded
├── reports/                       # Diretório para relatórios gerados
│
├── Dockerfile                     # 🐳 Containerização
├── requirements.txt               # Dependências gerais
├── .gitignore                    # Arquivos ignorados pelo Git
└── README.md                      # Este arquivo
```

---

## 📄 Descrição Detalhada dos Arquivos

### 🔍 `src/scanner.py`
**Módulo principal de coleta de logs**

Responsável por:
- Parsing de logs no formato Apache/Nginx Combined Log
- Extração de campos: IP, timestamp, método HTTP, URL, status, bytes
- Conversão para DataFrame pandas para análise
- Geração de estatísticas básicas (total de requisições, IPs únicos, distribuição de status codes)

**Classes principais:**
- `LogScanner`: Classe principal para coleta e parsing

**Métodos importantes:**
```python
parse_log_line(line)              # Parse de uma linha de log
collect_logs_from_file(filepath)  # Coleta de arquivo
collect_logs_from_text(text)      # Coleta de string
get_dataframe()                   # Retorna pandas DataFrame
get_statistics()                  # Retorna estatísticas básicas
```

**Uso:**
```python
scanner = LogScanner()
scanner.collect_logs_from_file('/var/log/apache2/access.log')
df = scanner.get_dataframe()
stats = scanner.get_statistics()
```

---

### 🧹 `src/utils/preprocessor.py`
**Módulo de pré-processamento e feature engineering**

Responsável por:
- Remoção de valores ausentes
- Remoção de duplicatas
- Detecção e remoção de outliers (Z-score)
- Geração de atributos (features) para análise de segurança

**Atributos gerados:**
- `request_size`: Tamanho total da requisição
- `path_length`: Comprimento do caminho da URL
- `path_depth`: Profundidade do caminho (contagem de `/`)
- `has_extension`: Booleano indicando presença de extensão
- `status_category`: Categorização do status HTTP (success, redirect, client_error, server_error)
- `has_params`: Booleano indicando parâmetros na URL
- `params_length`: Tamanho dos parâmetros
- `num_params`: Quantidade de parâmetros
- `suspicious_chars`: Contagem de caracteres suspeitos

**Padrões suspeitos detectados:**
- `..` → Path Traversal
- `<script>` → XSS (Cross-Site Scripting)
- `union`, `select`, `drop` → SQL Injection
- `exec` → Command Injection
- `%`, `\x` → Encoding suspeito

**Classes principais:**
- `DataPreprocessor`: Classe de pré-processamento

**Métodos importantes:**
```python
load_data(df)                 # Carrega DataFrame
remove_missing_values()       # Remove NaN
remove_duplicates()           # Remove duplicatas
remove_outliers(columns)      # Remove outliers por Z-score
generate_features()           # Gera todos os atributos
clean_all()                   # Pipeline completo
get_summary()                 # Resumo do processamento
```

---

### 📊 `src/report_generator.py`
**Gerador de relatórios de segurança**

Responsável por:
- Geração de relatórios de resumo
- Geração de relatórios de segurança
- Exportação em múltiplos formatos (HTML, JSON, CSV)
- Visualização de métricas e alertas

**Tipos de relatórios:**
1. **Relatório de Resumo**: Estatísticas gerais dos dados
2. **Relatório de Segurança**: Análise de ameaças e padrões suspeitos

**Classes principais:**
- `ReportGenerator`: Classe geradora de relatórios

**Métodos importantes:**
```python
generate_summary_report()       # Relatório de estatísticas
generate_security_report()      # Relatório de segurança
generate_html_report(filepath)  # Exporta HTML
generate_json_report(filepath)  # Exporta JSON
print_console_report()          # Imprime no console
```

**Formato do relatório HTML:**
- Design responsivo e moderno
- Métricas destacadas (total de requisições, IPs únicos, taxa de erro)
- Tabelas de distribuição de status codes
- Alertas de segurança destacados
- Gráficos e visualizações

---

### 🌐 `src/web_app.py`
**Aplicação web Flask para interface do usuário**

Responsável por:
- Servir interface web para upload de logs
- Processar logs uploadados automaticamente
- Gerar relatórios em tempo real
- Servir relatórios HTML, JSON e CSV

**Endpoints:**
- `GET /` → Página inicial (ou relatório se já gerado)
- `POST /upload` → Upload de arquivo de log
- `GET /report.html` → Relatório HTML
- `GET /report.json` → Relatório JSON
- `GET /processed.csv` → Dados processados CSV

**Portas:**
- Porta 8080 (configurada para compatibilidade com Docker)

**Fluxo de processamento:**
1. Usuário faz upload de arquivo `.log`
2. App salva em `logs/uploaded.log`
3. Scanner processa o arquivo
4. Preprocessor limpa e gera features
5. ReportGenerator cria relatórios
6. Arquivos salvos em `reports/`
7. Redirect para visualização do relatório HTML

---

### ✅ `src/tests/test_scanner.py`
**Testes unitários do módulo scanner**

Testes implementados:
- `test_scanner_initialization`: Inicialização correta
- `test_parse_valid_log_line`: Parse de linha válida
- `test_parse_invalid_log_line`: Tratamento de linha inválida
- `test_parse_log_with_params`: Parse de URL com parâmetros
- `test_collect_logs_from_text`: Coleta de logs em string
- `test_get_statistics`: Geração de estatísticas

**Executar:**
```bash
python3 src/tests/test_scanner.py
```

---

### ✅ `src/tests/test_preprocessor.py`
**Testes unitários do módulo preprocessor**

Testes implementados:
- `test_load_data`: Carregamento de DataFrame
- `test_remove_duplicates`: Remoção de duplicatas
- `test_categorize_status`: Categorização de status HTTP
- `test_detect_suspicious_chars`: Detecção de caracteres suspeitos
- `test_generate_features`: Geração de features

**Executar:**
```bash
python3 src/tests/test_preprocessor.py
```

---

### 📦 `src/requirements.txt`
**Dependências Python do projeto**

```
pandas>=2.0.0    # Manipulação de dados
numpy>=1.24.0    # Computação numérica
flask>=2.0.0     # Framework web
```

---

### 🐳 `Dockerfile`
**Containerização da aplicação**

**Características:**
- Baseado em `python:3.11-slim`
- Instala dependências de `src/requirements.txt`
- Copia código-fonte para `/app/src/`
- Cria diretórios `logs/` e `reports/`
- Define `PYTHONPATH=/app` para imports corretos
- Expõe porta 8080
- Executa `python3 src/web_app.py`

**Build e execução:**
```bash
docker build -t threat-detection-system .
docker run -p 8080:8080 threat-detection-system
```

Acesse: http://localhost:8080

---

### 🔒 `.github/workflows/security_scan.yml`
**Pipeline CI/CD para análise de segurança**

**Ferramentas configuradas:**
- **Bandit**: Análise de segurança em código Python
- **Safety**: Verificação de vulnerabilidades em dependências

**Triggers:**
- Push para branch `main`
- Pull requests
- Agendamento semanal

---

### 📐 `docs/architecture.md`
**Documentação da arquitetura do sistema**

Descreve:
- Visão geral da arquitetura
- Fluxo de dados
- Componentes principais
- Decisões de design

---

## 🎯 Estrutura de Diretórios de Execução

### `logs/`
Diretório para armazenar logs uploadados via interface web.
- `uploaded.log`: Último arquivo de log processado

### `reports/`
Diretório para relatórios gerados.
- `threat_report.html`: Relatório visual completo
- `threat_report.json`: Dados estruturados em JSON
- `processed_logs.csv`: Dados limpos e com features

---

---

## ⚙️ Instalação

### Requisitos
- Python 3.11+
- pip
- Docker (opcional, para containerização)

### 📥 Instalação Local

```bash
# Clone o repositório
git clone https://github.com/joaoopalma/aval-final-techack.git
cd aval-final-techack

# Instale as dependências
pip install -r src/requirements.txt
```

### 🐳 Usando Docker (Recomendado)

```bash
# Build da imagem
docker build -t threat-detection-system .

# Executar container com servidor web
docker run -p 8080:8080 threat-detection-system

# Acesse no navegador: http://localhost:8080
```

---

## 🚀 Uso

### 1️⃣ Interface Web (Modo Recomendado)

**Iniciar servidor local:**
```bash
python3 src/web_app.py
```

**Acesse:** http://localhost:8080

**Fluxo:**
1. Acesse a página inicial
2. Clique em "Choose File" e selecione seu arquivo `.log`
3. Clique em "Enviar e Processar"
4. Aguarde o processamento
5. Visualize o relatório HTML automaticamente
6. Links disponíveis:
   - **Relatório HTML**: Visualização completa
   - **Relatório JSON**: Dados estruturados
   - **CSV Processado**: Dados limpos para análise

---

### 2️⃣ Uso Programático (Python)

#### Coleta de Logs

### Usando Docker

```bash
# Build da imagem
docker build -t threat-detection-system .

# Executar container com servidor web
docker run -p 8080:8080 threat-detection-system

# Acesse no navegador: http://localhost:8080
```
---

---

### 2️⃣ Uso Programático (Python)

#### Coleta de Logs

```python
from src.scanner import LogScanner

# Criar scanner
scanner = LogScanner()

# Coletar logs de arquivo real do servidor
scanner.collect_logs_from_file('/var/log/apache2/access.log')

# Ou de qualquer arquivo de log
scanner.collect_logs_from_file('path/to/your/logs.txt')

# Obter estatísticas
stats = scanner.get_statistics()
print(f"Total de requisições: {stats['total_requests']}")
print(f"IPs únicos: {stats['unique_ips']}")
print(f"Distribuição de status: {stats['status_codes']}")

# Obter dados como DataFrame
df = scanner.get_dataframe()
print(df.head())
```

#### Pré-processamento

## Uso

### 1. Coleta de Dados

#### Pré-processamento

```python
from src.utils.preprocessor import DataPreprocessor

# Criar preprocessador
preprocessor = DataPreprocessor()

# Carregar dados do scanner
preprocessor.load_data(df)

# Executar limpeza completa (recomendado)
cleaned_data = preprocessor.clean_all()

# Ou executar etapas individuais
preprocessor.remove_missing_values()
preprocessor.remove_duplicates()
preprocessor.remove_outliers(columns=['bytes'])
preprocessor.generate_features()

# Obter resumo do processamento
summary = preprocessor.get_summary()
print(summary)
```

**Opções do clean_all():**
- Remove valores ausentes
- Remove duplicatas
- Remove outliers (Z-score > 3)
- Gera todas as features de segurança

#### Geração de Relatórios

#### Geração de Relatórios

```python
from src.report_generator import ReportGenerator

# Criar gerador de relatórios
generator = ReportGenerator(cleaned_data)

# Relatório no console
generator.print_console_report()

# Relatório HTML (completo e visual)
generator.generate_html_report('reports/relatorio.html')

# Relatório JSON (dados estruturados)
generator.generate_json_report('reports/relatorio.json')

# Salvar dados processados
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

print("✅ Pipeline completo executado com sucesso!")
```

---

## 🧪 Testes

### Executar Todos os Testes

```bash
# Testes do Scanner
python3 src/tests/test_scanner.py

# Testes do Preprocessor
python3 src/tests/test_preprocessor.py
```

### Cobertura de Testes

**test_scanner.py:**
- ✅ Inicialização do scanner
- ✅ Parse de linha válida
- ✅ Parse de linha inválida
- ✅ Parse de URL com parâmetros
- ✅ Coleta de logs de texto
- ✅ Geração de estatísticas

**test_preprocessor.py:**
- ✅ Carregamento de dados
- ✅ Remoção de duplicatas
- ✅ Categorização de status HTTP
- ✅ Detecção de caracteres suspeitos
- ✅ Geração de features

**Resultado esperado:**
```
Ran 6 tests in 0.011s
OK

Ran 5 tests in 0.047s
OK
```

---

---

## 📊 Atributos Gerados (Features)

O sistema gera automaticamente os seguintes atributos para análise:

| Atributo | Descrição |
|----------|-----------|
| `request_size` | Tamanho total da requisição (método + URL) |
| `path_length` | Comprimento do caminho da URL |
| `path_depth` | Número de níveis no caminho (/) |
| `has_extension` | Indica se há extensão de arquivo |
| `status_category` | Categoria do status (success, error, etc) |
| `has_params` | Indica presença de parâmetros na URL |
| `params_length` | Tamanho dos parâmetros |
| `num_params` | Quantidade de parâmetros |
| `suspicious_chars` | Contagem de padrões suspeitos |

## Padrões Suspeitos Detectados

O sistema identifica os seguintes padrões potencialmente maliciosos:

- `..` - Path Traversal
- `<script>` - XSS (Cross-Site Scripting)
- `union`, `select`, `drop` - SQL Injection
- `exec` - Command Injection
- Encoding suspeito (`%`, `\x`)

## Testes

```bash
# Gerar logs de exemplo para teste
python3 generate_test_logs.py

# Executar scanner com arquivo de log
python3 src/scanner.py sample_logs.txt

# Executar preprocessor em modo demo
python3 src/utils/preprocessor.py

# Executar gerador de relatórios em modo demo
python3 src/report_generator.py

# Executar testes unitários
python3 src/tests/test_scanner.py
python3 src/tests/test_preprocessor.py

# Executar demonstração completa do sistema
python3 demo.py
```

## Formato de Log Suportado

O sistema suporta o formato Apache/Nginx Combined Log:

```
IP - - [timestamp] "METHOD /path PROTOCOL" STATUS SIZE
```

Exemplo:
```
192.168.1.100 - - [28/Oct/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
```

## Segurança

- Pipeline CI/CD com análise de segurança automática (Bandit)
- Verificação de vulnerabilidades em dependências (Safety)
- Workflow GitHub Actions para scans periódicos
