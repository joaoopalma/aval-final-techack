# 🛡️ Sistema de Detecção de Ameaças Cibernéticas em Servidores Web

Sistema desenvolvido para identificar e classificar ameaças cibernéticas em servidores web através da análise de logs de acesso.

## 📋 Descrição

Este projeto implementa um sistema completo de detecção de ameaças que:
- ✅ Coleta logs detalhados de acesso ao servidor web
- ✅ Realiza pré-processamento e limpeza de dados
- ✅ Identifica padrões potencialmente suspeitos
- ✅ Gera relatórios detalhados de segurança

## 🏗️ Estrutura do Projeto

```
aval-final-techack/
├── src/
│   ├── scanner.py              # Módulo de coleta de logs
│   ├── report_generator.py     # Gerador de relatórios
│   ├── utils/
│   │   ├── __init__.py
│   │   └── preprocessor.py     # Pré-processamento de dados
│   ├── tests/                  # Testes unitários
│   └── requirements.txt        # Dependências Python
├── docs/
│   ├── architecture_diagram.png
│   └── flowchart.pdf
├── .github/
│   └── workflows/
│       └── security_scan.yml   # CI/CD para análise de segurança
├── Dockerfile                  # Containerização
└── README.md
```

## 🚀 Instalação

### Requisitos
- Python 3.11+
- pip

### Instalação Local

```bash
# Clone o repositório
git clone <url-do-repositorio>
cd aval-final-techack

# Instale as dependências
pip install -r src/requirements.txt
```

### Usando Docker

```bash
# Build da imagem
docker build -t threat-detection-system .

# Executar container com servidor web
docker run -p 8080:8080 threat-detection-system

# Acesse no navegador: http://localhost:8080
```

> 📖 **Guia Completo**: Veja [QUICK_START.md](QUICK_START.md) ou [DOCKER_GUIDE.md](DOCKER_GUIDE.md)

---

## 🌐 Servidor Web

O sistema inclui um servidor web para visualizar os relatórios:

```bash
# 1. Gere os relatórios
python3 demo.py

# 2. Inicie o servidor
python3 web_server.py

# 3. Acesse: http://localhost:8080
```

## 💻 Uso

### 1. Coleta de Dados

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
print(stats)

# Obter dados como DataFrame
df = scanner.get_dataframe()
```

**Para gerar logs de exemplo para testes:**
```bash
python3 generate_test_logs.py
python3 src/scanner.py sample_logs.txt
```

### 2. Pré-processamento

```python
from src.utils.preprocessor import DataPreprocessor

# Criar preprocessador
preprocessor = DataPreprocessor()

# Carregar dados do scanner
preprocessor.load_data(df)

# Executar limpeza completa
cleaned_data = preprocessor.clean_all()

# Ou executar etapas individuais
preprocessor.remove_missing_values()
preprocessor.remove_duplicates()
preprocessor.remove_outliers()
preprocessor.generate_features()
```

### 3. Geração de Relatórios

```python
from src.report_generator import ReportGenerator

# Criar gerador de relatórios
generator = ReportGenerator(cleaned_data)

# Relatório no console
generator.print_console_report()

# Relatório HTML
generator.generate_html_report('relatorio.html')

# Relatório JSON
generator.generate_json_report('relatorio.json')
```

### 4. Fluxo Completo

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
generator.generate_html_report()
generator.generate_json_report()
```

## 📊 Funcionalidades Implementadas

### ✅ Conceito C - Requisitos Básicos

#### Coleta de Dados Básica
- ✅ Captura de endereço IP
- ✅ Captura de requisições HTTP (método, path, protocolo)
- ✅ Captura de status de resposta
- ✅ Suporte para formato Apache/Nginx Combined Log
- ✅ Parse robusto com regex
- ✅ Processamento de arquivos de log reais

#### Pré-processamento de Dados Simples
- ✅ Remoção de valores ausentes
- ✅ Preenchimento de valores nulos
- ✅ Remoção de duplicatas
- ✅ Remoção de outliers (Z-score)
- ✅ Geração de atributos relevantes:
  - Tamanho da requisição (request_size)
  - Comprimento do caminho (path_length)
  - Profundidade do caminho (path_depth)
  - Número de parâmetros (num_params)
  - Comprimento dos parâmetros (params_length)
  - Detecção de caracteres suspeitos (suspicious_chars)
  - Categoria de status HTTP (status_category)

#### Geração de Relatórios
- ✅ Relatório resumido (console)
- ✅ Relatório de segurança
- ✅ Exportação em JSON
- ✅ Exportação em HTML com visualização web
- ✅ Estatísticas de requisições
- ✅ Top IPs e paths mais acessados
- ✅ Análise de padrões suspeitos

## 🔍 Atributos Gerados

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

## 📈 Padrões Suspeitos Detectados

O sistema identifica os seguintes padrões potencialmente maliciosos:

- `..` - Path Traversal
- `<script>` - XSS (Cross-Site Scripting)
- `union`, `select`, `drop` - SQL Injection
- `exec` - Command Injection
- Encoding suspeito (`%`, `\x`)

## 🧪 Testes

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

## 📝 Formato de Log Suportado

O sistema suporta o formato Apache/Nginx Combined Log:

```
IP - - [timestamp] "METHOD /path PROTOCOL" STATUS SIZE
```

Exemplo:
```
192.168.1.100 - - [28/Oct/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
```

## 🔒 Segurança

- Pipeline CI/CD com análise de segurança automática (Bandit)
- Verificação de vulnerabilidades em dependências (Safety)
- Workflow GitHub Actions para scans periódicos

## 📚 Documentação

Consulte a pasta `docs/` para:
- Diagrama de arquitetura
- Fluxogramas do sistema
- Documentação técnica adicional

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto foi desenvolvido para fins educacionais.

## 👨‍💻 Autor

Desenvolvido para a disciplina de Tecnologia e Hackeamento - 7º Semestre

---

**Status do Projeto:** ✅ Conceito C Implementado

- [x] Coleta de dados básica
- [x] Pré-processamento simples
- [x] Remoção de valores ausentes
- [x] Geração de atributos relevantes
- [x] Geração de relatórios