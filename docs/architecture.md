# Arquitetura do Sistema de Detecção de Ameaças Cibernéticas

## Visão Geral

O sistema é composto por três módulos principais que trabalham em conjunto:

```
┌─────────────────────────────────────────────────────────────┐
│              SISTEMA DE DETECÇÃO DE AMEAÇAS                 │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│              │      │              │      │              │
│   SCANNER    │─────▶│ PREPROCESSOR │─────▶│   REPORT     │
│              │      │              │      │  GENERATOR   │
└──────────────┘      └──────────────┘      └──────────────┘
      │                     │                      │
      ▼                     ▼                      ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Logs de     │      │  Dados       │      │  Relatórios  │
│  Servidor    │      │  Limpos      │      │  HTML/JSON   │
└──────────────┘      └──────────────┘      └──────────────┘
```

## Componentes

### 1. Scanner (scanner.py)
**Responsabilidade:** Coleta de Logs

**Entrada:**
- Arquivo de log do servidor web (Apache/Nginx)
- Texto com logs

**Processamento:**
- Parse de logs usando regex
- Extração de IP, método HTTP, path, status, tamanho
- Identificação de parâmetros na URL
- Cálculo de tamanho da requisição

**Saída:**
- DataFrame pandas com logs estruturados
- Estatísticas básicas

### 2. Preprocessor (utils/preprocessor.py)
**Responsabilidade:** Limpeza e Enriquecimento de Dados

**Entrada:**
- DataFrame com logs brutos

**Processamento:**
- Remoção de valores ausentes
- Eliminação de duplicatas
- Remoção de outliers (Z-score)
- Geração de atributos:
  * path_length
  * path_depth
  * has_extension
  * status_category
  * has_params
  * params_length
  * suspicious_chars

**Saída:**
- DataFrame limpo e enriquecido

### 3. Report Generator (report_generator.py)
**Responsabilidade:** Geração de Relatórios

**Entrada:**
- DataFrame processado

**Processamento:**
- Cálculo de estatísticas
- Análise de segurança
- Identificação de padrões suspeitos
- Formatação de dados

**Saída:**
- Relatório HTML
- Relatório JSON
- Relatório console

## Fluxo de Dados

1. **Coleta**
   ```
   Arquivo de Log → Scanner → DataFrame Bruto
   ```

2. **Processamento**
   ```
   DataFrame Bruto → Preprocessor → DataFrame Limpo
   ```

3. **Análise e Relatório**
   ```
   DataFrame Limpo → Report Generator → Relatórios
   ```

## Tecnologias Utilizadas

- **Python 3.11+**: Linguagem principal
- **Pandas**: Manipulação de dados
- **NumPy**: Operações numéricas
- **Regex**: Parse de logs
- **Docker**: Containerização
- **GitHub Actions**: CI/CD

## Escalabilidade

O sistema é projetado para ser escalável:

- **Modular**: Cada componente pode ser usado independentemente
- **Extensível**: Fácil adicionar novos tipos de análise
- **Containerizado**: Pode ser deployed em qualquer ambiente
- **Stateless**: Não mantém estado entre execuções

## Segurança

- Validação de entrada em todos os módulos
- Tratamento de exceções robusto
- Análise automática de código (Bandit)
- Verificação de vulnerabilidades em dependências (Safety)
- CI/CD com scans de segurança

## Performance

Otimizações implementadas:

- Uso de pandas para operações vetorizadas
- Regex compilado para parse eficiente
- Lazy loading de dados
- Geração de relatórios sob demanda

## Próximas Melhorias (Conceitos B/A)

- Machine Learning para classificação automática
- Interface web interativa
- Alertas em tempo real
- Integração com SIEM
- Análise de comportamento de usuários
- Detecção de anomalias avançada
