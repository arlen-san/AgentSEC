# AgentSEC

> **Agente de Segurança com IA para Operações SOC (Security Operations Center)**
> 
> [![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
> [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
> [![Pydantic](https://img.shields.io/badge/Pydantic-v2-orange.svg)](https://docs.pydantic.dev/)
> [![Google GenAI](https://img.shields.io/badge/SDK-Google%20GenAI-blueviolet.svg)](https://cloud.google.com/vertex-ai)

O **AgentSEC** é um assistente autônomo baseado em inteligência artificial projetado para apoiar analistas de SOC em triagem de incidentes, correlação de dados de segurança, consulta a inteligência de ameaças (CTI) e enriquecimento de alertas.

---

## 🎯 O que é o AgentSEC?

O AgentSEC atua como um analista de segurança N1/N2 automatizado, conectado a ferramentas corporativas como Microsoft Defender for Endpoint/Identity, feeds de Threat Intelligence (QuimeraX CTI, NVD/CVE) e bases de conhecimento de segurança. Ele permite interagir via CLI em linguagem natural para analisar incidentes, investigar máquinas e usuários comprometidos, correlacionar CVEs e gerar recomendações táticas de contenção e mitigação.

---

## 🚀 Funcionalidades (Fase 1)

- **Triagem Automatizada de Alertas**: Coleta e sumarização de incidentes do Microsoft Defender.
- **Enriquecimento de Ameaças (CTI)**: Consulta automatizada a bases de IoCs e CVEs (NVD e QuimeraX).
- **Interface Conversacional em Linha de Comando (CLI)**: Chat interativo com formatação rica via Rich.
- **Suporte a Mock Data**: Execução completa local sem necessidade de credenciais de produção para testes e desenvolvimento.
- **Arquitetura Baseada em Protocolos**: Conectores flexíveis e desacoplados utilizando `typing.Protocol`.
- **Validação Estrita de Dados**: Modelos de dados fortemente tipados com Pydantic v2.

---

## 🏗️ Visão Geral da Arquitetura

A arquitetura do AgentSEC é modular e organizada em camadas:

1. **CLI & Interface (Rich / Console)**:
   Recebe comandos e perguntas do analista em linguagem natural (PT-BR), renderizando respostas estruturadas, tabelas e alertas com formatação visual avançada.

2. **Núcleo do Agente (Agent Core)**:
   Gerencia o loop de raciocínio, ferramentas (tool calling) e orquestração do LLM usando a SDK oficial `google-genai`.

3. **Workflows de Operação SOC**:
   Encapsulam fluxos de análise padrão, como triagem de alertas, investigação de hosts comprometidos, correlação de vulnerabilidades e relatórios de plantão.

4. **Camada de Conectores (Connectors Layer)**:
   Implementada com o padrão `typing.Protocol`, permitindo alternar de forma transparente entre implementações reais e mocks:
   - **Microsoft Security**: Conexão à Graph API / Defender APIs para alertas e incidentes.
   - **CTI & Threat Intel**: Conectores para QuimeraX e APIs de vulnerabilidades (NVD/CVE).
   - **Mock Connectors**: Simulação local baseada em arquivos JSON para testes offline.

5. **Camada de Modelos e Configuração (Models & Config)**:
   Esquemas de dados em Pydantic v2 e carregamento de configurações de ambiente (`.env`).

---

## ⚡ Início Rápido

### Pré-requisitos

- Python 3.12 ou superior
- Pip ou uv instalado

### 1. Clonar o repositório

```bash
git clone https://github.com/arlensan/AgentSEC.git
cd AgentSEC
```

### 2. Criar e ativar ambiente virtual

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependências

```bash
pip install -e ".[dev]"
```

### 4. Configurar variáveis de ambiente

Copie o arquivo de exemplo e preencha sua chave do Google Gemini:

```bash
cp .env.example .env
```

Edite o arquivo `.env`:

```ini
USE_MOCK_DATA=true
LLM_PROVIDER=gemini
LLM_MODEL=gemini-2.5-flash
GEMINI_API_KEY=sua_chave_aqui
```

### 5. Executar o AgentSEC

```bash
agentsec
# ou
python -m agentsec.main
```

---

## 💻 Exemplos de Uso

Ao iniciar o CLI, você pode interagir com o agente em linguagem natural:

```
[AgentSEC] SOC AI Assistant inicializado.
Modo de dados: MOCK (data/mock/)

agentsec> Liste os alertas críticos abertos nas últimas 24 horas.

╭─────────────────────────── Alertas Críticos Encontrados ───────────────────────────╮
│ ID       │ Título                             │ Severidade │ Host        │ Status │
├──────────┼────────────────────────────────────┼────────────┼─────────────┼────────┤
│ ALT-1042 │ Suspicious PowerShell Execution    │ High       │ srv-db-01   │ Active │
│ ALT-1045 │ Mimikatz Memory Pattern Detected   │ Critical   │ wks-fin-04  │ Active │
╰──────────┴────────────────────────────────────┴────────────┴─────────────┴────────╯

agentsec> O que sabemos sobre o host wks-fin-04 e a vulnerabilidade associada?

[AgentSEC] Analisando o host 'wks-fin-04'...
- Usuário logado: financeiro\\maria.silva
- Alerta: Mimikatz Memory Pattern Detected (ALT-1045)
- CVEs pendentes no host: CVE-2024-21413 (CVSS 9.8)
- Recomendação imediata: Isolar o host 'wks-fin-04' da rede e resetar credenciais do usuário.
```

---

## 📂 Estrutura do Projeto

```
AgentSEC/
├── pyproject.toml              # Metadados e dependências do projeto
├── .env.example                # Template de configuração de ambiente
├── .gitignore                  # Arquivos ignorados pelo Git
├── README.md                   # Documentação do projeto
├── data/
│   └── mock/                   # Arquivos JSON para simulação de dados SOC
│       └── .gitkeep
├── src/
│   └── agentsec/
│       ├── __init__.py
│       ├── main.py             # Ponto de entrada da aplicação CLI
│       ├── agent/              # Raciocínio, prompts e tool calling do agente
│       ├── config/             # Gerenciamento de configurações e variáveis de ambiente
│       ├── connectors/         # Protocolos e integrações de APIs
│       │   ├── cti/            # Conectores de Threat Intelligence (QuimeraX, NVD)
│       │   ├── microsoft/      # Conector Microsoft Defender / Graph API
│       │   └── mock/           # Conectores mock para ambiente de testes
│       ├── models/             # Modelos de dados Pydantic v2
│       └── workflows/          # Fluxos de investigação e triagem do SOC
└── tests/                      # Testes automatizados com pytest
```

---

## 🗺️ Roadmap

- [x] **Fase 1: Fundação & Mocks** — Estrutura base, modelos Pydantic, CLI interativo, conectores mock e integração com Gemini.
- [ ] **Fase 2: Conectores Reais** — Microsoft Defender API (OAuth2) e feeds de Threat Intel (NVD / QuimeraX).
- [ ] **Fase 3: Workflows Autônomos de SOC** — Playbooks de triagem automatizada, investigação e geração de relatórios.
- [ ] **Fase 4: Memória & Contexto de Investigação** — Persistência de sessões de investigação e grafo de entidades.
- [ ] **Fase 5: Ações de Resposta e Contenção** — Execução assistida de ações de contenção com confirmação humana (Human-in-the-loop).
- [ ] **Fase 6: Dashboard & API REST** — Interface web e integração via webhooks com SIEM/SOAR.

---

## 📄 Licença

Este projeto está sob a licença [MIT](LICENSE).
