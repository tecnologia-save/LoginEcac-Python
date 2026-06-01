# ecac-login

Pacote Python para **login automatizado no portal eCAC** (Centro Virtual de Atendimento ao Contribuinte) da Receita Federal do Brasil.

Realiza o fluxo completo de autenticação com **certificado digital A1 (.pfx)**, resolve o **hCaptcha automaticamente via Google Gemini Vision** e retorna uma instância de navegador já autenticada, pronta para ser usada por outras automações.

---

## Sumário

1. [O que o pacote faz](#1-o-que-o-pacote-faz)
2. [Requisitos](#2-requisitos)
3. [Instalação](#3-instalação)
4. [Configuração](#4-configuração)
5. [Como usar](#5-como-usar)
6. [Fluxo de autenticação](#6-fluxo-de-autenticação)
7. [Tratamento de erros](#7-tratamento-de-erros)
8. [Logs](#8-logs)
9. [Estrutura do pacote](#9-estrutura-do-pacote)
10. [Dependências](#10-dependências)

---

## 1. O que o pacote faz

O `ecac-login` abstrai toda a complexidade de autenticação no eCAC, incluindo:

- **Abertura do Chrome** com certificado digital A1 acoplado (sem instalação manual no sistema)
- **Detecção de sessão ativa** — pula a autenticação se o navegador já estiver logado
- **Resolução automática do hCaptcha** no portal gov.br via Google Gemini Vision
- **Seleção de perfil de acesso** — preenche o CNPJ e seleciona Procurador de Pessoa Jurídica automaticamente
- **Configuração de download** — direciona PDFs para `C:\Users\<usuário>\Downloads\` e desativa o visualizador interno do Chrome
- **Suporte a múltiplos domínios** — certificado reconhecido em todos os domínios relevantes da Receita Federal (eCAC, gov.br, soluções, serviços, NF-e, etc.)
- **Log automático de erros** — registra falhas com data e hora em arquivo `.txt` diário

---

## 2. Requisitos

| Requisito | Versão mínima | Observação |
|-----------|--------------|------------|
| Python | 3.10+ | |
| Google Chrome | Qualquer versão recente | Obrigatório — o pacote usa um perfil persistente do Chrome |
| Certificado digital A1 | — | Arquivo `.pfx` com a senha correspondente |
| Google Gemini API Key | — | Para resolução automática do hCaptcha |
| Procuração eletrônica no eCAC | — | O certificado deve ter procuração cadastrada para o CNPJ informado |

**Sistema operacional:** Windows (desenvolvido e testado em Windows 10/11).

---

## 3. Instalação

```bash
pip install git+https://github.com/tecnologia-save/LoginEcac-Python.git
```

Para atualizar para a versão mais recente:

```bash
pip install --force-reinstall git+https://github.com/tecnologia-save/LoginEcac-Python.git
```

---

## 4. Configuração

### Variáveis de ambiente

Crie um arquivo `.env` na raiz do projeto que chama `fazer_login()`:

```env
# Chave da API do Google Gemini — usada para resolver o hCaptcha
GEMINI_API_KEY=sua_chave_gemini_aqui

# Caminho ou nome do arquivo .pfx do certificado digital
# Opção A: nome do arquivo (será resolvido em LoginEcac/Certificados/)
CERT_PFX_PATH=MeuCertificado.pfx
# Opção B: caminho absoluto
# CERT_PFX_PATH=C:\MeusCertificados\MeuCertificado.pfx

# Senha do certificado .pfx — opcional se configurada no senhas.json
CERT_PFX_PASSPHRASE=senha_do_certificado
```

> Consulte `.env.example` como referência.

### Configuração do certificado

O pacote resolve o certificado da seguinte forma:

1. Lê `CERT_PFX_PATH` do `.env`
2. Se for um **caminho relativo** (somente nome do arquivo), resolve em `LoginEcac/Certificados/<arquivo>.pfx`
3. Se for um **caminho absoluto**, usa diretamente

Para a senha (`CERT_PFX_PASSPHRASE`):

1. Lê do `.env` se preenchida
2. Se vazia, busca automaticamente em `LoginEcac/Certificados/senhas.json` pelo nome do arquivo

#### Exemplo de `senhas.json`

```json
{
  "MeuCertificado.pfx": "senha_do_certificado",
  "OutroEmpresa.pfx": "outra_senha"
}
```

> O arquivo `senhas.json` está no `.gitignore` — nunca é versionado.

### Como obter a chave do Google Gemini

1. Acesse [Google AI Studio](https://aistudio.google.com/)
2. Clique em **Get API Key**
3. Crie ou selecione um projeto e copie a chave gerada

---

## 5. Como usar

```python
from ecac_login import fazer_login, AcessoBloqueado, DispositivosMaximo
from pathlib import Path

try:
    resultado = fazer_login(
        cnpj="12345678000195",
        project_dir=Path(__file__).parent,  # pasta onde está o .env
    )
except AcessoBloqueado:
    print("Acesso bloqueado — tente novamente mais tarde.")
    resultado = None
except DispositivosMaximo:
    print("Número máximo de dispositivos conectados.")
    resultado = None

if resultado is None:
    print("Login não concluído.")
else:
    p, context, page = resultado

    # Use o `page` para navegar no eCAC autenticado
    page.goto("https://cav.receita.fazenda.gov.br/ecac/...")

    # Ao terminar, feche o navegador
    context.close()
    p.stop()
```

### Parâmetros de `fazer_login()`

| Parâmetro | Tipo | Obrigatório | Descrição |
|-----------|------|-------------|-----------|
| `cnpj` | `str` | Sim | CNPJ da empresa (14 dígitos, sem formatação) |
| `project_dir` | `Path \| str` | Não | Diretório do projeto — onde está o `.env` e onde serão salvos o perfil do Chrome e logs. Padrão: diretório de trabalho atual |
| `metrics` | `MetricasManager` | Não | Instância do gerenciador de métricas para registrar dados de captcha e login |

### Retorno de `fazer_login()`

| Caso | Retorno |
|------|---------|
| Sucesso | Tupla `(p, context, page)` — Playwright, contexto e página autenticada |
| Falha de login | `None` |
| Acesso bloqueado | Exceção `AcessoBloqueado` |
| Dispositivos máximos | Exceção `DispositivosMaximo` |

---

## 6. Fluxo de autenticação

```
1. Abre o Chrome com perfil persistente (chrome_debug_profile/)
   └── Certificado .pfx acoplado via client_certificates do Patchright
   └── Download automático configurado para C:\Users\<usuário>\Downloads\

2. Navega para o eCAC
   ├── Sessão ativa detectada? → pula para o passo 6
   └── Sem sessão:
       3. Clica em "Entrar com gov.br"
       4. Clica em "Usar certificado digital"
       5. Resolve o hCaptcha automaticamente (Google Gemini Vision)

6. Aguarda o dashboard do eCAC carregar
7. Clica em "Alterar perfil de acesso"
8. Preenche o CNPJ e seleciona Procurador de Pessoa Jurídica
9. Retorna (p, context, page) — navegador autenticado e pronto para uso
```

### Domínios cobertos pelo certificado

O certificado é configurado para ser reconhecido em todos os domínios relevantes:

- `cav.receita.fazenda.gov.br` — eCAC principal
- `sso.acesso.gov.br` / `acesso.gov.br` — autenticação gov.br
- `solucoes.receita.fazenda.gov.br` — soluções da Receita
- `servicos.receita.fazenda.gov.br` / `servicos.receitafederal.gov.br` — portal de serviços
- `restituicao.receita.fazenda.gov.br` — restituições
- `nfe.fazenda.gov.br` / `cte.fazenda.gov.br` — documentos fiscais eletrônicos
- `receitafederal.gov.br` e variantes

---

## 7. Tratamento de erros

| Situação | Comportamento |
|----------|--------------|
| `CERT_PFX_PATH` ausente no `.env` | Imprime aviso e retorna `None` |
| Senha do certificado não encontrada | Imprime aviso e retorna `None` |
| Arquivo `.pfx` não encontrado no caminho informado | Imprime aviso e retorna `None` |
| CNPJ inválido ou sem procuração eletrônica | Registra no log e retorna `None` |
| Procuração eletrônica vencida ou inválida | Registra no log e retorna `None` |
| Acesso automatizado detectado pelo portal | Lança `AcessoBloqueado` |
| Limite de dispositivos simultâneos atingido | Lança `DispositivosMaximo` |
| hCaptcha não resolvido após tentativas máximas | Registra no log e retorna `None` |
| Dashboard do eCAC não carregou | Registra no log e salva screenshot de debug |

---

## 8. Logs

Os erros são registrados automaticamente em `logs/DD-MM-AAAA_automation.txt` no `project_dir` informado.

### Exemplo de entradas no log

```
[01/06/2026 14:23:11] ERRO: [CNPJ: 12345678000195] Não existe procuração eletrônica para o detentor
[01/06/2026 15:10:44] ERRO: Login: hCaptcha nao resolvido apos 6 rodadas.
[01/06/2026 15:41:02] ERRO: [cert] Arquivo nao encontrado: C:\Certificados\cert.pfx
```

Screenshots de debug são salvos em `logs/` quando o dashboard não carrega ou o redirecionamento falha.

---

## 9. Estrutura do pacote

```
LoginEcac-Python/
├── ecac_login/
│   ├── __init__.py          # Exporta fazer_login, AcessoBloqueado, DispositivosMaximo
│   ├── login.py             # Fluxo principal de autenticação
│   ├── log_manager.py       # Registro de erros em arquivo .txt diário
│   └── Certificados/        # Pasta para armazenar os arquivos .pfx e senhas.json
├── pyproject.toml
├── .env.example
├── .gitignore               # Exclui .env, *.pfx, *.p12, senhas.json
└── README.md
```

---

## 10. Dependências

| Biblioteca | Uso |
|------------|-----|
| `patchright` | Automação do Chrome com suporte nativo a certificados digitais client-side |
| `python-dotenv` | Carregamento das variáveis do `.env` |
| `google-genai` | API Google Gemini Vision para resolução do hCaptcha |
| `resolvedor-captcha` | Módulo de resolução de hCaptcha (pacote interno Save) |

> O arquivo `.pfx`, o `.env` e o `senhas.json` **nunca devem ser versionados** — todos estão no `.gitignore`.
