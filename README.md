# ecac-login

Pacote Python para login automatizado no portal **eCAC** (Centro Virtual de Atendimento ao Contribuinte) da Receita Federal do Brasil.

Realiza o fluxo completo de autenticação com **certificado digital A1 (.pfx)**, resolve o **hCaptcha automaticamente via Google Gemini** e retorna uma instância de navegador já autenticada, pronta para ser usada em outras automações.

---

## Funcionalidades

- Login com certificado digital A1 (`.pfx`) via Patchright
- Resolução automática de hCaptcha usando visão computacional (Google Gemini 2.5 Flash)
- Detecção de sessão ativa — pula o login se o navegador já estiver autenticado
- Seleção automática de perfil de acesso (Procurador de Pessoa Jurídica via CNPJ)
- Tratamento de erros de CNPJ, procuração e acesso automatizado
- Log automático de erros com data e hora em arquivo `.txt` diário
- Compatível com Windows (Chrome via perfil persistente)

---

## Requisitos

- Python 3.10+
- Google Chrome instalado
- Certificado digital A1 (arquivo `.pfx`)
- Chave de API do Google Gemini

---

## Instalação

```bash
pip install git+https://github.com/tecnologia-save/LoginEcac-Python.git
```

Para atualizar para a versão mais recente:

```bash
pip install --upgrade git+https://github.com/tecnologia-save/LoginEcac-Python.git
```

---

## Configuração

Crie um arquivo `.env` na raiz do seu projeto com as seguintes variáveis:

```env
# Caminho completo para o arquivo .pfx do certificado digital
CERT_PFX_PATH=C:\Certificados\meu_certificado.pfx

# Senha do certificado .pfx
CERT_PFX_PASSPHRASE=senha_do_certificado

# Chave da API do Google Gemini (usada para resolver o hCaptcha)
GEMINI_API_KEY=sua_chave_gemini_aqui
```

> Consulte o arquivo `.env.example` como referência.

### Como obter a chave do Google Gemini

1. Acesse [Google AI Studio](https://aistudio.google.com/)
2. Clique em **Get API Key**
3. Crie ou selecione um projeto e copie a chave gerada

---

## Como usar

```python
from ecac_login import fazer_login

# Retorna (playwright, context, page) autenticados ou None em caso de falha
resultado = fazer_login(cnpj="12345678000195")

if resultado is None:
    print("Login falhou.")
else:
    p, context, page = resultado

    # Use o `page` para navegar no eCAC...
    page.goto("https://cav.receita.fazenda.gov.br/ecac/...")

    # Ao terminar, feche o navegador
    context.close()
    p.stop()
```

### Parâmetros de `fazer_login()`

| Parâmetro | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `cnpj` | `str` | Sim | CNPJ da empresa (14 dígitos, sem formatação) |
| `project_dir` | `Path \| str` | Não | Diretório do projeto. Usado para salvar o perfil do Chrome e screenshots de debug. Padrão: diretório de trabalho atual (`Path.cwd()`) |

### Retorno

- **Sucesso:** tupla `(p, context, page)` onde:
  - `p` — instância do Playwright
  - `context` — contexto persistente do navegador
  - `page` — página autenticada no eCAC, pronta para uso
- **Falha:** `None`

---

## Fluxo de autenticação

```
1. Abre o Chrome com perfil persistente
2. Navega para o eCAC
   ├── Sessão ativa detectada? → pula para o passo 6
   └── Sem sessão ativa:
       3. Clica em "Entrar com gov.br"
       4. Resolve hCaptcha (Google Gemini)
       5. Seleciona autenticação por certificado digital
6. Aguarda dashboard carregar (#btnPerfil)
7. Clica em "Alterar perfil de acesso"
8. Preenche o CNPJ e clica em "Alterar"
9. Retorna (p, context, page) autenticados
```

---

## Logs de erro

Os erros são salvos automaticamente em `logs/DD-MM-AAAA_automation.txt` no diretório do projeto chamador.

Exemplo de entrada no log:

```
[08/05/2026 14:23:11] ERRO: [CNPJ: 12345678000195] Não existe procuração eletrônica para o detentor
[08/05/2026 15:10:44] ERRO: Login: hCaptcha nao resolvido apos 3 tentativas (etapa gov.br).
```

### Erros tratados automaticamente

| Situação | Comportamento |
|---|---|
| CNPJ inválido ou incompleto | Registra no log e encerra |
| Sem procuração eletrônica para o CNPJ | Registra no log e encerra |
| Procuração eletrônica vencida/inválida | Registra no log e encerra |
| Acesso automatizado detectado | Tenta novamente até 5x, depois registra e encerra |
| hCaptcha não resolvido | Registra no log e encerra |
| Dashboard do eCAC não carregou | Registra no log e salva screenshot de debug |
| Redirecionamento falhou | Registra no log e salva screenshot de debug |

---

## Estrutura do pacote

```
ecac-login/
├── ecac_login/
│   ├── __init__.py          # Exporta fazer_login()
│   ├── login.py             # Fluxo principal de autenticação
│   ├── captcha_solver.py    # Resolução de hCaptcha via Google Gemini
│   └── log_manager.py       # Registro de erros em arquivo .txt
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
```

---

## Dependências

| Biblioteca | Uso |
|---|---|
| `patchright` | Automação do navegador com suporte a certificados digitais |
| `python-dotenv` | Carregamento das variáveis do `.env` |
| `google-generativeai` | API do Google Gemini para resolução do hCaptcha |

---

## Observações importantes

- O pacote utiliza um **perfil persistente do Chrome** salvo em `chrome_debug_profile/` no diretório do projeto. Isso mantém cookies e sessões entre execuções.
- O arquivo `.pfx` e o `.env` **nunca devem ser commitados** no repositório — adicione-os ao `.gitignore` do seu projeto.
- O pacote foi desenvolvido e testado em **Windows** com Google Chrome. Outros sistemas operacionais não foram validados.
- A chave do Gemini é utilizada apenas para resolver o hCaptcha — nenhum dado sensível é enviado à API.