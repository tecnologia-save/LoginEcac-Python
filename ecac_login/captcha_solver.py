"""Resolve hCaptcha via Gemini (vision) — versao Playwright."""
import json
import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import types
from patchright.sync_api import Page, TimeoutError as PWTimeoutError

from .log_manager import registrar_erro


CHALLENGE_IFRAME_SELECTOR = "iframe[src*='hcaptcha.com'][src*='frame=challenge']"
CLICK_SELECTOR  = ".task"
SUBMIT_SELECTOR = ".button-submit"

GEMINI_MODEL = "gemini-2.5-flash"

CLASSIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "task_summary": {
            "type": "string",
            "description": "Criterio identificado: texto do enunciado ou categoria da imagem de referencia.",
        },
        "matching_tiles": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "Indices 0-8 dos tiles que atendem ao criterio.",
        },
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
        },
    },
    "required": ["task_summary", "matching_tiles", "confidence"],
}

PROMPT = (
    "Esta imagem e um desafio hCaptcha completo.\n\n"
    "ESTRUTURA:\n"
    "- TOPO: faixa colorida com o ENUNCIADO em texto. Pode haver uma IMAGEM DE REFERENCIA "
    "pequena ao lado — se houver, ela define a CATEGORIA do objeto a selecionar.\n"
    "- GRADE 3x3: logo abaixo do topo, 9 imagens numeradas assim:\n"
    "  ┌───┬───┬───┐\n"
    "  │ 0 │ 1 │ 2 │  (linha superior)\n"
    "  ├───┼───┼───┤\n"
    "  │ 3 │ 4 │ 5 │  (linha do meio)\n"
    "  ├───┼───┼───┤\n"
    "  │ 6 │ 7 │ 8 │  (linha inferior)\n"
    "  └───┴───┴───┘\n\n"
    "COMO RESOLVER:\n"
    "1. Leia o enunciado. Se houver imagem de referencia ao lado, identifique a categoria "
    "do objeto mostrado (ex.: aviao, cachorro, bicicleta).\n"
    "2. Para cada tile (0 a 8), verifique se o objeto principal pertence ao criterio.\n"
    "3. Seja INCLUSIVO: qualquer angulo, cor, estilo, recorte parcial — inclua o tile "
    "se o objeto for da categoria. Em caso de duvida razoavel, INCLUA.\n\n"
    "Retorne:\n"
    "  task_summary: criterio em uma linha\n"
    "  matching_tiles: lista de indices (0-8) dos tiles que atendem ao criterio\n"
    "  confidence: 'high' | 'medium' | 'low'"
)

_gemini_client: genai.Client | None = None


def _get_client() -> genai.Client:
    global _gemini_client
    if _gemini_client is None:
        load_dotenv(override=True)
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key or api_key.startswith("cole-"):
            raise RuntimeError("GEMINI_API_KEY nao configurada no .env.")
        _gemini_client = genai.Client(api_key=api_key)
    return _gemini_client


def _classify_with_gemini(png: bytes) -> dict:
    response = _get_client().models.generate_content(
        model=GEMINI_MODEL,
        contents=[
            types.Part.from_bytes(data=png, mime_type="image/png"),
            PROMPT,
        ],
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=CLASSIFICATION_SCHEMA,
        ),
    )
    return json.loads(response.text)


def _challenge_visible(page: Page) -> bool:
    try:
        return page.locator(CHALLENGE_IFRAME_SELECTOR).first.is_visible(timeout=300)
    except Exception:
        return False


def _wait_for_tiles(page: Page, timeout_ms: int = 6_000) -> bool:
    cf = page.frame_locator(CHALLENGE_IFRAME_SELECTOR)
    try:
        cf.locator(CLICK_SELECTOR).nth(8).wait_for(state="visible", timeout=timeout_ms)
    except Exception:
        print("[captcha] Timeout aguardando tiles.")
        return False

    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            ready = cf.evaluate(
                """() => {
                    const tiles = document.querySelectorAll('.task-image');
                    if (tiles.length < 9) return false;
                    for (const t of tiles) {
                        const bg = window.getComputedStyle(t).backgroundImage;
                        const img = t.querySelector('img');
                        if (!(bg && bg !== 'none' && bg.includes('url(')) &&
                            !(img && img.complete && img.naturalWidth > 0)) return false;
                    }
                    return true;
                }"""
            )
            if ready:
                return True
        except Exception:
            pass
        page.wait_for_timeout(80)

    return True


def _wait_for_resolve(page: Page, timeout_ms: int = 3_000) -> bool:
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        if not _challenge_visible(page):
            return True
        page.wait_for_timeout(100)
    return False


def solve_hcaptcha(page: Page, max_rounds: int = 6) -> bool:
    """Verifica se ha hCaptcha na tela e resolve via Gemini. Retorna True se resolvido ou ausente."""
    try:
        page.locator(CHALLENGE_IFRAME_SELECTOR).first.wait_for(state="visible", timeout=12_000)
    except PWTimeoutError:
        print("[captcha] Nenhum desafio hCaptcha detectado.")
        return True

    for round_idx in range(max_rounds):
        if not _challenge_visible(page):
            print("[captcha] Desafio resolvido.")
            return True

        print(f"[captcha] rodada {round_idx + 1}: aguardando imagens...")
        _wait_for_tiles(page)

        result = None
        last_err = None
        iframe_loc = page.locator(CHALLENGE_IFRAME_SELECTOR).first

        for attempt in range(1, 6):
            try:
                png = iframe_loc.screenshot()
            except Exception as e:
                last_err = e
                print(f"[captcha] tentativa {attempt}/5 — erro no screenshot: {e}")
                time.sleep(1)
                continue

            try:
                result = _classify_with_gemini(png)
            except Exception as e:
                last_err = e
                tipo = type(e).__name__
                detalhe = str(e)
                print(f"[captcha] tentativa {attempt}/5 — erro Gemini ({tipo}): {detalhe[:300]}")
                registrar_erro(f"Captcha: erro Gemini na tentativa {attempt}/5 — {tipo}: {detalhe}")
                time.sleep(1)
                continue

            if result.get("confidence") == "low":
                print(f"[captcha] tentativa {attempt}/5 — confianca baixa, repetindo.")
                result = None
                time.sleep(1)
                continue

            break

        if result is None:
            tipo = type(last_err).__name__ if last_err else "desconhecido"
            detalhe = str(last_err) if last_err else "sem detalhes"
            msg = f"Captcha: todas as tentativas falharam na rodada {round_idx + 1} — {tipo}: {detalhe}"
            print(f"[captcha] Nao foi possivel classificar. Ultimo erro: {last_err}")
            registrar_erro(msg)
            input("Resolva manualmente e pressione ENTER para continuar...")
            return True

        valid_tiles = sorted({i for i in result.get("matching_tiles", []) if 0 <= i <= 8})
        print(
            f"[captcha] rodada {round_idx + 1}: '{result.get('task_summary')}' "
            f"({result.get('confidence')}) -> tiles {valid_tiles}"
        )

        cf = page.frame_locator(CHALLENGE_IFRAME_SELECTOR)
        tiles = cf.locator(CLICK_SELECTOR)
        for idx in valid_tiles:
            try:
                tiles.nth(idx).click(delay=30)
                time.sleep(0.05)
            except Exception as e:
                print(f"[captcha] Erro clicando tile {idx}: {e}")

        time.sleep(0.1)

        try:
            cf.locator(SUBMIT_SELECTOR).first.click(timeout=3_000)
        except Exception:
            print("[captcha] Botao de submit nao encontrado — pode ser auto-submit.")

        if _wait_for_resolve(page):
            print("[captcha] Captcha resolvido com sucesso.")
            return True

    print("[captcha] Limite de rodadas atingido.")
    return False