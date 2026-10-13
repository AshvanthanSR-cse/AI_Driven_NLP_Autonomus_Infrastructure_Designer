"""Client for the local LM Studio server (OpenAI-compatible). The LLM never sees credentials."""
import re

from openai import OpenAI

from core.config import settings

_THINK_RE = re.compile(r"<think>.*?</think>", re.S)

_client: OpenAI | None = None


def client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(base_url=settings.llm_base_url, api_key="lm-studio", timeout=settings.llm_timeout_s)
    return _client


def strip_think(text: str | None) -> str:
    if not text:
        return ""
    text = _THINK_RE.sub("", text)
    if "<think>" in text:
        text = text.split("<think>", 1)[0]
    return text.strip()


def chat(messages: list[dict], tools: list[dict] | None = None):
    """One chat completion. Returns the assistant message object (content already de-thought)."""
    kwargs = dict(model=settings.llm_model, messages=messages, temperature=settings.llm_temperature)
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    resp = client().chat.completions.create(**kwargs)
    msg = resp.choices[0].message
    msg.content = strip_think(msg.content)
    return msg


def ping() -> tuple[bool, str]:
    try:
        ids = [m.id for m in client().models.list().data]
        if settings.llm_model not in ids:
            return False, f"LM Studio is up but model '{settings.llm_model}' is not loaded"
        return True, f"LM Studio OK ({settings.llm_model})"
    except Exception as e:
        return False, f"LM Studio not reachable at {settings.llm_base_url} ({type(e).__name__})"
