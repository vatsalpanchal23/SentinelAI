"""
AI client abstraction.

Swaps between a local Ollama model and cloud providers (Gemini/DeepSeek/Kimi)
based on config.AI_PROVIDER, so the rest of the app never calls a provider SDK directly.
"""

import requests
from flask import current_app


def ask(prompt: str, system: str | None = None) -> str:
    provider = current_app.config.get("AI_PROVIDER", "ollama")

    if provider == "ollama":
        return _ask_ollama(prompt, system)

    raise NotImplementedError(f"AI provider '{provider}' not wired up yet.")


def _ask_ollama(prompt: str, system: str | None) -> str:
    host = current_app.config["OLLAMA_HOST"]
    model = current_app.config["OLLAMA_MODEL"]

    payload = {"model": model, "prompt": prompt, "stream": False}
    if system:
        payload["system"] = system

    resp = requests.post(f"{host}/api/generate", json=payload, timeout=120)
    resp.raise_for_status()
    return resp.json().get("response", "")
