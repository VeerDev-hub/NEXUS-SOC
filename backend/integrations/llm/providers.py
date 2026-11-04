"""Catalogue of supported LLM providers.

Every provider is reached through an OpenAI-compatible Chat Completions endpoint,
so a single client (langchain-openai ``ChatOpenAI``) serves all of them:

* DeepSeek  - https://api.deepseek.com
* OpenAI    - https://api.openai.com/v1
* Google    - Gemini's OpenAI-compatible endpoint
* Any other OpenAI-compatible gateway (Ollama, vLLM, OpenRouter, ...)

``structured_method`` tells LangChain how to coerce structured output. DeepSeek
and Gemini do not support OpenAI's ``json_schema`` response format reliably, so
they use function calling instead.
"""

import os
from dataclasses import dataclass

PROVIDER_DEEPSEEK = "deepseek"
PROVIDER_OPENAI = "openai"
PROVIDER_GEMINI = "gemini"
PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
PROVIDER_OLLAMA = "ollama"


@dataclass(frozen=True)
class ProviderSpec:
    key: str
    label: str
    default_base_url: str
    default_model: str
    structured_method: str
    api_key_env: str


PROVIDERS = {
    PROVIDER_DEEPSEEK: ProviderSpec(
        key=PROVIDER_DEEPSEEK,
        label="DeepSeek",
        default_base_url="https://api.deepseek.com",
        default_model="deepseek-chat",
        structured_method="function_calling",
        api_key_env="DEEPSEEK_API_KEY",
    ),
    PROVIDER_OPENAI: ProviderSpec(
        key=PROVIDER_OPENAI,
        label="OpenAI",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-4.1-mini",
        structured_method="json_schema",
        api_key_env="OPENAI_API_KEY",
    ),
    PROVIDER_GEMINI: ProviderSpec(
        key=PROVIDER_GEMINI,
        label="Google Gemini",
        default_base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        default_model="gemini-2.5-flash",
        structured_method="function_calling",
        api_key_env="GEMINI_API_KEY",
    ),
    # Ollama honours OpenAI's json_schema response format with grammar-constrained
    # decoding; its tool calling on small local models drops required fields.
    PROVIDER_OLLAMA: ProviderSpec(
        key=PROVIDER_OLLAMA,
        label="Ollama (local)",
        default_base_url="http://localhost:11434/v1",
        default_model="qwen2.5:7b",
        structured_method="json_schema",
        api_key_env="",
    ),
    PROVIDER_OPENAI_COMPATIBLE: ProviderSpec(
        key=PROVIDER_OPENAI_COMPATIBLE,
        label="OpenAI-compatible",
        default_base_url="http://localhost:11434/v1",
        default_model="",
        structured_method="function_calling",
        api_key_env="",
    ),
}

PROVIDER_CHOICES = [(spec.key, spec.label) for spec in PROVIDERS.values()]

# Order used when building configs from environment variables.
ENV_PROVIDER_ORDER = (PROVIDER_DEEPSEEK, PROVIDER_OPENAI, PROVIDER_GEMINI)


def get_provider_spec(key):
    return PROVIDERS.get(key or PROVIDER_OPENAI_COMPATIBLE, PROVIDERS[PROVIDER_OPENAI_COMPATIBLE])


def guess_provider(base_url):
    url = (base_url or "").lower()
    if "deepseek" in url:
        return PROVIDER_DEEPSEEK
    if "generativelanguage.googleapis.com" in url:
        return PROVIDER_GEMINI
    if "api.openai.com" in url:
        return PROVIDER_OPENAI
    if ":11434" in url:
        return PROVIDER_OLLAMA
    return PROVIDER_OPENAI_COMPATIBLE


def env_llm_configs():
    """Build provider configs from environment variables.

    Lets the platform run with just ``DEEPSEEK_API_KEY=...`` in ``.env``; database
    configs (managed from the admin UI) always take precedence.
    """
    configs = []
    for key in ENV_PROVIDER_ORDER:
        spec = PROVIDERS[key]
        api_key = os.environ.get(spec.api_key_env, "").strip()
        if not api_key:
            continue
        prefix = key.upper()
        configs.append({
            "name": f"{spec.label} (env)",
            "provider": key,
            "api_key": api_key,
            "base_url": os.environ.get(f"{prefix}_BASE_URL", spec.default_base_url).rstrip("/"),
            "model": os.environ.get(f"{prefix}_MODEL", spec.default_model),
            "tags": [],
        })
    return configs
