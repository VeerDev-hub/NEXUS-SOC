"""Single entry point for every agent's LLM call.

Modes (RuntimeConfig.agent_llm_mode):

* ``auto``    - call the configured provider; if it is unreachable, mis-configured
                or errors out, fall back to the agent's offline (rule-based) logic.
* ``online``  - provider only; errors propagate (useful for evaluating models).
* ``offline`` - never touch the network; always use the offline logic.

The gateway also probes connectivity once per minute so an offline laptop does not
wait for a network timeout on every agent call during a live demo.
"""

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from langchain_core.messages import HumanMessage, SystemMessage

from apps.settings.runtime_config import get_llm_configs, get_runtime_config
from integrations.llm.llmapi import LLMAPI, provider_key, structured_method
from integrations.llm.providers import get_provider_spec

logger = logging.getLogger(__name__)

MODE_AUTO = "auto"
MODE_ONLINE = "online"
MODE_OFFLINE = "offline"

PROBE_TTL_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 2.5

_probe_lock = threading.Lock()
_probe_cache = {}


class LLMUnavailable(RuntimeError):
    pass


@dataclass
class LLMResult:
    output: object
    mode: str
    provider: str = ""
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    fallback_reason: str = ""
    extra: dict = field(default_factory=dict)


def _configured_mode():
    try:
        return get_runtime_config().get("agent_llm_mode") or MODE_AUTO
    except Exception:
        return MODE_AUTO


def _host_port(base_url):
    parsed = urlparse(base_url or "")
    if not parsed.hostname:
        return None, None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname, port


def probe_endpoint(base_url, *, force=False):
    """Return (reachable, detail). Cached for PROBE_TTL_SECONDS."""
    host, port = _host_port(base_url)
    if not host:
        return False, "Invalid base URL."
    key = (host, port)
    now = time.monotonic()
    with _probe_lock:
        cached = _probe_cache.get(key)
        if cached and not force and now - cached[0] < PROBE_TTL_SECONDS:
            return cached[1], cached[2]
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT_SECONDS):
            result = (True, f"{host}:{port} reachable")
    except OSError as exc:
        result = (False, f"{host}:{port} unreachable ({type(exc).__name__})")
    with _probe_lock:
        _probe_cache[key] = (now, *result)
    return result


def _select_config(configs, agent_key):
    for tag in (f"agent:{agent_key}", agent_key):
        for config in configs:
            if tag in (config.get("tags") or []):
                return config
    return configs[0]


def llm_status(*, force_probe=False):
    """Describe what the agents will use right now (shown in the UI header)."""
    mode = _configured_mode()
    configs = get_llm_configs()
    providers = [
        {
            "name": c.get("name"),
            "provider": provider_key(c),
            "provider_label": get_provider_spec(provider_key(c)).label,
            "model": c.get("model") or get_provider_spec(provider_key(c)).default_model,
            "tags": c.get("tags") or [],
        }
        for c in configs
    ]
    status = {"configured_mode": mode, "providers": providers, "effective_mode": MODE_OFFLINE, "detail": ""}
    if mode == MODE_OFFLINE:
        status["detail"] = "Offline mock mode is forced in runtime settings."
        return status
    if not configs:
        status["detail"] = "No LLM provider configured; agents run in offline mock mode."
        return status
    reachable, detail = probe_endpoint(configs[0].get("base_url") or get_provider_spec(provider_key(configs[0])).default_base_url, force=force_probe)
    status["detail"] = detail
    status["effective_mode"] = MODE_ONLINE if reachable or mode == MODE_ONLINE else MODE_OFFLINE
    return status


def _usage(raw_message):
    usage = getattr(raw_message, "usage_metadata", None) or {}
    return int(usage.get("input_tokens", 0) or 0), int(usage.get("output_tokens", 0) or 0)


class LLMGateway:
    def __init__(self, *, mode=None, configs=None):
        self.mode = mode or _configured_mode()
        self.configs = get_llm_configs() if configs is None else configs

    def invoke(self, *, agent_key, system_prompt, payload, schema, offline_fn):
        if self.mode == MODE_OFFLINE:
            return self._offline(offline_fn, "Offline mode forced in runtime settings.")
        if not self.configs:
            if self.mode == MODE_ONLINE:
                raise LLMUnavailable("No LLM provider configured.")
            return self._offline(offline_fn, "No LLM provider configured.")

        config = _select_config(self.configs, agent_key)
        spec = get_provider_spec(provider_key(config))
        base_url = config.get("base_url") or spec.default_base_url
        if self.mode == MODE_AUTO:
            reachable, detail = probe_endpoint(base_url)
            if not reachable:
                return self._offline(offline_fn, f"Provider unreachable: {detail}")

        started = time.monotonic()
        try:
            output, tokens_in, tokens_out = self._call(config, system_prompt, payload, schema)
        except Exception as exc:
            logger.warning("LLM call failed for agent=%s provider=%s: %s", agent_key, config.get("name"), exc)
            if self.mode == MODE_ONLINE:
                raise
            return self._offline(offline_fn, f"{type(exc).__name__}: {str(exc)[:300]}")

        return LLMResult(
            output=output,
            mode=MODE_ONLINE,
            provider=config.get("name") or spec.label,
            model=config.get("model") or spec.default_model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    def _call(self, config, system_prompt, payload, schema):
        model = LLMAPI(configs=[config]).build_model(config)
        structured = model.with_structured_output(schema, method=structured_method(config), include_raw=True)
        response = structured.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=json.dumps(payload, ensure_ascii=False, default=str)),
        ])
        if response.get("parsing_error") or response.get("parsed") is None:
            raise ValueError(f"Model output did not match {schema.__name__}: {response.get('parsing_error')}")
        tokens_in, tokens_out = _usage(response.get("raw"))
        return response["parsed"], tokens_in, tokens_out

    @staticmethod
    def _offline(offline_fn, reason):
        started = time.monotonic()
        output = offline_fn()
        return LLMResult(
            output=output,
            mode=MODE_OFFLINE,
            provider="Offline engine",
            model="rule-based",
            latency_ms=int((time.monotonic() - started) * 1000),
            fallback_reason=reason,
        )
