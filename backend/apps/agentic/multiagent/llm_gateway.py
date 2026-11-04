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

from django.conf import settings
from langchain_core.messages import HumanMessage, SystemMessage

from apps.agentic.multiagent import guardrails
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

# Circuit breaker: a provider that reported "no credits" or rejected its API key is skipped for a while
# instead of costing a failed round trip on every agent call.
CIRCUIT_OPEN_SECONDS = 120
_circuit = {}


def _trip(label, reason):
    _circuit[label] = (time.monotonic() + CIRCUIT_OPEN_SECONDS, reason)


def _tripped(label):
    entry = _circuit.get(label)
    if not entry:
        return ""
    until, reason = entry
    if time.monotonic() >= until:
        _circuit.pop(label, None)
        return ""
    return f"{reason}; paused for {int(until - time.monotonic())} s"


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
    def __init__(self, *, mode=None, configs=None, guard=None):
        self.mode = mode or _configured_mode()
        self.configs = get_llm_configs() if configs is None else configs
        self.guard = guard  # guardrails.RunGuardrails for the current run (optional)
        self.run_tokens = 0

    def _record(self, kind, agent_key, detail):
        if self.guard is not None:
            self.guard.record(kind, agent_key, detail)

    def _candidates(self, agent_key):
        """The agent's preferred provider first, then the others in priority order (fail-over)."""
        first = _select_config(self.configs, agent_key)
        return [first] + [c for c in self.configs if c is not first]

    def _budget_block(self, config, spec):
        """Return a reason when the budget forbids calling this (paid) provider, else ''."""
        if guardrails.is_local_provider(config, spec):
            return ""
        run_limit = int(getattr(settings, "AGENT_RUN_TOKEN_BUDGET", 0) or 0)
        if run_limit and self.run_tokens >= run_limit:
            return f"run token budget reached ({self.run_tokens}/{run_limit})"
        day_limit = int(getattr(settings, "AGENT_DAILY_TOKEN_BUDGET", 0) or 0)
        if day_limit:
            local_names = [c.get("name") for c in self.configs if guardrails.is_local_provider(c, get_provider_spec(provider_key(c)))]
            used = guardrails.paid_tokens_today(local_names)
            if used >= day_limit:
                return f"daily paid-token budget reached ({used}/{day_limit})"
        return ""

    def invoke(self, *, agent_key, system_prompt, payload, schema, offline_fn):
        if self.mode == MODE_OFFLINE:
            return self._offline(offline_fn, "Offline mode forced in runtime settings.")
        if not self.configs:
            if self.mode == MODE_ONLINE:
                raise LLMUnavailable("No LLM provider configured.")
            return self._offline(offline_fn, "No LLM provider configured.")

        payload = guardrails.prepare_payload(payload, guard=self.guard, agent_key=agent_key)
        problems, last_exc = [], None
        for config in self._candidates(agent_key):
            spec = get_provider_spec(provider_key(config))
            label = config.get("name") or spec.label
            blocked = self._budget_block(config, spec) or _tripped(label)
            if blocked:
                problems.append(f"{label}: {blocked}")
                self._record("budget", agent_key, f"Skipped {label}: {blocked}.")
                continue
            if self.mode == MODE_AUTO:
                reachable, detail = probe_endpoint(config.get("base_url") or spec.default_base_url)
                if not reachable:
                    problems.append(f"{label}: unreachable ({detail})")
                    continue
            started = time.monotonic()
            try:
                output, tokens_in, tokens_out = self._call(config, system_prompt, payload, schema)
            except Exception as exc:
                logger.warning("LLM call failed for agent=%s provider=%s: %s", agent_key, label, exc)
                problems.append(f"{label}: {type(exc).__name__}: {str(exc)[:200]}")
                last_exc = exc
                status = getattr(exc, "status_code", None)
                if status == 402:
                    _trip(label, "out of credits (HTTP 402)")
                elif status in (401, 403):
                    _trip(label, f"API key rejected (HTTP {status})")
                continue
            self.run_tokens += tokens_in + tokens_out
            if problems:
                self._record("failover", agent_key, f"Used {label} after: " + "; ".join(problems))
            return LLMResult(
                output=output,
                mode=MODE_ONLINE,
                provider=label,
                model=config.get("model") or spec.default_model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=int((time.monotonic() - started) * 1000),
                fallback_reason="; ".join(problems)[:500],
            )

        if self.mode == MODE_ONLINE:
            if last_exc is not None:
                raise last_exc
            raise LLMUnavailable("; ".join(problems))
        return self._offline(offline_fn, "; ".join(problems)[:500] or "No provider available.")

    def _call(self, config, system_prompt, payload, schema):
        max_out = int(getattr(settings, "AGENT_LLM_MAX_OUTPUT_TOKENS", 0) or 0)
        model = LLMAPI(configs=[config]).build_model(config, **({"max_tokens": max_out} if max_out else {}))
        structured = model.with_structured_output(schema, method=structured_method(config), include_raw=True)
        response = structured.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=guardrails.render_user_message(payload)),
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
