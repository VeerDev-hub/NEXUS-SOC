"""Tools available to agents.

Every call goes through ``Toolbox._call`` which times it, catches failures and
records a compact trace that is persisted on the AgentStep and shown in the UI.
Tools wrap the platform's existing integrations (threat intel, CMDB, SIEM,
knowledge base) so the same code paths serve analysts and agents.
"""

import logging
import time
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from apps.agentic.analysis.knowledge import normalize_knowledge_keywords, search_knowledge_records
from apps.cases.models import Case

logger = logging.getLogger(__name__)

MAX_TRACE_CHARS = 600


def _short(value):
    text = str(value)
    return text if len(text) <= MAX_TRACE_CHARS else text[:MAX_TRACE_CHARS] + "..."


class Toolbox:
    def __init__(self, case):
        self.case = case
        self.calls = []

    def reset(self):
        calls, self.calls = self.calls, []
        return calls

    def _call(self, name, args, fn, summarize=None):
        started = time.monotonic()
        status = "ok"
        try:
            result = fn()
        except Exception as exc:
            logger.warning("Tool %s failed: %s", name, exc)
            result = None
            status = "error"
            summary = f"{type(exc).__name__}: {exc}"
        else:
            summary = summarize(result) if summarize else _short(result)
        self.calls.append({
            "tool": name,
            "args": args,
            "status": status,
            "summary": _short(summary),
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
        return result

    # ---- threat intelligence -------------------------------------------------
    def threat_intel_lookup(self, indicator, artifact_type):
        from integrations.threat_intel.service import query_indicator

        def summarize(out):
            providers = ", ".join(sorted({r.provider for r in out.results})) or "none"
            return f"risk={out.aggregated_risk_level or 'unknown'} providers={providers}"

        def run():
            out = query_indicator(indicator, artifact_type=artifact_type)
            if not out.results:
                # No external feed configured (or offline): use the built-in local feed.
                from integrations.threat_intel.providers import MOCK_PROVIDER_NAME, MockThreatIntelProvider
                from integrations.threat_intel.service import _aggregate_risk

                result = MockThreatIntelProvider().query(indicator, artifact_type=artifact_type)
                out = out.model_copy(update={
                    "results": [result],
                    "indicator_type": result.indicator_type,
                    "aggregated_risk_level": _aggregate_risk([result]),
                    "errors": [e for e in out.errors if MOCK_PROVIDER_NAME not in e],
                })
            return out

        out = self._call("threat_intel.lookup", {"indicator": indicator, "type": artifact_type}, run, summarize)
        return out.model_dump() if out is not None else None

    # ---- CMDB / identity -------------------------------------------------------
    def cmdb_lookup(self, artifact_type, value):
        from integrations.cmdb.service import lookup_artifact_context

        def summarize(out):
            for r in out.results:
                if r.supported:
                    crit = (r.business or {}).get("business_criticality", "?")
                    owner = (r.owner or {}).get("owner_team", "?")
                    return f"{r.record_type or 'record'} found, criticality={crit} owner={owner}"
            return "no record"

        out = self._call(
            "cmdb.lookup",
            {"type": artifact_type, "value": value},
            lambda: lookup_artifact_context(artifact_type, value),
            summarize,
        )
        return out.model_dump() if out is not None else None

    # ---- SIEM / log search -----------------------------------------------------
    def log_search(self, keyword, *, hours=24):
        """Search the configured SIEM; fall back to the case's own raw events."""
        from integrations.siem.registry import list_indices

        def run():
            try:
                indices = list_indices()
            except Exception:
                indices = []
            siem_error = ""
            if indices:
                from integrations.siem.models import KeywordSearchInput
                from integrations.siem.service import keyword_search

                end = timezone.now()
                start = end - timedelta(hours=hours)
                try:
                    results = keyword_search(KeywordSearchInput(
                        keyword=keyword,
                        time_range_start=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        time_range_end=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    ))
                    return {"source": "siem", "results": [r.model_dump() for r in results][:3]}
                except Exception as exc:
                    # SIEM not configured/reachable: degrade to the case's own raw events.
                    siem_error = f"{type(exc).__name__}: {exc}"[:200]
            return {"source": "case_events", "siem_error": siem_error, "results": self._local_events(keyword)}

        def summarize(out):
            return f"source={out['source']} hits={len(out['results'])}"

        return self._call("siem.search", {"keyword": keyword, "window_hours": hours}, run, summarize)

    def _local_events(self, keyword):
        needle = str(keyword).lower()
        hits = []
        for alert in self.case.alerts.all().order_by("first_seen_time"):
            raw = alert.raw_data or {}
            if needle in str(raw).lower() or needle in (alert.desc or "").lower():
                hits.append({
                    "alert_id": alert.alert_id,
                    "time": alert.first_seen_time.isoformat() if alert.first_seen_time else None,
                    "rule": alert.rule_name,
                    "event": raw,
                })
        return hits[:10]

    # ---- knowledge base ----------------------------------------------------------
    def knowledge_search(self, keywords):
        keywords = normalize_knowledge_keywords(keywords)
        return self._call(
            "knowledge.search",
            {"keywords": keywords},
            lambda: search_knowledge_records(keywords, limit=5),
            lambda out: f"{len(out)} record(s)",
        )

    # ---- correlation -------------------------------------------------------------
    def related_cases(self, values):
        values = [v for v in values if v][:20]

        def run():
            if not values:
                return []
            query = Q()
            for value in values:
                query |= Q(alerts__artifacts__value=value)
            cases = (
                Case.objects.filter(query)
                .exclude(pk=self.case.pk)
                .distinct()
                .order_by("-created_at")[:5]
            )
            return [
                {"case_id": c.case_id, "title": c.title, "status": c.status, "verdict": c.verdict or c.verdict_ai}
                for c in cases
            ]

        return self._call("cases.related", {"values": values[:5]}, run, lambda out: f"{len(out)} related case(s)")
