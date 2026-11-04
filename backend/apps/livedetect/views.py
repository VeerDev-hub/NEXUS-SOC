"""Read-only API over the behavioural baselines (``/api/ueba/...``)."""

from django.conf import settings
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import EntityProfile


def _risk_now(row, now):
    if not row.risk_score or row.risk_updated_at is None:
        return 0.0
    hours = max(0.0, (now - row.risk_updated_at).total_seconds() / 3600)
    return row.risk_score * 0.5 ** (hours / settings.UEBA_RISK_HALF_LIFE_HOURS)


def _top(table, limit=5):
    table = table or {}
    return [{"value": key, "count": table[key]} for key in sorted(table, key=table.get, reverse=True)[:limit]]


def serialize_profile(row, now, *, detail=False):
    data = row.data or {}
    if row.entity_type == "user":
        count, needed = int(data.get("logons", 0)), settings.UEBA_MIN_OBSERVATIONS
    else:
        count, needed = int(data.get("process_events", 0)), settings.UEBA_MIN_PROCESS_EVENTS
    mature = count >= needed and (row.last_seen - row.first_seen).total_seconds() >= settings.UEBA_MIN_AGE_HOURS * 3600
    item = {
        "id": row.pk,
        "entity_type": row.entity_type,
        "entity": row.entity,
        "observations": row.observations,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "state": "active" if mature else "learning",
        "learning_progress": min(100, round(100 * count / max(1, needed))),
        "risk_score": round(_risk_now(row, now)),
        "anomaly_count": row.anomaly_count,
        "last_anomaly_at": row.last_anomaly_at,
        "last_anomaly": row.last_anomaly or {},
        "summary": {
            "source_ips": len(data.get("src_ips") or {}),
            "hosts": len(data.get("hosts") or {}),
            "users": len(data.get("users") or {}),
            "processes": len(data.get("processes") or {}),
            "privileged_hosts": len(data.get("privilege") or {}),
        },
    }
    if detail:
        item["baseline"] = {
            "top_source_ips": _top(data.get("src_ips")),
            "top_hosts": _top(data.get("hosts")),
            "top_users": _top(data.get("users")),
            "privileged_hosts": _top(data.get("privilege")),
            "hours": data.get("hours") or [0] * 24,
            "top_processes": _top(data.get("processes"), 15),
        }
    return item


class EntityProfileListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        now = timezone.now()
        rows = EntityProfile.objects.all()
        entity_type = request.query_params.get("type")
        if entity_type in ("user", "host"):
            rows = rows.filter(entity_type=entity_type)
        search = (request.query_params.get("q") or "").strip()
        if search:
            rows = rows.filter(entity__icontains=search)
        items = [serialize_profile(row, now) for row in rows[:1000]]
        items.sort(key=lambda item: (-item["risk_score"], -(item["anomaly_count"]), item["entity"]))
        totals = EntityProfile.objects.aggregate(
            users=Count("id", filter=Q(entity_type="user")),
            hosts=Count("id", filter=Q(entity_type="host")),
            anomalous=Count("id", filter=Q(anomaly_count__gt=0)),
        )
        return Response({
            "enabled": settings.UEBA_ENABLED,
            "config": {
                "min_observations": settings.UEBA_MIN_OBSERVATIONS,
                "min_age_hours": settings.UEBA_MIN_AGE_HOURS,
                "min_process_events": settings.UEBA_MIN_PROCESS_EVENTS,
                "min_alert_score": settings.UEBA_MIN_ALERT_SCORE,
                "risk_half_life_hours": settings.UEBA_RISK_HALF_LIFE_HOURS,
            },
            "totals": {**totals, "active": sum(1 for item in items if item["state"] == "active")},
            "results": items[: int(request.query_params.get("limit") or 200)],
        })


class EntityProfileDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        row = EntityProfile.objects.filter(pk=pk).first()
        if row is None:
            return Response({"detail": "Not found."}, status=404)
        return Response(serialize_profile(row, timezone.now(), detail=True))
