from django.utils import timezone

from apps.agentic.multiagent.orchestrator import run_agents_for_case
from apps.agentic.models import AgenticJobStatus, CaseAnalysisJob
from apps.agentic.services.cases import (
    complete_case_analysis_job,
    fail_case_analysis_job,
    start_case_analysis_job,
)
from apps.agentic.services.playbooks import (
    claim_pending_playbook_run,
    find_playbook_class,
    mark_playbook_failed,
    mark_playbook_success,
)


def run_playbook_once(*, scripts_dir=None):
    playbook_run = claim_pending_playbook_run()
    if playbook_run is None:
        return False

    try:
        playbook_class = find_playbook_class(playbook_run.name, scripts_dir=scripts_dir)
        result = playbook_class(playbook_run=playbook_run).run()
        mark_playbook_success(playbook_run, str(result))
    except Exception as exc:
        mark_playbook_failed(playbook_run, exc)
        return True

    return True


def run_case_analysis_once():
    job = (
        CaseAnalysisJob.objects.filter(
            status=AgenticJobStatus.PENDING,
            scheduled_at__lte=timezone.now(),
        )
        .order_by("scheduled_at", "created_at")
        .first()
    )
    if job is None:
        return False

    running_job = start_case_analysis_job(job)
    try:
        run = run_agents_for_case(
            running_job.case,
            trigger=running_job.trigger,
            user=running_job.requested_by,
            user_input=running_job.user_input,
            job=running_job,
        )
        complete_case_analysis_job(
            running_job,
            result_json={"agent_run_id": str(run.pk), "verdict": run.final_verdict},
        )
    except Exception as exc:
        fail_case_analysis_job(running_job, str(exc))
    return True
