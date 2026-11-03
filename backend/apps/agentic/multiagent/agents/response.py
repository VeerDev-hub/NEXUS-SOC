from apps.agentic.multiagent.actions import ACTION_CATALOG, create_proposal
from apps.agentic.multiagent.agents.base import BaseAgent
from apps.agentic.multiagent.context import is_private_ip
from apps.agentic.multiagent.schemas import ProposedAction, ResponsePlan
from apps.artifacts.models import ArtifactType

MALICIOUS_VERDICTS = ("True Positive", "Suspicious")
ENTITY_ROLES = ("Affected", "Target", "Actor")


def _is_internal_host(artifact):
    """Hosts we own and could isolate: affected/target role and not a public domain name."""
    value = artifact["value"]
    return artifact["role"] in ("Affected", "Target") and value.count(".") < 2 and not value.endswith((".com", ".net", ".org", ".io"))


def _is_user_account(artifact):
    """Real user identities only: skip numeric cloud account IDs, ARNs and mailboxes."""
    value = artifact["value"]
    return artifact["role"] in ENTITY_ROLES and not value.isdigit() and not value.startswith("arn:") and "@" not in value
MAX_ACTIONS = 10


class ResponseAgent(BaseAgent):
    key = "response"
    name = "Response Agent"
    description = "Builds a containment plan and proposes response actions. Actions above low risk wait for human approval."
    tools = ("actions.propose",)
    output_schema = ResponsePlan

    def gather(self, ctx, toolbox):
        return {"action_catalog": {k: {"label": v["label"], "risk": str(v["risk"])} for k, v in ACTION_CATALOG.items()}}

    def offline(self, ctx, evidence):
        investigation = ctx.findings.get("investigation") or {}
        triage = ctx.findings.get("triage") or {}
        verdict = investigation.get("verdict") or triage.get("verdict", "Suspicious")
        if verdict not in MALICIOUS_VERDICTS:
            return ResponsePlan(containment_strategy="No containment required.", actions=[], summary=f"Verdict is {verdict}; no response actions proposed.")
        confirmed = verdict == "True Positive"
        text = ctx.text_blob()
        ti = {i["value"]: i for i in (ctx.findings.get("threat_intel") or {}).get("indicators", [])}
        actions = []

        def add(action_type, target, rationale):
            if target and not any(a.action_type == action_type and a.target == target for a in actions):
                actions.append(ProposedAction(action_type=action_type, target=target, rationale=rationale))

        for artifact in ctx.ioc_artifacts():
            rep = ti.get(artifact["value"], {}).get("reputation")
            if artifact["type"] == ArtifactType.IP_ADDRESS and rep in ("malicious", "suspicious"):
                add("block_ip", artifact["value"], f"External IP rated {rep} by threat intel.")
            elif artifact["type"] in (ArtifactType.URL_STRING, ArtifactType.UNIFORM_RESOURCE_LOCATOR) and rep in ("malicious", "suspicious"):
                add("block_domain", artifact["value"], f"URL rated {rep} by threat intel.")
            elif artifact["type"] == ArtifactType.HOSTNAME and not _is_internal_host(artifact) and rep in ("malicious", "suspicious"):
                add("block_domain", artifact["value"], f"Domain rated {rep} by threat intel.")
            elif artifact["type"] == ArtifactType.HASH:
                add("quarantine_file", artifact["value"], "File hash tied to the detected activity.")
            elif artifact["type"] == ArtifactType.EMAIL_ADDRESS and "phish" in text and artifact["role"] in ("Actor", "Attacker", "Source"):
                add("block_sender", artifact["value"], "Sender of the reported phishing email.")

        if "phish" in text:
            subject_hosts = [a["value"] for a in ctx.artifacts if a["type"] == ArtifactType.EMAIL_ADDRESS and a["role"] not in ("Actor", "Attacker", "Source")]
            for mailbox in subject_hosts[:1]:
                add("purge_email", mailbox, "Remove the phishing message from recipient mailboxes.")

        if confirmed:
            for host in ctx.artifacts_of({ArtifactType.HOSTNAME, ArtifactType.ENDPOINT}):
                if _is_internal_host(host):
                    add("isolate_host", host["value"], "Contain the affected endpoint to stop spread while forensics continue.")
            for user in ctx.artifacts_of({ArtifactType.USER_NAME, ArtifactType.USER}):
                if not _is_user_account(user):
                    continue
                add("revoke_sessions", user["value"], "Invalidate any attacker-held sessions for the involved account.")
                add("reset_credentials", user["value"], "Credentials of the involved account may be compromised.")
            if any(k in text for k in ("iam", "attachuserpolicy", "privilege escalation")):
                principal = next((u for u in ctx.identity_artifacts() if _is_user_account(u)), None)
                if principal:
                    add("revoke_iam_policy", principal["value"], "Detach the policy the principal granted itself.")

        owner_hint = next((e.get("owner") for e in (ctx.findings.get("asset_context") or {}).get("entities", []) if e.get("owner")), "")
        add("create_ticket", owner_hint or ctx.payload.get("title", "SOC"), "Track response and notify the asset owner team.")

        strategy = (
            "Contain immediately: isolate affected assets, cut attacker access, then eradicate and recover."
            if confirmed else
            "Monitor and apply low-impact controls while the investigation confirms the activity."
        )
        actions = actions[:MAX_ACTIONS]
        return ResponsePlan(containment_strategy=strategy, actions=actions, summary=f"Proposed {len(actions)} action(s) for a {verdict} case.")

    def confidence(self, output):
        return None

    def apply(self, ctx, output, *, run, step):
        criticality = {e["name"]: e.get("criticality") for e in (ctx.findings.get("asset_context") or {}).get("entities", [])}
        proposals = []
        for action in output.actions:
            if action.action_type not in ACTION_CATALOG:
                continue
            proposal, _ = create_proposal(
                case=ctx.case,
                run=run,
                step=step,
                action_type=action.action_type,
                target=action.target,
                rationale=action.rationale,
                target_criticality=criticality.get(action.target),
            )
            proposals.append(proposal)
        return proposals
