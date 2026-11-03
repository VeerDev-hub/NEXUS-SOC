"""Typed outputs for every agent.

Each agent must return one of these Pydantic models. In online mode the LLM is
forced to emit this schema (function calling / JSON schema); in offline mode the
agent's rule-based fallback builds the same object, so downstream code never
cares which path produced it.
"""

from typing import Literal

from pydantic import BaseModel, Field

from apps.agentic.analysis.schemas import (
    AffectedAsset,
    AttackChainStep,
    EvidenceFinding,
    IndicatorOfCompromise,
    Remediation,
    TimelineEvent,
)

Verdict = Literal["True Positive", "Suspicious", "False Positive", "Benign", "Insufficient Data"]
Level = Literal["Critical", "High", "Medium", "Low", "Informational"]
Reputation = Literal["malicious", "suspicious", "clean", "unknown"]

ACTION_TYPES = (
    "block_ip",
    "block_domain",
    "quarantine_file",
    "isolate_host",
    "disable_user",
    "reset_credentials",
    "revoke_sessions",
    "block_sender",
    "purge_email",
    "revoke_iam_policy",
    "create_ticket",
)
ActionType = Literal[
    "block_ip",
    "block_domain",
    "quarantine_file",
    "isolate_host",
    "disable_user",
    "reset_credentials",
    "revoke_sessions",
    "block_sender",
    "purge_email",
    "revoke_iam_policy",
    "create_ticket",
]

SPECIALIST_AGENTS = ("triage", "threat_intel", "asset_context", "investigation", "response", "reporting")
FINISH = "finish"


class SupervisorDecision(BaseModel):
    next_agent: str = Field(description="Key of the next agent to run, or 'finish'. Must be one of the allowed options.")
    reasoning: str = Field(description="One or two sentences explaining why this agent is the best next step.")


class TriageResult(BaseModel):
    classification: str = Field(description="Short incident category, e.g. 'Ransomware precursor', 'Phishing', 'Cloud privilege escalation'.")
    verdict: Verdict
    severity: Level
    priority: Level
    confidence_score: int = Field(ge=0, le=100, description="Confidence in the verdict, 0-100.")
    is_duplicate: bool = False
    false_positive_indicators: list[str] = Field(default_factory=list)
    key_observations: list[str] = Field(default_factory=list)
    summary: str


class IndicatorAssessment(BaseModel):
    value: str
    indicator_type: str
    reputation: Reputation
    sources: list[str] = Field(default_factory=list)
    context: str = ""


class ThreatIntelResult(BaseModel):
    indicators: list[IndicatorAssessment] = Field(default_factory=list)
    overall_risk: Level
    malicious_count: int = 0
    known_campaigns: list[str] = Field(default_factory=list)
    summary: str


class EntityContext(BaseModel):
    name: str
    entity_type: Literal["host", "user", "cloud_resource", "mailbox", "other"]
    criticality: Literal["Critical", "High", "Medium", "Low", "Unknown"]
    owner: str = ""
    business_unit: str = ""
    notes: str = ""


class AssetContextResult(BaseModel):
    entities: list[EntityContext] = Field(default_factory=list)
    highest_criticality: Literal["Critical", "High", "Medium", "Low", "Unknown"]
    blast_radius: str = Field(description="What else could be affected if this incident is real.")
    summary: str


class MitreTechnique(BaseModel):
    tactic: str
    technique_id: str = Field(description="ATT&CK ID, e.g. T1490")
    name: str
    evidence: str = ""


class InvestigationResult(BaseModel):
    attack_narrative: str
    verdict: Verdict
    confidence_score: int = Field(ge=0, le=100)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    attack_timeline: list[TimelineEvent] = Field(default_factory=list)
    evidence_findings: list[EvidenceFinding] = Field(default_factory=list)
    scope: str = ""
    unknowns: list[str] = Field(default_factory=list)


class ProposedAction(BaseModel):
    action_type: ActionType
    target: str = Field(description="Exact entity value to act on (IP, hostname, username, hash, ...).")
    rationale: str


class ResponsePlan(BaseModel):
    containment_strategy: str
    actions: list[ProposedAction] = Field(default_factory=list)
    summary: str


class FinalReport(BaseModel):
    verdict: Verdict
    severity: Level
    impact: Literal["Critical", "High", "Medium", "Low", "Unknown"]
    priority: Level
    confidence: Literal["High", "Medium", "Low"]
    executive_summary: str = Field(description="3-5 sentences for a non-technical manager.")
    digest: str = Field(description="One-line technical summary.")
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    evidence_findings: list[EvidenceFinding] = Field(default_factory=list)
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    attack_timeline: list[TimelineEvent] = Field(default_factory=list)
    ioc_indicators: list[IndicatorOfCompromise] = Field(default_factory=list)
    remediations: list[Remediation] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
