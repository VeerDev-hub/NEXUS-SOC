from apps.agentic.multiagent.agents.asset_context import AssetContextAgent
from apps.agentic.multiagent.agents.investigation import InvestigationAgent
from apps.agentic.multiagent.agents.reporting import ReportingAgent
from apps.agentic.multiagent.agents.response import ResponseAgent
from apps.agentic.multiagent.agents.threat_intel import ThreatIntelAgent
from apps.agentic.multiagent.agents.triage import TriageAgent

AGENT_CLASSES = (TriageAgent, ThreatIntelAgent, AssetContextAgent, InvestigationAgent, ResponseAgent, ReportingAgent)
AGENTS = {cls.key: cls() for cls in AGENT_CLASSES}


def get_agent(key):
    return AGENTS[key]
