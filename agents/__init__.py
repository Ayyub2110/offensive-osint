"""
Agent module containing specialized OSINT and offensive security agents.

This package contains individual agent implementations that perform
specific tasks within the overall OSINT workflow. Each agent is designed
to be modular and can be orchestrated through LangGraph.

Available Agents:
    - ReconAgent: Performs reconnaissance and information gathering
    - VulnerabilityAgent: Identifies and analyzes vulnerabilities
    - IntelligenceAgent: Correlates and analyzes gathered intelligence
    - UsernameCorrelationAgent: Cross-platform username enumeration
    - EmailPatternInferenceAgent: Email pattern generation and validation
    - AssetDiscoveryAgent: Attack surface enumeration and asset discovery
    - TechStackFingerprintAgent: Technology stack fingerprinting
    - AttackSurfacePrioritizerAgent: Target prioritization for exploitation
    - ReconStopDecisionAgent: Recon continuation/termination decision making
"""

from agents.recon_agent import ReconAgent
from agents.vulnerability_agent import VulnerabilityAgent
from agents.intelligence_agent import IntelligenceAgent
from agents.username_correlation_agent import UsernameCorrelationAgent
from agents.email_pattern_inference_agent import EmailPatternInferenceAgent
from agents.asset_discovery_agent import AssetDiscoveryAgent
from agents.tech_stack_fingerprint_agent import TechStackFingerprintAgent
from agents.attack_surface_prioritizer_agent import AttackSurfacePrioritizerAgent
from agents.recon_stop_decision_agent import ReconStopDecisionAgent

__all__ = [
    "ReconAgent",
    "VulnerabilityAgent",
    "IntelligenceAgent",
    "UsernameCorrelationAgent",
    "EmailPatternInferenceAgent",
    "AssetDiscoveryAgent",
    "TechStackFingerprintAgent",
    "AttackSurfacePrioritizerAgent",
    "ReconStopDecisionAgent",
]
