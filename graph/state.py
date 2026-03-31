"""
State definitions for the LangGraph OSINT workflow.

This module defines the state schema and structure that flows through
the LangGraph workflow. The state contains all information gathered
by agents and controls the workflow execution path.
"""

from typing import Dict, Any, List, Optional, TypedDict
from pydantic import BaseModel, Field


class OSINTState(TypedDict):
    """
    State object for the OSINT workflow graph.
    
    This state is passed between nodes in the LangGraph workflow and
    accumulates information from each agent's execution.
    
    Attributes:
        target: Primary target (domain, IP, organization)
        scope: List of assessment types to perform
        recon_data: Reconnaissance findings
        vulnerability_data: Vulnerability assessment results
        intelligence_data: Correlated intelligence and analysis
        metadata: Execution metadata (timestamps, errors, etc.)
        next_action: Determines which node to execute next
        completed: Flag indicating workflow completion
    """
    
    target: str
    scope: List[str]
    recon_data: Optional[Dict[str, Any]]
    vulnerability_data: Optional[Dict[str, Any]]
    intelligence_data: Optional[Dict[str, Any]]
    metadata: Optional[Dict[str, Any]]
    next_action: Optional[str]
    completed: bool


class ReconData(BaseModel):
    """
    Schema for reconnaissance data.
    
    Attributes:
        subdomains: Discovered subdomains
        dns_records: DNS information
        certificates: Certificate transparency data
        public_repos: Public code repositories
        social_profiles: Social media profiles
    """
    
    subdomains: List[str] = Field(default_factory=list)
    dns_records: Dict[str, Any] = Field(default_factory=dict)
    certificates: List[Dict[str, Any]] = Field(default_factory=list)
    public_repos: List[str] = Field(default_factory=list)
    social_profiles: Dict[str, str] = Field(default_factory=dict)


class VulnerabilityData(BaseModel):
    """
    Schema for vulnerability assessment data.
    
    Attributes:
        open_ports: List of open ports and services
        vulnerabilities: Identified vulnerabilities
        misconfigurations: Security misconfigurations
        security_headers: HTTP security header analysis
        risk_score: Overall risk assessment score
    """
    
    open_ports: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    misconfigurations: List[Dict[str, Any]] = Field(default_factory=list)
    security_headers: Dict[str, Any] = Field(default_factory=dict)
    risk_score: Optional[float] = None


class IntelligenceData(BaseModel):
    """
    Schema for intelligence analysis data.
    
    Attributes:
        correlations: Correlated findings across agents
        risk_assessment: Risk analysis and scoring
        recommendations: Actionable recommendations
        threat_intel: External threat intelligence
        report: Generated intelligence report
    """
    
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    report: Optional[str] = None


def create_initial_state(target: str, scope: List[str]) -> OSINTState:
    """
    Create initial state for the workflow.
    
    Args:
        target: Target to assess
        scope: List of assessment scopes
        
    Returns:
        Initial OSINTState object
    """
    return OSINTState(
        target=target,
        scope=scope,
        recon_data=None,
        vulnerability_data=None,
        intelligence_data=None,
        metadata={"start_time": None, "errors": []},
        next_action="recon",
        completed=False
    )
