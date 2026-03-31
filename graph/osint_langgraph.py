"""
LangGraph OSINT Workflow for offensive security reconnaissance.

This module implements a complete LangGraph workflow that orchestrates
all OSINT agents in a logical sequence for automated target analysis
and attack surface mapping.

WORKFLOW SEQUENCE:
    1. Username Correlation (find user across platforms)
    2. Email Pattern Inference (generate target emails)
    3. Asset Discovery (enumerate attack surface)
    4. Tech Stack Fingerprinting (identify technologies)
    5. Attack Surface Prioritization (score and rank targets)
    6. Recon Stop Decision (continue or transition to exploitation)

OFFENSIVE WORKFLOW: Complete pre-attack intelligence gathering
"""

from typing import Dict, Any, List, Optional, TypedDict, Annotated
from langgraph.graph import StateGraph, END
from datetime import datetime
import asyncio

# Import all agents
from agents.username_correlation_agent import UsernameCorrelationAgent
from agents.email_pattern_inference_agent import EmailPatternInferenceAgent
from agents.asset_discovery_agent import AssetDiscoveryAgent
from agents.tech_stack_fingerprint_agent import TechStackFingerprintAgent
from agents.attack_surface_prioritizer_agent import AttackSurfacePrioritizerAgent
from agents.recon_stop_decision_agent import ReconStopDecisionAgent
from agents.llm_attack_advisor_agent import LLMAttackAdvisorAgent


class OSINTWorkflowState(TypedDict, total=False):
    """
    Complete state for OSINT workflow.

    This state flows through all nodes and accumulates intelligence
    from each agent in the reconnaissance pipeline.

    Attributes:
        # Input
        username: Target username for correlation
        target_name: Target full name for email inference
        domain: Target domain for asset discovery
        target_url: Primary target URL for fingerprinting

        # Agent outputs
        username_correlation: Username correlation results
        email_patterns: Email pattern inference results
        asset_discovery: Asset discovery results
        tech_fingerprint: Technology fingerprinting results
        attack_surface_prioritization: Prioritization results
        recon_decision: Stop/continue decision

        # Workflow control
        iteration: Current iteration number
        should_continue_recon: Whether to continue recon loop
        start_time: Workflow start timestamp
        state_history: History of previous states

        # Metadata
        metadata: Additional workflow metadata
        errors: List of errors encountered
    """

    # Input parameters
    username: str
    target_name: str
    domain: str
    target_url: str

    # Agent outputs
    username_correlation: Optional[Dict[str, Any]]
    email_patterns: Optional[Dict[str, Any]]
    asset_discovery: Optional[Dict[str, Any]]
    tech_fingerprint: Optional[Dict[str, Any]]
    attack_surface_prioritization: Optional[Dict[str, Any]]
    attack_advisory: Optional[Dict[str, Any]]  # LLM-powered strategic recommendations
    recon_decision: Optional[Dict[str, Any]]

    # Workflow control
    iteration: int
    should_continue_recon: bool
    start_time: str
    state_history: List[Dict[str, Any]]

    # Metadata
    metadata: Dict[str, Any]
    errors: List[str]


# ==================== NODE IMPLEMENTATIONS ====================


async def username_correlation_node(state: OSINTWorkflowState) -> OSINTWorkflowState:
    """
    Username correlation node - discovers user across platforms.

    ATTACK VALUE: Identifies social media, code repos, forums where
    target has accounts. Useful for OSINT and social engineering.

    Args:
        state: Current workflow state

    Returns:
        Updated state with username correlation results
    """
    print(f"[USERNAME CORRELATION] Checking username: {state.get('username', 'N/A')}")

    try:
        username = state.get("username")

        if username:
            agent = UsernameCorrelationAgent()
            try:
                results = await agent.check_username(username)
                state["username_correlation"] = results
                print(
                    f"[USERNAME CORRELATION] Found on {results['summary']['exists']} platforms"
                )
            finally:
                await agent._close_session()
        else:
            print("[USERNAME CORRELATION] Skipped - no username provided")
            state["username_correlation"] = None

    except Exception as e:
        error_msg = f"Username correlation error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        state.setdefault("errors", []).append(error_msg)
        state["username_correlation"] = None

    return state


async def email_pattern_inference_node(state: OSINTWorkflowState) -> OSINTWorkflowState:
    """
    Email pattern inference node - generates probable email addresses.

    ATTACK VALUE: Creates target lists for:
        - Credential stuffing
        - Password spraying
        - Phishing campaigns

    Args:
        state: Current workflow state

    Returns:
        Updated state with email pattern results
    """
    print(
        f"[EMAIL INFERENCE] Generating email patterns for domain: {state.get('domain', 'N/A')}"
    )

    try:
        identifier = state.get("target_name") or state.get("username")
        domain = state.get("domain")

        if identifier and domain:
            agent = EmailPatternInferenceAgent()
            results = await agent.infer_email_patterns(
                identifier=identifier, domain=domain, validate_domain=True
            )
            state["email_patterns"] = results

            print(
                f"[EMAIL INFERENCE] Generated {results['total_patterns']} email patterns"
            )
        else:
            print("[EMAIL INFERENCE] Skipped - missing identifier or domain")
            state["email_patterns"] = None

    except Exception as e:
        error_msg = f"Email inference error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        state.setdefault("errors", []).append(error_msg)
        state["email_patterns"] = None

    return state


async def asset_discovery_node(state: OSINTWorkflowState) -> OSINTWorkflowState:
    """
    Asset discovery node - enumerates attack surface.

    ATTACK VALUE: Discovers:
        - Subdomains (dev, staging, admin panels)
        - Hidden endpoints (robots.txt, sitemaps)
        - Sensitive files (configs, backups)

    Args:
        state: Current workflow state

    Returns:
        Updated state with asset discovery results
    """
    print(
        f"[ASSET DISCOVERY] Discovering assets for domain: {state.get('domain', 'N/A')}"
    )

    try:
        domain = state.get("domain")

        if domain:
            agent = AssetDiscoveryAgent()
            try:
                results = await agent.discover_assets(
                    domain=domain, include_subdomains=True, include_files=True
                )
                state["asset_discovery"] = results
                print(f"[ASSET DISCOVERY] Found {results['total_assets']} assets")
                print(f"[ASSET DISCOVERY] Breakdown: {results['summary']}")
            finally:
                await agent._close_session()
        else:
            print("[ASSET DISCOVERY] Skipped - no domain provided")
            state["asset_discovery"] = None

    except Exception as e:
        error_msg = f"Asset discovery error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        state.setdefault("errors", []).append(error_msg)
        state["asset_discovery"] = None

    return state


async def tech_fingerprint_node(state: OSINTWorkflowState) -> OSINTWorkflowState:
    """
    Technology fingerprinting node - identifies tech stack.

    ATTACK VALUE: Technology profile enables:
        - CVE lookup for specific versions
        - Framework-specific exploits
        - WAF detection for bypass planning

    Args:
        state: Current workflow state

    Returns:
        Updated state with tech fingerprint results
    """
    print(f"[TECH FINGERPRINT] Fingerprinting URL: {state.get('target_url', 'N/A')}")

    try:
        # Get primary URL or construct from domain
        url = state.get("target_url")
        if not url and state.get("domain"):
            url = f"https://{state['domain']}"

        if url:
            agent = TechStackFingerprintAgent()
            try:
                fingerprint = await agent.fingerprint(url)
                state["tech_fingerprint"] = fingerprint.to_dict()

                # Print key findings
                web_server = fingerprint.web_server.get("type", "unknown")
                backend = fingerprint.backend.get("primary", {})
                backend_tech = (
                    backend.get("technology", "unknown") if backend else "unknown"
                )

                print(
                    f"[TECH FINGERPRINT] Server: {web_server}, Backend: {backend_tech}"
                )

                # Print security info
                security = fingerprint.security
                waf_cdn = security.get("waf_cdn", {})
                if waf_cdn.get("has_waf"):
                    print(
                        f"[TECH FINGERPRINT] WAF detected: {waf_cdn.get('detected', [{}])[0].get('name', 'unknown')}"
                    )
                else:
                    print("[TECH FINGERPRINT] No WAF detected - direct access possible")
            finally:
                await agent._close_session()
        else:
            print("[TECH FINGERPRINT] Skipped - no URL provided")
            state["tech_fingerprint"] = None

    except Exception as e:
        error_msg = f"Tech fingerprint error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        state.setdefault("errors", []).append(error_msg)
        state["tech_fingerprint"] = None

    return state


async def attack_surface_prioritization_node(
    state: OSINTWorkflowState,
) -> OSINTWorkflowState:
    """
    Attack surface prioritization node - ranks targets by exploitability.

    ATTACK VALUE: Identifies highest-value targets for:
        - Resource allocation
        - Attack path planning
        - Exploit prioritization

    Args:
        state: Current workflow state

    Returns:
        Updated state with prioritization results
    """
    print("[ATTACK SURFACE PRIORITIZATION] Analyzing and prioritizing targets...")

    try:
        # Get assets
        assets = []
        asset_discovery = state.get("asset_discovery")
        if asset_discovery:
            assets = asset_discovery.get("assets", [])

        # Get tech fingerprints
        tech_fingerprints = {}
        if state.get("tech_fingerprint"):
            url = state["tech_fingerprint"].get("url")
            if url:
                tech_fingerprints[url] = state["tech_fingerprint"]

        if assets:
            agent = AttackSurfacePrioritizerAgent()
            results = agent.prioritize_assets(assets, tech_fingerprints)
            state["attack_surface_prioritization"] = results

            # Print summary
            summary = results["summary"]
            print(f"[PRIORITIZATION] Analyzed {results['total_assets']} assets")
            print(
                f"[PRIORITIZATION] Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}"
            )

            # Print top targets
            top_targets = results.get("top_targets", [])[:3]
            if top_targets:
                print("[PRIORITIZATION] Top 3 targets:")
                for i, target in enumerate(top_targets, 1):
                    print(
                        f"  {i}. {target['asset']} (score: {target['total_score']}, priority: {target['priority_level']})"
                    )
        else:
            print("[PRIORITIZATION] Skipped - no assets to prioritize")
            state["attack_surface_prioritization"] = None

    except Exception as e:
        error_msg = f"Prioritization error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        state.setdefault("errors", []).append(error_msg)
        state["attack_surface_prioritization"] = None

    return state


async def llm_advisor_node(state: OSINTWorkflowState) -> OSINTWorkflowState:
    """
    LLM Attack Advisor node - generates strategic attack recommendations.

    OFFENSIVE VALUE: Acts as senior red teamer providing:
        - Phishing campaign strategies
        - Credential attack methodologies
        - JWT/authentication abuse scenarios
        - Account takeover approaches
        - Realistic attack path prioritization

    Args:
        state: Current workflow state with all intelligence

    Returns:
        Updated state with attack advisory
    """
    print("[LLM ADVISOR] Generating strategic attack recommendations...")

    try:
        # Prepare complete intelligence package for analysis
        intelligence_data = {
            "domain": state.get("domain"),
            "url": state.get("target_url"),
            "username_correlation": state.get("username_correlation"),
            "email_patterns": state.get("email_patterns"),
            "asset_discovery": state.get("asset_discovery"),
            "tech_stack": state.get("tech_fingerprint"),
            "attack_surface_prioritization": state.get("attack_surface_prioritization"),
        }

        # Initialize LLM advisor agent
        agent = LLMAttackAdvisorAgent()

        # Generate attack advisory
        advisory = agent.analyze_intelligence(intelligence_data)
        state["attack_advisory"] = advisory

        # Print summary
        num_paths = len(advisory.get("attack_paths", []))
        print(
            f"[LLM ADVISOR] Generated {num_paths} strategic attack path recommendations"
        )

        if advisory.get("attack_paths"):
            top_path = advisory["attack_paths"][0]
            print(f"[LLM ADVISOR] Top recommendation: {top_path.get('name', 'N/A')}")
            print(
                f"[LLM ADVISOR] Success probability: {top_path.get('success_probability', 'N/A').upper()}"
            )

    except Exception as e:
        error_msg = f"LLM advisor error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        state.setdefault("errors", []).append(error_msg)
        state["attack_advisory"] = None

    return state


async def recon_decision_node(state: OSINTWorkflowState) -> OSINTWorkflowState:
    """
    Recon stop decision node - determines whether to continue or stop.

    WORKFLOW CONTROL: Prevents endless loops by detecting:
        - Diminishing returns
        - Low-value targets only
        - Convergence to stable state

    Args:
        state: Current workflow state

    Returns:
        Updated state with decision
    """
    print("[RECON DECISION] Evaluating whether to continue reconnaissance...")

    try:
        iteration = state.get("iteration", 1)
        start_time = state.get("start_time")

        # Get state history
        state_history = state.get("state_history", [])
        previous_state = state_history[-1] if state_history else None

        agent = ReconStopDecisionAgent()
        decision = agent.decide(
            current_iteration=iteration,
            current_state=state,
            previous_state=previous_state,
            state_history=state_history if len(state_history) >= 2 else None,
            start_time=start_time,
        )

        state["recon_decision"] = decision.to_dict()
        state["should_continue_recon"] = decision.decision.value == "continue"

        # Print decision
        print(f"[RECON DECISION] Decision: {decision.decision.value.upper()}")
        print(f"[RECON DECISION] Confidence: {decision.confidence:.2f}")
        print(f"[RECON DECISION] Reason: {decision.primary_reason}")

        if decision.decision.value == "stop":
            print("[RECON DECISION] Transitioning to exploitation phase")
        else:
            print("[RECON DECISION] Continuing reconnaissance")

    except Exception as e:
        error_msg = f"Recon decision error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        state.setdefault("errors", []).append(error_msg)
        # Default to stopping on error
        state["should_continue_recon"] = False

    return state


# ==================== ROUTING FUNCTIONS ====================


def route_after_decision(state: OSINTWorkflowState) -> str:
    """
    Route workflow after recon decision.

    Args:
        state: Current workflow state

    Returns:
        Next node name or END
    """
    should_continue = state.get("should_continue_recon", False)

    if should_continue:
        # Loop back to asset discovery for another iteration
        print("[ROUTER] Routing to asset discovery for another iteration")
        return "asset_discovery"
    else:
        # End workflow
        print("[ROUTER] Ending workflow")
        return END


# ==================== WORKFLOW BUILDER ====================


def create_osint_workflow() -> StateGraph:
    """
    Create the complete OSINT LangGraph workflow.

    WORKFLOW GRAPH:
        START
          ↓
        username_correlation
          ↓
        email_inference
          ↓
        asset_discovery ←──┐
          ↓                │
        tech_fingerprint   │
          ↓                │
        prioritization     │
          ↓                │
        llm_advisor        │
          ↓                │
        recon_decision ────┘
          ↓
        END

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create workflow
    workflow = StateGraph(OSINTWorkflowState)

    # Add nodes
    workflow.add_node("username_correlation", username_correlation_node)
    workflow.add_node("email_inference", email_pattern_inference_node)
    workflow.add_node("asset_discovery", asset_discovery_node)
    workflow.add_node("tech_fingerprint", tech_fingerprint_node)
    workflow.add_node("prioritization", attack_surface_prioritization_node)
    workflow.add_node("llm_advisor", llm_advisor_node)  # LLM strategic recommendations
    workflow.add_node("recon_decision", recon_decision_node)

    # Set entry point
    workflow.set_entry_point("username_correlation")

    # Add edges (sequential flow)
    workflow.add_edge("username_correlation", "email_inference")
    workflow.add_edge("email_inference", "asset_discovery")
    workflow.add_edge("asset_discovery", "tech_fingerprint")
    workflow.add_edge("tech_fingerprint", "prioritization")
    workflow.add_edge("prioritization", "llm_advisor")
    workflow.add_edge("llm_advisor", "recon_decision")

    # Add conditional edge for recon decision
    workflow.add_conditional_edges(
        "recon_decision",
        route_after_decision,
        {
            "asset_discovery": "asset_discovery",  # Loop back
            END: END,  # Stop
        },
    )

    # Compile workflow
    compiled = workflow.compile()

    return compiled


# ==================== EXECUTION HELPER ====================


async def run_osint_workflow(
    username: Optional[str] = None,
    target_name: Optional[str] = None,
    domain: Optional[str] = None,
    target_url: Optional[str] = None,
    max_iterations: int = 3,
) -> Dict[str, Any]:
    """
    Execute the complete OSINT workflow.

    USAGE EXAMPLE:
        results = await run_osint_workflow(
            username="johndoe",
            target_name="John Doe",
            domain="targetcorp.com",
            target_url="https://targetcorp.com"
        )

    Args:
        username: Target username for correlation
        target_name: Target full name for email inference
        domain: Target domain for asset discovery
        target_url: Primary target URL for fingerprinting
        max_iterations: Maximum recon iterations

    Returns:
        Final state with all intelligence gathered
    """
    # Create initial state
    initial_state: OSINTWorkflowState = {
        "username": username or "",
        "target_name": target_name or "",
        "domain": domain or "",
        "target_url": target_url or "",
        "username_correlation": None,
        "email_patterns": None,
        "asset_discovery": None,
        "tech_fingerprint": None,
        "attack_surface_prioritization": None,
        "attack_advisory": None,
        "recon_decision": None,
        "iteration": 1,
        "should_continue_recon": True,
        "start_time": datetime.utcnow().isoformat(),
        "state_history": [],
        "metadata": {
            "max_iterations": max_iterations,
        },
        "errors": [],
    }

    # Create workflow
    workflow = create_osint_workflow()

    # Execute workflow
    print("=" * 60)
    print("OSINT WORKFLOW EXECUTION STARTED")
    print("=" * 60)
    print(f"Target: {username or target_name or domain or target_url}")
    print(f"Start time: {initial_state['start_time']}")
    print("=" * 60)

    try:
        # Run workflow
        final_state = await workflow.ainvoke(initial_state)

        print("=" * 60)
        print("OSINT WORKFLOW EXECUTION COMPLETED")
        print("=" * 60)

        # Print summary
        print("\n[SUMMARY]")
        print(f"Total iterations: {final_state.get('iteration', 1)}")
        print(f"Errors encountered: {len(final_state.get('errors', []))}")

        if final_state.get("username_correlation"):
            uc = final_state["username_correlation"]
            print(f"Platforms found: {uc['summary']['exists']}")

        if final_state.get("email_patterns"):
            ep = final_state["email_patterns"]
            print(f"Email patterns generated: {ep['total_patterns']}")

        if final_state.get("asset_discovery"):
            ad = final_state["asset_discovery"]
            print(f"Assets discovered: {ad['total_assets']}")

        if final_state.get("attack_surface_prioritization"):
            asp = final_state["attack_surface_prioritization"]
            summary = asp["summary"]
            print(f"Critical targets: {summary['critical']}")
            print(f"High-value targets: {summary['high']}")

        if final_state.get("attack_advisory"):
            advisory = final_state["attack_advisory"]
            num_paths = len(advisory.get("attack_paths", []))
            print(f"Attack paths recommended: {num_paths}")
            if advisory.get("attack_paths"):
                top_path = advisory["attack_paths"][0]
                print(f"Top attack path: {top_path.get('name', 'N/A')}")

        return final_state

    except Exception as e:
        print(f"\n[FATAL ERROR] Workflow execution failed: {str(e)}")
        raise


# ==================== CONVENIENCE FUNCTION ====================


def create_workflow_for_domain(domain: str) -> StateGraph:
    """
    Create a simplified workflow focused on domain reconnaissance.

    Skips username/email nodes and focuses on:
        - Asset discovery
        - Tech fingerprinting
        - Prioritization

    Args:
        domain: Target domain

    Returns:
        Compiled StateGraph for domain recon
    """
    workflow = StateGraph(OSINTWorkflowState)

    # Add nodes
    workflow.add_node("asset_discovery", asset_discovery_node)
    workflow.add_node("tech_fingerprint", tech_fingerprint_node)
    workflow.add_node("prioritization", attack_surface_prioritization_node)
    workflow.add_node("recon_decision", recon_decision_node)

    # Set entry point
    workflow.set_entry_point("asset_discovery")

    # Add edges
    workflow.add_edge("asset_discovery", "tech_fingerprint")
    workflow.add_edge("tech_fingerprint", "prioritization")
    workflow.add_edge("prioritization", "recon_decision")

    # Add conditional edge
    workflow.add_conditional_edges(
        "recon_decision",
        route_after_decision,
        {"asset_discovery": "asset_discovery", END: END},
    )

    return workflow.compile()


def create_workflow_for_user(username: str, domain: Optional[str] = None) -> StateGraph:
    """
    Create a simplified workflow focused on user reconnaissance.

    Focuses on:
        - Username correlation
        - Email pattern inference

    Args:
        username: Target username
        domain: Optional domain for email inference

    Returns:
        Compiled StateGraph for user recon
    """
    workflow = StateGraph(OSINTWorkflowState)

    # Add nodes
    workflow.add_node("username_correlation", username_correlation_node)
    workflow.add_node("email_inference", email_pattern_inference_node)

    # Set entry point
    workflow.set_entry_point("username_correlation")

    # Add edges
    workflow.add_edge("username_correlation", "email_inference")
    workflow.add_edge("email_inference", END)

    return workflow.compile()
