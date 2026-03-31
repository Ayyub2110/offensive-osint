"""
Reconnaissance Stop Decision Agent for workflow control.

This agent analyzes reconnaissance progress and determines when to stop
the recon phase. It prevents endless loops by detecting diminishing returns,
duplicate intelligence, and convergence to stable state.

OFFENSIVE SECURITY USE CASES:
    - Efficient resource allocation (stop when no new value)
    - Prevent detection via excessive scanning
    - Time-boxed reconnaissance operations
    - Automatic transition to exploitation phase

DECISION STRATEGY: Stop when marginal gains don't justify continued recon
"""

from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum


class DecisionType(Enum):
    """Recon decision types."""
    CONTINUE = "continue"
    STOP = "stop"


@dataclass
class StopCondition:
    """
    Condition that contributes to stop decision.
    
    Attributes:
        condition_type: Type of condition
        met: Whether condition is met
        score: Severity score (0-100, higher = stronger stop signal)
        description: Human-readable description
        evidence: Supporting evidence
    """
    condition_type: str
    met: bool
    score: int
    description: str
    evidence: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ReconDecision:
    """
    Reconnaissance stop/continue decision.
    
    Attributes:
        decision: CONTINUE or STOP
        confidence: Decision confidence (0.0-1.0)
        primary_reason: Main reason for decision
        stop_conditions: List of conditions evaluated
        recommendations: Recommendations for next steps
        metadata: Additional metadata
        timestamp: Decision timestamp
    """
    decision: DecisionType
    confidence: float
    primary_reason: str
    stop_conditions: List[StopCondition]
    recommendations: List[str]
    metadata: Dict[str, Any]
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['decision'] = self.decision.value
        data['stop_conditions'] = [c.to_dict() for c in self.stop_conditions]
        return data


class ReconStopDecisionAgent:
    """
    Reconnaissance stop decision agent for workflow control.
    
    This agent prevents endless reconnaissance loops by evaluating:
        - Asset discovery rate (diminishing returns)
        - Score thresholds (low-value targets only)
        - Duplicate intelligence detection
        - Time/iteration limits
        - Risk vs. reward assessment
    
    STOP CONDITIONS:
        1. No new assets discovered in last N iterations
        2. All discovered assets below exploitability threshold
        3. High percentage of duplicate/redundant findings
        4. Maximum iteration limit reached
        5. Time limit exceeded
        6. Risk level too high (detection probability)
    
    CONTINUE CONDITIONS:
        1. New high-value assets still being discovered
        2. Recent assets have high exploitability scores
        3. Coverage gaps still exist
        4. Within time/iteration budget
    
    Attributes:
        min_new_assets: Minimum new assets to continue
        score_threshold: Minimum average score to continue
        duplicate_threshold: Maximum duplicate percentage to continue
        max_iterations: Maximum recon iterations
        max_time_seconds: Maximum recon time in seconds
    """
    
    def __init__(
        self,
        min_new_assets: int = 3,
        score_threshold: float = 30.0,
        duplicate_threshold: float = 70.0,
        max_iterations: int = 10,
        max_time_seconds: int = 3600
    ):
        """
        Initialize the Recon Stop Decision Agent.
        
        Args:
            min_new_assets: Minimum new assets per iteration to continue
            score_threshold: Minimum average exploitability score to continue
            duplicate_threshold: Stop if duplicates exceed this percentage
            max_iterations: Hard limit on recon iterations
            max_time_seconds: Hard time limit for recon phase
        """
        self.min_new_assets = min_new_assets
        self.score_threshold = score_threshold
        self.duplicate_threshold = duplicate_threshold
        self.max_iterations = max_iterations
        self.max_time_seconds = max_time_seconds
    
    def _check_new_asset_condition(
        self,
        current_assets: List[Any],
        previous_assets: List[Any]
    ) -> StopCondition:
        """
        Check if sufficient new assets are being discovered.
        
        DIMINISHING RETURNS: If no new assets, recon is exhausted.
        
        Args:
            current_assets: Current asset list
            previous_assets: Previous iteration asset list
            
        Returns:
            StopCondition for new asset discovery
        """
        # Extract asset identifiers
        current_ids = set()
        for asset in current_assets:
            if isinstance(asset, dict):
                current_ids.add(asset.get("asset", str(asset)))
            else:
                current_ids.add(str(asset))
        
        previous_ids = set()
        for asset in previous_assets:
            if isinstance(asset, dict):
                previous_ids.add(asset.get("asset", str(asset)))
            else:
                previous_ids.add(str(asset))
        
        new_assets = current_ids - previous_ids
        new_asset_count = len(new_assets)
        
        # Determine if condition is met (should stop)
        should_stop = new_asset_count < self.min_new_assets
        
        if should_stop:
            score = min(100, (self.min_new_assets - new_asset_count) * 30)
            description = f"Only {new_asset_count} new assets found (minimum: {self.min_new_assets})"
            evidence = "Reconnaissance has reached diminishing returns"
        else:
            score = 0
            description = f"{new_asset_count} new assets discovered (healthy progress)"
            evidence = "Continue discovering new targets"
        
        return StopCondition(
            condition_type="new_asset_rate",
            met=should_stop,
            score=score,
            description=description,
            evidence=evidence
        )
    
    def _check_score_threshold_condition(
        self,
        prioritized_assets: Optional[Dict[str, Any]] = None
    ) -> StopCondition:
        """
        Check if recent assets meet exploitability score threshold.
        
        LOW-VALUE TARGETS: If only low-score targets remain, stop recon.
        
        Args:
            prioritized_assets: Prioritization results
            
        Returns:
            StopCondition for score threshold
        """
        if not prioritized_assets:
            return StopCondition(
                condition_type="score_threshold",
                met=False,
                score=0,
                description="No prioritization data available",
                evidence="Cannot evaluate score threshold"
            )
        
        ranked_assets = prioritized_assets.get("ranked_assets", [])
        
        if not ranked_assets:
            return StopCondition(
                condition_type="score_threshold",
                met=True,
                score=80,
                description="No assets to prioritize",
                evidence="Empty asset list indicates recon completion"
            )
        
        # Calculate average score of recent assets (top 10 or all if less)
        recent_assets = ranked_assets[:10]
        scores = [asset.get("total_score", 0) for asset in recent_assets]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        # Check if average is below threshold
        should_stop = avg_score < self.score_threshold
        
        if should_stop:
            score = min(100, int((self.score_threshold - avg_score) * 2))
            description = f"Average exploitability score {avg_score:.1f} below threshold {self.score_threshold}"
            evidence = "Only low-value targets remaining - not worth continued recon"
        else:
            score = 0
            description = f"Average exploitability score {avg_score:.1f} exceeds threshold"
            evidence = "High-value targets still being discovered"
        
        return StopCondition(
            condition_type="score_threshold",
            met=should_stop,
            score=score,
            description=description,
            evidence=evidence
        )
    
    def _check_duplicate_condition(
        self,
        current_iteration: int,
        state_history: List[Dict[str, Any]]
    ) -> StopCondition:
        """
        Check for duplicate/redundant intelligence.
        
        REDUNDANCY: If seeing mostly duplicates, coverage is complete.
        
        Args:
            current_iteration: Current iteration number
            state_history: History of state snapshots
            
        Returns:
            StopCondition for duplicate detection
        """
        if len(state_history) < 2:
            return StopCondition(
                condition_type="duplicate_intelligence",
                met=False,
                score=0,
                description="Insufficient history to detect duplicates",
                evidence="Continue gathering intelligence"
            )
        
        # Compare last two states
        current_state = state_history[-1]
        previous_state = state_history[-2]
        
        # Extract assets from both states
        current_assets = self._extract_assets_from_state(current_state)
        previous_assets = self._extract_assets_from_state(previous_state)
        
        if not current_assets:
            return StopCondition(
                condition_type="duplicate_intelligence",
                met=False,
                score=0,
                description="No assets in current state",
                evidence="N/A"
            )
        
        # Calculate overlap
        current_set = set(current_assets)
        previous_set = set(previous_assets)
        
        overlap = current_set & previous_set
        duplicate_percentage = (len(overlap) / len(current_set)) * 100 if current_set else 0
        
        should_stop = duplicate_percentage >= self.duplicate_threshold
        
        if should_stop:
            score = min(100, int(duplicate_percentage))
            description = f"{duplicate_percentage:.1f}% duplicate intelligence (threshold: {self.duplicate_threshold}%)"
            evidence = "Reconnaissance has converged - seeing same targets repeatedly"
        else:
            score = 0
            description = f"{duplicate_percentage:.1f}% overlap with previous iteration"
            evidence = "Still discovering new unique targets"
        
        return StopCondition(
            condition_type="duplicate_intelligence",
            met=should_stop,
            score=score,
            description=description,
            evidence=evidence
        )
    
    def _check_iteration_limit_condition(
        self,
        current_iteration: int
    ) -> StopCondition:
        """
        Check if iteration limit is reached.
        
        HARD LIMIT: Prevent infinite loops.
        
        Args:
            current_iteration: Current iteration number
            
        Returns:
            StopCondition for iteration limit
        """
        should_stop = current_iteration >= self.max_iterations
        
        if should_stop:
            score = 100
            description = f"Reached maximum iterations ({current_iteration}/{self.max_iterations})"
            evidence = "Hard limit reached - must stop to prevent infinite loop"
        else:
            score = 0
            description = f"Iteration {current_iteration}/{self.max_iterations}"
            evidence = f"{self.max_iterations - current_iteration} iterations remaining"
        
        return StopCondition(
            condition_type="iteration_limit",
            met=should_stop,
            score=score,
            description=description,
            evidence=evidence
        )
    
    def _check_time_limit_condition(
        self,
        start_time: Optional[datetime] = None
    ) -> StopCondition:
        """
        Check if time limit is exceeded.
        
        OPERATIONAL CONSTRAINT: Time-boxed operations.
        
        Args:
            start_time: Recon start timestamp
            
        Returns:
            StopCondition for time limit
        """
        if not start_time:
            return StopCondition(
                condition_type="time_limit",
                met=False,
                score=0,
                description="No start time provided",
                evidence="Cannot evaluate time limit"
            )
        
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        
        elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
        should_stop = elapsed_seconds >= self.max_time_seconds
        
        if should_stop:
            score = 100
            description = f"Time limit exceeded ({elapsed_seconds:.0f}s / {self.max_time_seconds}s)"
            evidence = "Operational time constraint reached"
        else:
            score = 0
            remaining = self.max_time_seconds - elapsed_seconds
            description = f"Time elapsed: {elapsed_seconds:.0f}s / {self.max_time_seconds}s"
            evidence = f"{remaining:.0f}s remaining"
        
        return StopCondition(
            condition_type="time_limit",
            met=should_stop,
            score=score,
            description=description,
            evidence=evidence
        )
    
    def _extract_assets_from_state(self, state: Dict[str, Any]) -> List[str]:
        """
        Extract asset identifiers from state.
        
        Args:
            state: Workflow state
            
        Returns:
            List of asset identifier strings
        """
        assets = []
        
        # Check asset_discovery
        if "asset_discovery" in state:
            asset_data = state["asset_discovery"]
            if isinstance(asset_data, dict):
                asset_list = asset_data.get("assets", [])
                for asset in asset_list:
                    if isinstance(asset, dict):
                        assets.append(asset.get("asset", ""))
                    else:
                        assets.append(str(asset))
        
        # Check prioritization
        if "attack_surface_prioritization" in state:
            priority_data = state["attack_surface_prioritization"]
            if isinstance(priority_data, dict):
                ranked = priority_data.get("ranked_assets", [])
                for asset in ranked:
                    if isinstance(asset, dict):
                        assets.append(asset.get("asset", ""))
        
        return [a for a in assets if a]
    
    def _calculate_decision_confidence(
        self,
        stop_conditions: List[StopCondition]
    ) -> float:
        """
        Calculate confidence in the decision.
        
        Args:
            stop_conditions: List of evaluated conditions
            
        Returns:
            Confidence score (0.0-1.0)
        """
        if not stop_conditions:
            return 0.5
        
        # Count how many stop conditions are met
        met_conditions = [c for c in stop_conditions if c.met]
        total_conditions = len(stop_conditions)
        
        # Base confidence on percentage of conditions agreeing
        agreement_ratio = len(met_conditions) / total_conditions
        
        # Weight by severity scores
        total_score = sum(c.score for c in met_conditions)
        max_possible_score = total_conditions * 100
        
        score_ratio = total_score / max_possible_score if max_possible_score > 0 else 0
        
        # Combine agreement and score
        confidence = (agreement_ratio * 0.6) + (score_ratio * 0.4)
        
        return round(confidence, 2)
    
    def decide(
        self,
        current_iteration: int,
        current_state: Dict[str, Any],
        previous_state: Optional[Dict[str, Any]] = None,
        state_history: Optional[List[Dict[str, Any]]] = None,
        start_time: Optional[str] = None
    ) -> ReconDecision:
        """
        Make a decision on whether to continue or stop reconnaissance.
        
        DECISION LOGIC:
            - Evaluate all stop conditions
            - STOP if any critical condition is met (iteration/time limit)
            - STOP if majority of conditions suggest stopping
            - CONTINUE otherwise
        
        Args:
            current_iteration: Current iteration number
            current_state: Current workflow state
            previous_state: Previous iteration state (optional)
            state_history: Full state history (optional)
            start_time: Recon start timestamp (ISO format)
            
        Returns:
            ReconDecision with recommendation and reasoning
        """
        stop_conditions = []
        
        # Evaluate iteration limit (critical)
        iteration_condition = self._check_iteration_limit_condition(current_iteration)
        stop_conditions.append(iteration_condition)
        
        # Evaluate time limit (critical)
        time_condition = self._check_time_limit_condition(start_time)
        stop_conditions.append(time_condition)
        
        # Evaluate new asset discovery
        if previous_state:
            current_assets = self._extract_assets_from_state(current_state)
            previous_assets = self._extract_assets_from_state(previous_state)
            new_asset_condition = self._check_new_asset_condition(
                current_assets,
                previous_assets
            )
            stop_conditions.append(new_asset_condition)
        
        # Evaluate score threshold
        prioritization = current_state.get("attack_surface_prioritization")
        score_condition = self._check_score_threshold_condition(prioritization)
        stop_conditions.append(score_condition)
        
        # Evaluate duplicates
        if state_history and len(state_history) >= 2:
            duplicate_condition = self._check_duplicate_condition(
                current_iteration,
                state_history
            )
            stop_conditions.append(duplicate_condition)
        
        # Make decision
        # STOP if any critical condition is met
        critical_conditions = [iteration_condition, time_condition]
        critical_stop = any(c.met for c in critical_conditions)
        
        # Or if majority of non-critical conditions suggest stopping
        non_critical = [c for c in stop_conditions if c not in critical_conditions]
        non_critical_stop = sum(1 for c in non_critical if c.met) > len(non_critical) / 2
        
        should_stop = critical_stop or non_critical_stop
        
        # Determine decision
        if should_stop:
            decision = DecisionType.STOP
            met_conditions = [c for c in stop_conditions if c.met]
            
            # Primary reason is highest scoring met condition
            primary_condition = max(met_conditions, key=lambda c: c.score)
            primary_reason = primary_condition.description
            
            recommendations = [
                "Transition to exploitation phase",
                "Analyze prioritized targets",
                "Begin attack execution on highest-priority assets",
            ]
        else:
            decision = DecisionType.CONTINUE
            primary_reason = "High-value targets still being discovered with acceptable progress"
            
            recommendations = [
                "Continue reconnaissance for additional assets",
                "Expand subdomain enumeration depth",
                "Check for additional sensitive endpoints",
            ]
        
        # Calculate confidence
        confidence = self._calculate_decision_confidence(stop_conditions)
        
        # Build metadata
        metadata = {
            "iteration": current_iteration,
            "conditions_evaluated": len(stop_conditions),
            "conditions_met": sum(1 for c in stop_conditions if c.met),
            "critical_stop": critical_stop,
            "non_critical_stop": non_critical_stop,
        }
        
        return ReconDecision(
            decision=decision,
            confidence=confidence,
            primary_reason=primary_reason,
            stop_conditions=stop_conditions,
            recommendations=recommendations,
            metadata=metadata
        )
    
    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute recon stop decision based on workflow state.
        
        Args:
            state: Current workflow state
            
        Returns:
            Updated state with decision
        """
        # Extract iteration info from state
        current_iteration = state.get("iteration", 1)
        
        # Get state history if available
        state_history = state.get("state_history", [])
        previous_state = state_history[-1] if state_history else None
        
        # Get start time
        start_time = state.get("start_time") or state.get("metadata", {}).get("start_time")
        
        # Make decision
        decision = self.decide(
            current_iteration=current_iteration,
            current_state=state,
            previous_state=previous_state,
            state_history=state_history if len(state_history) >= 2 else None,
            start_time=start_time
        )
        
        # Update state
        state["recon_decision"] = decision.to_dict()
        state["should_continue_recon"] = (decision.decision == DecisionType.CONTINUE)
        
        return state
