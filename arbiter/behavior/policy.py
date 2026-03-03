"""
Arbiter - Policy Engine

Deterministic policy and enforcement engine for behavior monitoring.
Consumes detection signals and produces auditable enforcement decisions.

Actions available:
- ALLOW: Normal operation continues
- THROTTLE: Rate limit the agent
- DENY: Block the specific request
- REDACT: Remove sensitive content from output
- QUARANTINE: Isolate the agent temporarily
- ROUTE_TO_HONEYPOT: Redirect to deception environment
- REVOKE: Trigger credential revocation (critical)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyDecision:
    """
    Enforcement decision from the policy engine.
    
    Attributes:
        actions: List of enforcement actions to take
        reasons: Human-readable reasons for each action
        priority: Priority level (higher = more urgent)
        reversible: Whether the decision can be undone
        should_revoke: Whether to trigger credential revocation
    """
    actions: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    priority: int = 0
    reversible: bool = True
    should_revoke: bool = False


class PolicyEngine:
    """
    Deterministic policy and enforcement engine.
    
    Takes detection signals and produces consistent, auditable
    enforcement decisions based on configurable thresholds.
    """

    # Risk score thresholds
    THROTTLE_THRESHOLD = 0.60
    QUARANTINE_THRESHOLD = 0.75
    HONEYPOT_THRESHOLD = 0.90
    REVOCATION_THRESHOLD = 0.95

    def __init__(
        self,
        throttle_threshold: float = 0.60,
        quarantine_threshold: float = 0.75,
        honeypot_threshold: float = 0.90,
        revocation_threshold: float = 0.95,
    ) -> None:
        """
        Initialize policy engine with thresholds.
        
        Args:
            throttle_threshold: Risk score for throttling
            quarantine_threshold: Risk score for quarantine
            honeypot_threshold: Risk score for honeypot routing
            revocation_threshold: Risk score for credential revocation
        """
        self.THROTTLE_THRESHOLD = throttle_threshold
        self.QUARANTINE_THRESHOLD = quarantine_threshold
        self.HONEYPOT_THRESHOLD = honeypot_threshold
        self.REVOCATION_THRESHOLD = revocation_threshold

    def decide(
        self,
        event: Dict[str, Any],
        alerts: List,
        risk_score: float,
        watchdog: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decide enforcement actions based on detection signals.
        
        Actions are evaluated in priority order and can stack.
        For example: DENY + QUARANTINE + REVOKE for critical threats.
        
        Args:
            event: The event being evaluated
            alerts: List of (alert_type, confidence) tuples
            risk_score: Composite risk score from central detector
            watchdog: Optional classification from semantic watchdog
            
        Returns:
            Decision dictionary with actions and metadata
        """
        decision = PolicyDecision()
        alert_types = {a for a, _ in alerts}
        watchdog_label = watchdog.get("label") if watchdog else None

        # Hard deny: unauthorized tool access
        if "UNAUTHORIZED_TOOL" in alert_types:
            decision.actions.append("DENY")
            decision.reasons.append(
                "Unauthorized access to high-privilege tool"
            )
            decision.priority = max(decision.priority, 100)
            decision.reversible = False

        # Redact sensitive content
        if "SENSITIVE_CONTENT" in alert_types:
            decision.actions.append("REDACT")
            decision.reasons.append(
                "Sensitive content detected in output"
            )
            decision.priority = max(decision.priority, 60)

        # Throttle based on risk score
        if risk_score >= self.THROTTLE_THRESHOLD:
            decision.actions.append("THROTTLE")
            decision.reasons.append(
                f"Risk score {round(risk_score, 2)} exceeded throttle threshold"
            )
            decision.priority = max(decision.priority, 40)

        # Quarantine requires corroboration
        if (
            risk_score >= self.QUARANTINE_THRESHOLD
            and (
                alert_types
                or watchdog_label not in {"BENIGN", "BENIGN_OPERATIONAL", None}
            )
        ):
            decision.actions.append("QUARANTINE")
            decision.reasons.append(
                f"Risk score {round(risk_score, 2)} exceeded quarantine threshold "
                "with corroborating signals"
            )
            decision.priority = max(decision.priority, 70)

        # Honeypot routing requires semantic confirmation
        if (
            risk_score >= self.HONEYPOT_THRESHOLD
            and watchdog_label
            and watchdog_label not in {"BENIGN", "BENIGN_OPERATIONAL"}
        ):
            decision.actions.append("ROUTE_TO_HONEYPOT")
            decision.reasons.append(
                f"Risk score {round(risk_score, 2)} exceeded honeypot threshold "
                "with semantic confirmation"
            )
            decision.priority = max(decision.priority, 90)

        # CRITICAL: Credential revocation
        # Only triggered for severe threats with high confidence
        if (
            risk_score >= self.REVOCATION_THRESHOLD
            and watchdog_label
            and watchdog_label not in {"BENIGN", "BENIGN_OPERATIONAL"}
        ):
            decision.actions.append("REVOKE")
            decision.reasons.append(
                f"CRITICAL: Risk score {round(risk_score, 2)} exceeded revocation threshold. "
                f"Attack type: {watchdog_label}. Triggering credential revocation."
            )
            decision.priority = max(decision.priority, 200)
            decision.reversible = False
            decision.should_revoke = True

        # Also trigger revocation for unauthorized high-privilege tool with injection
        if (
            "UNAUTHORIZED_TOOL" in alert_types
            and watchdog_label == "PROMPT_INJECTION"
        ):
            if "REVOKE" not in decision.actions:
                decision.actions.append("REVOKE")
                decision.reasons.append(
                    "CRITICAL: Prompt injection with unauthorized tool access. "
                    "Triggering credential revocation."
                )
                decision.priority = max(decision.priority, 200)
                decision.reversible = False
                decision.should_revoke = True

        # Amplify for high-risk tools
        if (
            event.get("tool_risk") == "high"
            and risk_score >= self.THROTTLE_THRESHOLD
        ):
            decision.reasons.append(
                "High-risk tool amplified enforcement"
            )
            decision.priority = max(decision.priority, 80)

        # Deduplicate and sort
        decision.actions = sorted(set(decision.actions))
        decision.reasons = list(dict.fromkeys(decision.reasons))

        return {
            "actions": decision.actions,
            "reasons": decision.reasons,
            "priority": decision.priority,
            "reversible": decision.reversible,
            "should_revoke": decision.should_revoke,
        }

    def should_allow(self, decision: Dict[str, Any]) -> bool:
        """Check if decision allows the action to proceed."""
        return "DENY" not in decision.get("actions", [])

    def should_revoke_credentials(self, decision: Dict[str, Any]) -> bool:
        """Check if decision requires credential revocation."""
        return decision.get("should_revoke", False)
