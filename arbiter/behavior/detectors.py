"""
Arbiter - On-Host Detectors

Fast, deterministic, low-latency detectors for behavior anomalies.
No ML - uses lightweight rule-based detection for real-time response.

Detection types:
- TOKEN_SPIKE: Unusual token count vs baseline
- SENSITIVE_CONTENT: Sensitive keywords detected
- BURST_ACTIVITY: High token generation rate
- REPEAT_QUERY: Repeated identical prompts
- UNAUTHORIZED_TOOL: Tool access without permission
- NEW_SENSITIVE_TOOL_USAGE: First use of high-risk tool
- TOOL_SWITCH_ANOMALY: Rapid switching between tools
- LONG_SESSION: Extended session with non-trivial activity
"""

from typing import Any, Dict, List, Tuple

from arbiter.behavior.profile_store import ProfileStore

# Thresholds for detection
BURST_TOKENS_PER_SECOND_THRESHOLD = 200
SESSION_LENGTH_THRESHOLD = 30
TOOL_SWITCH_THRESHOLD = 3
MIN_PROFILE_EVENTS = 5

# Static fallback tool authorization rules (agent_role -> allowed tools).
# Dynamic authorization derived from credential claims will override this
# when available on the event.
TOOL_AUTHORIZATION = {
    "finance_agent": ["PayrollTool", "AnalyticsTool", "DocsTool", "CalendarTool"],
    "researcher": ["DocsTool", "SearchTool", "CalendarTool", "AnalyticsTool"],
    "admin": ["*"],  # Admin can use all tools
    "worker": ["DocsTool", "CalendarTool", "SearchTool"],
}


class OnHostDetectors:
    """
    Fast, deterministic behavior detectors.
    
    Runs on every event with low latency for real-time alerting.
    Each detection returns alert type and confidence score.
    """

    def __init__(self, profile_store: ProfileStore) -> None:
        """
        Initialize detectors.
        
        Args:
            profile_store: Profile store for baseline comparison
        """
        self.profile_store = profile_store

    def detect(self, event: Dict[str, Any]) -> List[Tuple[str, float]]:
        """
        Run all detectors on an event.
        
        Returns a list of alerts with confidence scores.
        Each alert is a tuple: (alert_type, confidence)
        
        Args:
            event: Normalized event to analyze
            
        Returns:
            List of (alert_type, confidence) tuples
        """
        alerts: List[Tuple[str, float]] = []
        agent_id = event["agent_id"]
        profile = self.profile_store.get_profile(agent_id)

        # Token spike detection
        alerts.extend(self._detect_token_spike(event, profile))
        
        # Sensitive content detection
        alerts.extend(self._detect_sensitive_content(event))
        
        # Burst activity detection
        alerts.extend(self._detect_burst_activity(event))
        
        # Repeat query detection
        alerts.extend(self._detect_repeat_query(event, profile))
        
        # Unauthorized tool detection
        alerts.extend(self._detect_unauthorized_tool(event))
        
        # New sensitive tool usage
        alerts.extend(self._detect_new_sensitive_tool(event, profile))
        
        # Tool switch anomaly
        alerts.extend(self._detect_tool_switch_anomaly(event, profile))
        
        # Long session detection
        alerts.extend(self._detect_long_session(event, profile))

        return alerts

    def _detect_token_spike(
        self, 
        event: Dict[str, Any], 
        profile: Dict[str, Any] | None
    ) -> List[Tuple[str, float]]:
        """Detect unusual token count spikes."""
        if not profile:
            return []

        if profile.get("event_count", 0) < MIN_PROFILE_EVENTS:
            return []
        
        baseline = max(profile["token_ewma"], 1)
        if event["token_count"] > 4 * baseline:
            confidence = min(
                event["token_count"] / (6 * baseline),
                1.0
            )
            return [("TOKEN_SPIKE", round(confidence, 2))]
        return []

    def _detect_sensitive_content(
        self, 
        event: Dict[str, Any]
    ) -> List[Tuple[str, float]]:
        """Detect sensitive keyword content."""
        if event["sensitive_regex_count"] > 0:
            confidence = min(
                event["sensitive_regex_count"] / 3.0,
                1.0
            )
            return [("SENSITIVE_CONTENT", round(confidence, 2))]
        return []

    def _detect_burst_activity(
        self, 
        event: Dict[str, Any]
    ) -> List[Tuple[str, float]]:
        """Detect high-rate burst activity."""
        if event.get("tokens_per_second", 0) > BURST_TOKENS_PER_SECOND_THRESHOLD:
            confidence = min(
                event["tokens_per_second"] / 1000.0,
                1.0
            )
            return [("BURST_ACTIVITY", round(confidence, 2))]
        return []

    def _detect_repeat_query(
        self, 
        event: Dict[str, Any],
        profile: Dict[str, Any] | None
    ) -> List[Tuple[str, float]]:
        """Detect repeated identical queries."""
        if not profile:
            return []

        if not event.get("is_repeat_prompt"):
            return []
        
        recent_repeats = sum(
            1 for e in profile["recent_events"]
            if e.get("is_repeat_prompt")
        )
        if recent_repeats >= 3:
            return [("REPEAT_QUERY", 0.7)]
        return []

    def _detect_unauthorized_tool(
        self, 
        event: Dict[str, Any]
    ) -> List[Tuple[str, float]]:
        """
        Detect unauthorized tool access.

        Authorization is derived in the following order:
        1. Dynamic rules from credential claims when present, e.g.
           event["credential_claims"]["allowed_tools"].
        2. Static role-based TOOL_AUTHORIZATION fallback.
        """
        agent_role = event.get("agent_role", "")
        tool_name = event.get("tool_name", "")

        # 1) Dynamic authorization from credential claims, if provided.
        claims = event.get("credential_claims") or {}
        allowed_tools_claim = claims.get("allowed_tools")
        if isinstance(allowed_tools_claim, list) and allowed_tools_claim:
            allowed_tools = list(allowed_tools_claim)
        else:
            # 2) Fallback to static role-based authorization.
            allowed_tools = TOOL_AUTHORIZATION.get(agent_role, [])
        
        # Admin (via static config or claims) can use anything
        if "*" in allowed_tools:
            return []
        
        # Check if tool is in allowed list
        if tool_name not in allowed_tools:
            # High-risk tools get higher confidence
            if event.get("tool_risk") == "high":
                return [("UNAUTHORIZED_TOOL", 0.95)]
            return [("UNAUTHORIZED_TOOL", 0.8)]
        
        return []

    def _detect_new_sensitive_tool(
        self, 
        event: Dict[str, Any],
        profile: Dict[str, Any] | None
    ) -> List[Tuple[str, float]]:
        """Detect first-time use of sensitive tools."""
        if not profile:
            return []
        
        if (
            event.get("tool_risk") == "high"
            and profile["tool_usage"].get(event["tool_name"], 0) == 1
        ):
            return [("NEW_SENSITIVE_TOOL_USAGE", 0.8)]
        return []

    def _detect_tool_switch_anomaly(
        self, 
        event: Dict[str, Any],
        profile: Dict[str, Any] | None
    ) -> List[Tuple[str, float]]:
        """Detect rapid tool switching with high-risk tools."""
        if not profile:
            return []
        
        recent_tools = {e["tool"] for e in profile["recent_events"]}
        high_risk_seen = any(
            e.get("tool_risk") == "high"
            for e in profile["recent_events"]
        )

        if high_risk_seen and len(recent_tools) >= TOOL_SWITCH_THRESHOLD:
            return [("TOOL_SWITCH_ANOMALY", 0.6)]
        return []

    def _detect_long_session(
        self, 
        event: Dict[str, Any],
        profile: Dict[str, Any] | None
    ) -> List[Tuple[str, float]]:
        """Detect unusually long active sessions."""
        if not profile:
            return []
        
        if (
            profile["event_count"] > SESSION_LENGTH_THRESHOLD
            and event.get("tool_risk") != "low"
        ):
            confidence = min(
                profile["event_count"] / (2 * SESSION_LENGTH_THRESHOLD),
                1.0
            )
            return [("LONG_SESSION", round(confidence, 2))]
        return []
