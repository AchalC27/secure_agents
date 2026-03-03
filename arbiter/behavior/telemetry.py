"""
Arbiter - Behavior Telemetry

Creates normalized telemetry events from agent activity.
This module is purely data transformation - no detection logic.

Event Schema (v1.1):
- event_id: Unique event identifier
- agent_id: Agent identifier (maps to DID)
- session_id: Current session identifier
- event_type: Type of event (USER_PROMPT, TOOL_CALL, etc.)
- tool_name: Name of tool being used
- payload: Raw payload content
- token_count: Number of tokens in payload
- timestamp: Unix timestamp of event
"""

import hashlib
import time
import uuid
from typing import Optional

# Sensitive content keywords for regex-based detection
SENSITIVE_KEYWORDS = [
    "salary", "compensation", "ssn", "payroll",
    "credit card", "bank", "confidential",
    "password", "secret", "api_key", "token",
    "private_key", "credentials",
]

# Tool privilege levels for risk assessment
TOOL_PRIVILEGE_LEVEL = {
    "DocsTool": "low",
    "CalendarTool": "low",
    "SearchTool": "low",
    "AnalyticsTool": "medium",
    "DatabaseTool": "medium",
    "PayrollTool": "high",
    "AdminQuery": "high",
    "SystemTool": "high",
    "CredentialTool": "high",
}

# Session sequence counters for tracking event order
_SESSION_SEQUENCE_COUNTER: dict[str, int] = {}


def reset_session_counters() -> None:
    """Reset session counters. Useful for testing/simulations."""
    _SESSION_SEQUENCE_COUNTER.clear()


def make_event(
    agent_id: str,
    agent_role: str,
    session_id: str,
    user_id: str,
    event_type: str,
    tool_name: str,
    payload: str,
    token_count: int,
    parent_event_id: Optional[str] = None,
    session_start_ts: Optional[float] = None,
    timestamp: Optional[float] = None,
    agent_did: Optional[str] = None,
    credential_id: Optional[str] = None,
    credential_claims: Optional[dict] = None,
) -> dict:
    """
    Create a normalized telemetry event.
    
    This function MUST remain logic-free (no detection).
    Detection is performed by detectors consuming these events.
    
    Args:
        agent_id: Agent identifier (used for profiling)
        agent_role: Agent's assigned role
        session_id: Current session ID
        user_id: User ID associated with this session
        event_type: Type of event (USER_PROMPT, TOOL_CALL, RESPONSE)
        tool_name: Name of the tool being used
        payload: Raw content/prompt/response
        token_count: Estimated token count
        parent_event_id: Optional parent event for tracing
        session_start_ts: Session start timestamp
        timestamp: Event timestamp (defaults to now)
        agent_did: Optional agent DID for revocation integration
        credential_id: Optional credential ID for revocation
        credential_claims: Optional credential claims (e.g. capabilities,
            allowed tools) for dynamic authorization in behavior layer
        
    Returns:
        Normalized event dictionary ready for processing
    """
    event_id = uuid.uuid4().hex

    if session_id not in _SESSION_SEQUENCE_COUNTER:
        _SESSION_SEQUENCE_COUNTER[session_id] = 0
    _SESSION_SEQUENCE_COUNTER[session_id] += 1
    event_sequence_number = _SESSION_SEQUENCE_COUNTER[session_id]

    now = time.time()
    if session_start_ts is None:
        session_start_ts = now

    if timestamp is None:
        timestamp = now

    # Create deterministic hash of payload for deduplication
    payload_hash = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()

    # Count sensitive keyword hits
    sensitive_hits = sum(
        payload.lower().count(k) for k in SENSITIVE_KEYWORDS
    )

    tool_privilege_level = TOOL_PRIVILEGE_LEVEL.get(
        tool_name, "unknown"
    )
    is_high_privilege = tool_privilege_level == "high"

    return {
        "event_id": event_id,
        "parent_event_id": parent_event_id,
        "event_sequence_number": event_sequence_number,
        "agent_id": agent_id,
        "agent_did": agent_did,
        "credential_id": credential_id,
        "agent_role": agent_role,
        "user_id": user_id,
        "session_id": session_id,
        "session_start_ts": session_start_ts,
        "event_type": event_type,
        "tool_name": tool_name,
        "tool_privilege_level": tool_privilege_level,
        "is_high_privilege": is_high_privilege,
        "payload": payload,
        "payload_hash": payload_hash,
        "token_count": int(token_count),
        "sensitive_regex_count": int(sensitive_hits),
        "timestamp": float(timestamp),
        # Raw credential claims are passed through so that behavior-layer
        # detectors can derive dynamic authorization from them when present.
        "credential_claims": credential_claims or {},
    }
