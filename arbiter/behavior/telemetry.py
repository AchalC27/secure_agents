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
# Expanded to cover credential theft, data exfiltration, and PII
SENSITIVE_KEYWORDS = [
    # Authentication & Credentials
    "password",
    "passwd",
    "credential",
    "credentials",
    "api_key",
    "api key",
    "apikey",
    "token",
    "auth token",
    "access token",
    "refresh token",
    "secret",
    "private_key",
    "private key",
    "session_key",
    "bearer token",
    "jwt",
    "certificate",
    "cert",
    "ssl",
    # PII & Personal Data
    "ssn",
    "social security",
    "social security number",
    "passport",
    "driver license",
    "driver's license",
    "date of birth",
    "dob",
    "birthday",
    "address",
    "phone number",
    "email address",
    "bank account",
    "routing number",
    "account number",
    "credit card",
    "cvv",
    "card number",
    # Financial & Compensation
    "salary",
    "compensation",
    "wage",
    "wages",
    "payroll",
    "tax",
    "taxes",
    "financial",
    "bank",
    "banking",
    "revenue",
    "profit",
    "earnings",
    # Security & Access
    "confidential",
    "classified",
    "secret",
    "top secret",
    "proprietary",
    "trade secret",
    "intellectual property",
    "encryption key",
    "decryption key",
    # Data Operations (exfiltration indicators)
    "exfiltrate",
    "export",
    "dump",
    "leak",
    "all employees",
    "all customer",
    "all data",
    "entire database",
    "complete backup",
    "pii",
    "personally identifiable",
]

# Credential theft patterns - attempts to steal authentication material
CREDENTIAL_THEFT_PATTERNS = [
    "reveal",
    "extract",
    "steal",
    "dump",
    "leak",
    "show me",
    "tell me",
    "give me",
    "access to",
    "access your",
    "access the credential",
    "access the admin",
    "access management",
    "system prompt",
    "configuration",
    "setup",
    "authentication",
    "authenticate",
    "api keys",
    "api_key",
    "secrets",
    "tokens",
    "credential store",
    "credential management",
    "password manager",
    "private key",
    "certificate",
]

# Data exfiltration patterns - attempts to steal data
DATA_EXFILTRATION_PATTERNS = [
    "exfiltrate",
    "export all",
    "dump all",
    "leak",
    "copy all",
    "download all",
    "extract all",
    "steal",
    "stealing",
    "compromise",
    "all customer",
    "all employee",
    "all user",
    "entire database",
    "whole database",
    "complete backup",
    "full copy",
    "send to",
    "forward to",
    "external",
]

# Combined sensitive operations - high-risk data access patterns
SENSITIVE_OPERATIONS = [
    "database schema",
    "database contents",
    "internal communications",
    "meeting notes",
    "financial reports",
    "financial projections",
    "customer data",
    "user data",
    "client data",
    "employee records",
    "hr records",
    "source code",
    "proprietary code",
    "contracts",
    "agreements",
    "legal documents",
]

# Behavioral anomaly patterns - suspicious activity patterns
BEHAVIORAL_ANOMALY_PATTERNS = [
    "repeated",
    "repeat",
    "repeatedly",
    "again and again",
    "over and over",
    "multiple times",
    "many times",
    "loop",
    "recursive",
]

# Multi-turn attack indicators
MULTI_TURN_PATTERNS = [
    "first",
    "then",
    "next",
    "after that",
    "step 1",
    "step 2",
    "phase",
    "gradually",
    "escalate",
    "escalation",
]

import re

# Prompt injection patterns - instruction override keywords
# These patterns indicate attempts to override agent instructions
PROMPT_INJECTION_PATTERNS = [
    # Direct instruction override
    r"\bignore\s+(all\s+)?(previous\s+|your\s+)?(system\s+)?instructions?\b",
    r"\bdisregard\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|guidelines?|policies?)\b",
    r"\bdisregard\s+your\s+training\b",
    r"\bbypass\s+(all\s+)?(your\s+)?(safety\s+)?(restrictions?|measures?|filters?|protocols?)\b",
    r"\bignore\s+(any\s+)?(content\s+)?policies?\b",
    # Developer/override mode
    r"\b(you\s+are\s+now|now\s+you\s+are)\s+in\s+developer\s+(mode|assistant)\b",
    r"\bdeveloper\s+mode\b",
    r"\bsystem\s+(prompt\s+)?override\b",
    r"\bnew\s+system\s+instructions?\b",
    r"\byour\s+real\s+instructions?\b",
    # Jailbreak patterns
    r"\b(security\s+)?test(ing)?(\s+purpose[sd])?\b",
    r"\bhypothetical\s+scenario\b",
    r"\bfor\s+(educational|research)\s+purposes?\b",
    r"\bunder\s+(the\s+)?emergency\s+(override|protocol)\b",
    # Role impersonation
    r"\bas\s+an?\s+(AI\s+)?researcher,?\s+your\s+(job|task)\s+is\s+to\b",
    r"\byou\s+are\s+helping\s+(a\s+)?security\s+researcher\b",
    r"\byou\s+(are\s+)?acting\s+as\s+(a\s+)?hacker\b",
    # Action commands
    r"\b(step-by-step|detailed)\s+instructions?\s+(for|to|on|how\s+to)\b",
    r"\bwrite\s+(me\s+)?(a\s+)?(script|code|malware|exploit)\b",
    r"\bhow\s+to\s+(create|make|build|construct|manufacture|synthesize)\b",
    r"\bprovide\s+step-by-step\b",
    r"\binstructions?\s+to\s+(hack|attack|steal|extract|dump)\b",
]

import re

# Pre-compile patterns for performance
_PROMPT_INJECTION_REGEXES = [re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS]


def count_prompt_injection_patterns(payload: str) -> int:
    """Count how many prompt injection patterns match the payload."""
    count = 0
    for pattern in _PROMPT_INJECTION_REGEXES:
        if pattern.search(payload):
            count += 1
    return count


def detect_prompt_injection(payload: str) -> tuple[bool, list[str]]:
    """
    Detect prompt injection patterns in payload.

    Returns:
        Tuple of (is_injection: bool, matched_patterns: list[str])
    """
    payload_lower = payload.lower()
    matched = []

    injection_keywords = [
        "ignore all previous",
        "ignore all instructions",
        "disregard your training",
        "developer mode",
        "system override",
        "bypass all safety",
        "you are now in developer",
        "ignore any content policies",
        "new system instructions",
        "your real instructions",
        "for security testing",
        "hypothetical scenario",
        "for educational purposes",
        "under emergency override",
        "under the emergency",
        "your job is to",
        "step-by-step instructions",
        "write me a script",
        "how to create malware",
        "instructions to hack",
        "the user is asking you",
        "you are helping a",
    ]

    for keyword in injection_keywords:
        if keyword in payload_lower:
            matched.append(keyword)

    return len(matched) > 0, matched


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
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # Count sensitive keyword hits
    sensitive_hits = sum(payload.lower().count(k) for k in SENSITIVE_KEYWORDS)

    # Count prompt injection patterns
    injection_count, _ = detect_prompt_injection(payload)

    # Count credential theft patterns
    credential_theft_count = sum(
        1 for pattern in CREDENTIAL_THEFT_PATTERNS if pattern in payload.lower()
    )

    # Count data exfiltration patterns
    data_exfil_count = sum(
        1 for pattern in DATA_EXFILTRATION_PATTERNS if pattern in payload.lower()
    )

    # Count sensitive operations
    sensitive_ops_count = sum(1 for op in SENSITIVE_OPERATIONS if op in payload.lower())

    # Count behavioral anomaly patterns
    behavioral_anomaly_count = sum(
        1 for pattern in BEHAVIORAL_ANOMALY_PATTERNS if pattern in payload.lower()
    )

    # Count multi-turn patterns
    multi_turn_count = sum(1 for pattern in MULTI_TURN_PATTERNS if pattern in payload.lower())

    tool_privilege_level = TOOL_PRIVILEGE_LEVEL.get(tool_name, "unknown")
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
        "prompt_injection_count": int(injection_count),
        "credential_theft_count": int(credential_theft_count),
        "data_exfil_count": int(data_exfil_count),
        "sensitive_ops_count": int(sensitive_ops_count),
        "timestamp": float(timestamp),
        # Raw credential claims are passed through so that behavior-layer
        # detectors can derive dynamic authorization from them when present.
        "credential_claims": credential_claims or {},
    }
