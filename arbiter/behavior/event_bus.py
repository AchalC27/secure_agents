"""
Arbiter - Event Bus

Normalizes and distributes telemetry events to detection pipelines.
Handles event enrichment with derived features like embeddings and risk scores.

The EventBus provides:
- Event normalization with schema versioning
- Automatic embedding generation
- Tool risk classification
- Repeat/duplicate detection
- Fan-out to multiple processing paths
"""

import hashlib
from collections import defaultdict
from typing import Dict, List, Any

from arbiter.behavior.embedding_service import EmbeddingService

# Event schema version for compatibility tracking
EVENT_SCHEMA_VERSION = "1.1"

# Tool risk classification map
TOOL_RISK_MAP = {
    # Low risk - read-only, informational
    "DocsTool": "low",
    "CalendarTool": "low",
    "SearchTool": "low",
    "HelpTool": "low",
    # Medium risk - some data access
    "AnalyticsTool": "medium",
    "DatabaseTool": "medium",
    "ReportTool": "medium",
    # High risk - sensitive operations
    "PayrollTool": "high",
    "AdminQuery": "high",
    "SystemTool": "high",
    "CredentialTool": "high",
    "DeleteTool": "high",
}


class EventBus:
    """
    Event bus for behavior monitoring.
    
    Normalizes raw telemetry into analysis-ready events and
    distributes them to fast-path and central detection paths.
    """

    def __init__(self) -> None:
        """Initialize the event bus."""
        self.embedding_service = EmbeddingService()
        
        # Processing paths
        self.fast_path: List[Dict[str, Any]] = []
        self.central_path: List[Dict[str, Any]] = []
        
        # Metrics
        self.embedding_cache_hits = 0
        self.embedding_cache_misses = 0
        self.total_events = 0
        
        # State tracking
        self._last_event_ts_per_session: Dict[str, float] = {}
        
        # Repeat detection per agent per session
        # Structure: { agent_id -> { session_id -> set(payload_hashes) } }
        self._recent_payload_hashes: Dict[str, Dict[str, set]] = defaultdict(
            lambda: defaultdict(set)
        )

    def normalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert raw telemetry into analysis-ready canonical event.
        
        Adds derived features:
        - tool_risk: Risk level of the tool
        - tokens_per_second: Rate of token generation
        - is_repeat_prompt: Whether this is a repeated prompt
        - embedding: Semantic embedding of payload
        - near_duplicate_hash: Hash for near-duplicate detection
        
        No detection logic here - purely normalization.
        
        Args:
            event: Raw telemetry event
            
        Returns:
            Normalized event with derived features
            
        Raises:
            ValueError: If required fields are missing
        """
        required = [
            "event_id", "agent_id", "agent_role",
            "session_id", "event_type", "tool_name",
            "payload", "payload_hash", "token_count",
            "timestamp"
        ]
        for r in required:
            if r not in event:
                raise ValueError(f"Missing required field: {r}")

        # Add schema version
        event["schema_version"] = EVENT_SCHEMA_VERSION
        
        # Add tool risk classification
        event["tool_risk"] = TOOL_RISK_MAP.get(
            event["tool_name"], "unknown"
        )

        # Compute tokens per second based on time delta
        session_id = event["session_id"]
        last_ts = self._last_event_ts_per_session.get(session_id)

        if last_ts is None:
            tokens_per_second = 0.0
        else:
            delta = max(event["timestamp"] - last_ts, 1e-6)
            tokens_per_second = event["token_count"] / delta

        self._last_event_ts_per_session[session_id] = event["timestamp"]
        event["tokens_per_second"] = float(tokens_per_second)

        # Repeat detection: same payload hash in this agent's session
        agent_id = event["agent_id"]
        payload_hash = event["payload_hash"]
        seen_hashes = self._recent_payload_hashes[agent_id][session_id]

        if payload_hash in seen_hashes:
            event["is_repeat_prompt"] = True
        else:
            event["is_repeat_prompt"] = False
            seen_hashes.add(payload_hash)

        # Near-duplicate hash (case-insensitive)
        event["near_duplicate_hash"] = hashlib.sha256(
            event["payload"].lower().encode("utf-8")
        ).hexdigest()[:16]

        # Generate embedding with cache tracking
        before_cache_size = len(self.embedding_service.cache)
        event["embedding"] = self.embedding_service.embed(
            event["payload"]
        )
        after_cache_size = len(self.embedding_service.cache)

        if after_cache_size > before_cache_size:
            self.embedding_cache_misses += 1
        else:
            self.embedding_cache_hits += 1

        self.total_events += 1
        return event

    def fan_out(self, event: Dict[str, Any]) -> None:
        """
        Distribute event to processing paths.
        
        Args:
            event: Normalized event to distribute
        """
        self.fast_path.append(event)
        self.central_path.append(event)

    def clear_paths(self) -> None:
        """Clear processing path queues."""
        self.fast_path.clear()
        self.central_path.clear()

    def reset(self) -> None:
        """Reset all state for fresh start."""
        self.fast_path.clear()
        self.central_path.clear()
        self._last_event_ts_per_session.clear()
        self._recent_payload_hashes.clear()
        self.embedding_service.clear_cache()
        self.embedding_cache_hits = 0
        self.embedding_cache_misses = 0
        self.total_events = 0

    def stats(self) -> Dict[str, Any]:
        """
        Get event bus statistics.
        
        Returns:
            Dictionary with processing metrics
        """
        cache_total = self.embedding_cache_hits + self.embedding_cache_misses
        hit_rate = (
            self.embedding_cache_hits / cache_total
            if cache_total > 0 else 0.0
        )
        return {
            "total_events": self.total_events,
            "fast_path_queue": len(self.fast_path),
            "central_path_queue": len(self.central_path),
            "embedding_cache_size": len(self.embedding_service.cache),
            "embedding_cache_hit_rate": round(hit_rate, 3),
            "ml_embeddings_enabled": self.embedding_service.is_ml_enabled,
        }
