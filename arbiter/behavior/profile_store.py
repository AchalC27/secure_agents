"""
Arbiter - Profile Store

Maintains per-agent behavioral baselines using exponential moving averages (EWMA).
No detection logic here - only statistics collection and computation.

The profile store tracks:
- Token usage patterns
- Tool usage patterns
- Semantic baseline (embedding centroid)
- Call rate patterns
- Recent event history
"""

import numpy as np
from collections import defaultdict, deque
from typing import Any, Dict, Optional, Deque


class ProfileStore:
    """
    Per-agent behavioral profile store.
    
    Uses exponential moving averages (EWMA) for adaptive baselines
    that respond to gradual behavior changes while detecting anomalies.
    """

    def __init__(self, alpha: float = 0.2, history_size: int = 20) -> None:
        """
        Initialize the profile store.
        
        Args:
            alpha: EWMA smoothing factor (0 < alpha < 1)
                   Higher values respond faster to changes
            history_size: Number of recent events to keep per agent
        """
        self.alpha = alpha
        self.history_size = history_size
        self.profiles: Dict[str, Dict[str, Any]] = {}

    def _init_profile(self) -> Dict[str, Any]:
        """Create a new empty profile."""
        return {
            "event_count": 0,
            "calls_ewma": 0.0,
            "last_event_ts": None,
            "token_ewma": 0.0,
            "token_sq_ewma": 0.0,
            "embedding_centroid": None,
            "embedding_sq_centroid": None,
            "tool_usage": defaultdict(int),
            "recent_events": deque(maxlen=self.history_size),
            # Additional tracking for behavior layer
            "first_seen_ts": None,
            "total_tokens": 0,
            "alerts_count": 0,
            "revocation_warnings": 0,
        }

    def update(self, agent_id: str, event: Dict[str, Any]) -> None:
        """
        Update agent profile using a normalized event.
        
        Uses EWMA for adaptive baselines that respond to gradual
        behavior changes while detecting sudden anomalies.
        
        Args:
            agent_id: Agent identifier
            event: Normalized event dictionary
        """
        profile = self.profiles.get(agent_id)
        if profile is None:
            profile = self._init_profile()

        now = event["timestamp"]
        token_count = event["token_count"]
        embedding = event["embedding"]
        tool = event["tool_name"]

        # Track first seen timestamp
        if profile["first_seen_ts"] is None:
            profile["first_seen_ts"] = now

        profile["event_count"] += 1
        profile["total_tokens"] += token_count

        # Call-rate EWMA: compute calls per minute from time delta
        if profile["last_event_ts"] is not None:
            delta_sec = max(now - profile["last_event_ts"], 1e-6)
            calls_per_min = 60.0 / delta_sec
        else:
            calls_per_min = 0.0

        profile["calls_ewma"] = (
            (1 - self.alpha) * profile["calls_ewma"]
            + self.alpha * calls_per_min
        )
        profile["last_event_ts"] = now

        # Token statistics: EWMA for mean, squared EWMA for variance
        profile["token_ewma"] = (
            (1 - self.alpha) * profile["token_ewma"]
            + self.alpha * token_count
        )

        profile["token_sq_ewma"] = (
            (1 - self.alpha) * profile["token_sq_ewma"]
            + self.alpha * (token_count ** 2)
        )

        # Semantic centroid: EWMA of embedding vectors
        if profile["embedding_centroid"] is None:
            profile["embedding_centroid"] = embedding.copy()
            profile["embedding_sq_centroid"] = embedding ** 2
        else:
            profile["embedding_centroid"] = (
                (1 - self.alpha) * profile["embedding_centroid"]
                + self.alpha * embedding
            )
            profile["embedding_sq_centroid"] = (
                (1 - self.alpha) * profile["embedding_sq_centroid"]
                + self.alpha * (embedding ** 2)
            )

        # Tool usage tracking
        profile["tool_usage"][tool] += 1

        # Recent events queue
        profile["recent_events"].append({
            "timestamp": now,
            "tool": tool,
            "token_count": token_count,
            "is_repeat_prompt": event.get("is_repeat_prompt", False),
            "tool_risk": event.get("tool_risk", "unknown"),
        })

        self.profiles[agent_id] = profile

    def get_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get agent profile.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Profile dictionary or None if not found
        """
        return self.profiles.get(agent_id)

    def token_variance(self, agent_id: str) -> float:
        """
        Compute token variance using E[X²] - E[X]² formula.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Token count variance
        """
        profile = self.get_profile(agent_id)
        if not profile or profile["event_count"] < 2:
            return 0.0
        mean = profile["token_ewma"]
        mean_sq = profile["token_sq_ewma"]
        return max(mean_sq - mean ** 2, 0.0)

    def embedding_variance(self, agent_id: str) -> float:
        """
        Approximate semantic dispersion using embedding variance.
        
        Higher variance indicates more diverse semantic behavior.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Mean embedding variance
        """
        profile = self.get_profile(agent_id)
        if not profile:
            return 0.0
        if profile["embedding_centroid"] is None:
            return 0.0
        if profile["embedding_sq_centroid"] is None:
            return 0.0
        
        mean = profile["embedding_centroid"]
        mean_sq = profile["embedding_sq_centroid"]
        variance = mean_sq - mean ** 2
        return float(np.mean(np.maximum(variance, 0.0)))

    def increment_alerts(self, agent_id: str) -> None:
        """Increment alert count for agent."""
        profile = self.profiles.get(agent_id)
        if profile:
            profile["alerts_count"] += 1

    def increment_revocation_warnings(self, agent_id: str) -> None:
        """Increment revocation warning count for agent."""
        profile = self.profiles.get(agent_id)
        if profile:
            profile["revocation_warnings"] += 1

    def get_all_agents(self) -> list[str]:
        """Get list of all agent IDs with profiles."""
        return list(self.profiles.keys())

    def clear(self) -> None:
        """Clear all profiles."""
        self.profiles.clear()

    def stats(self) -> Dict[str, Any]:
        """Get profile store statistics."""
        total_events = sum(
            p["event_count"] for p in self.profiles.values()
        )
        return {
            "total_agents": len(self.profiles),
            "total_events": total_events,
            "agents": list(self.profiles.keys()),
        }
