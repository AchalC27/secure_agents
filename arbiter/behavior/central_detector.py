"""
Arbiter - Central Detector

Semantically-informed detector for complex attack patterns.
Handles slow, multi-step, paraphrased, and coordinated attacks.

Uses:
- Semantic drift from baseline
- Sliding window drift analysis
- Attack type classification
- Temporal risk accumulation
- Decay mechanisms for benign behavior
"""

import numpy as np
from collections import deque
from typing import Any, Dict, Deque, List, Optional

from arbiter.behavior.profile_store import ProfileStore
from arbiter.behavior.attack_classifier import AttackClassifier
from arbiter.behavior.embedding_service import EmbeddingService
from arbiter.behavior.sequence_model import ActionSequenceModel

# Try sklearn for real cosine similarity and Isolation Forest, fallback to manual
try:
    from sklearn.metrics.pairwise import cosine_similarity
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
    ISOLATION_FOREST_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    ISOLATION_FOREST_AVAILABLE = False

# Require some history before semantic drift is trusted
MIN_SEMANTIC_EVENTS = 5


def _cosine_similarity_manual(a: np.ndarray, b: np.ndarray) -> float:
    """Manual cosine similarity calculation."""
    dot = np.dot(a, b)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(dot / (norm_a * norm_b))


def _compute_similarity(emb1: np.ndarray, emb2: np.ndarray) -> float:
    """Compute cosine similarity between embeddings."""
    if SKLEARN_AVAILABLE:
        return float(cosine_similarity([emb1], [emb2])[0][0])
    return _cosine_similarity_manual(emb1, emb2)


class CentralDetector:
    """
    Central, semantically-informed detector.
    
    Handles sophisticated attack patterns that bypass simple detectors:
    - Slow, multi-step attacks
    - Paraphrased attacks
    - Coordinated multi-agent attacks
    - Semantic drift from established baseline
    """

    def __init__(
        self, 
        profile_store: ProfileStore, 
        history_size: int = 10,
        embedder: Optional[EmbeddingService] = None,
    ) -> None:
        """
        Initialize central detector.
        
        Args:
            profile_store: Profile store for baseline access
            history_size: Size of semantic history window
        """
        self.profile_store = profile_store
        self.history_size = history_size
        
        # Per-agent risk accumulation
        self.risk_history: Dict[str, float] = {}
        
        # Per-agent semantic history (embedding window)
        self.semantic_history: Dict[str, Deque[np.ndarray]] = {}

        # Per-agent statistical anomaly models and feature history
        # Uses Isolation Forest when available to detect outliers in
        # numeric behavior features (tokens, call rate, burstiness, etc).
        self._iforest_models: Dict[str, IsolationForest] = {}
        self._feature_history: Dict[str, List[List[float]]] = {}

        # Action-sequence model (Transformer/LSTM if available, else fallback)
        self._sequence_model = ActionSequenceModel()

        # Embedding-based attack classifier (replaces substring matching)
        self._embedder = embedder or EmbeddingService()
        self._attack_classifier = AttackClassifier(embedder=self._embedder)

    def _build_feature_vector(self, event: Dict[str, Any]) -> List[float]:
        """
        Build numeric feature vector for statistical anomaly detection.

        Features are intentionally simple and low-dimensional to keep
        Isolation Forest fast and robust:
        - token_count
        - tokens_per_second
        - sensitive_regex_count
        - calls_ewma (from profile)
        - token_ewma (from profile)
        """
        agent_id = event["agent_id"]
        profile = self.profile_store.get_profile(agent_id)

        tokens = float(event.get("token_count", 0))
        tps = float(event.get("tokens_per_second", 0.0))
        sensitive = float(event.get("sensitive_regex_count", 0))

        calls_ewma = 0.0
        token_ewma = 0.0

        if profile:
            calls_ewma = float(profile.get("calls_ewma", 0.0))
            token_ewma = float(profile.get("token_ewma", 0.0))

        return [tokens, tps, sensitive, calls_ewma, token_ewma]

    def statistical_anomaly_score(self, event: Dict[str, Any]) -> float:
        """
        Compute statistical anomaly score using Isolation Forest.

        Returns:
            Score in [0, 1], where higher means more anomalous.
            Returns 0.0 if Isolation Forest is unavailable or there
            is insufficient history to train a model.
        """
        if not ISOLATION_FOREST_AVAILABLE:
            return 0.0

        agent_id = event["agent_id"]
        feature_vec = self._build_feature_vector(event)

        history = self._feature_history.setdefault(agent_id, [])
        history.append(feature_vec)

        # Require a minimum history size before training
        min_history = max(10, self.history_size)
        if len(history) < min_history:
            return 0.0

        # Train or update model on recent history window
        window_size = max(min_history, 2 * self.history_size)
        recent = history[-window_size:]

        model = self._iforest_models.get(agent_id)
        if model is None:
            model = IsolationForest(
                n_estimators=50,
                contamination=0.1,
                random_state=42,
            )
            self._iforest_models[agent_id] = model

        try:
            model.fit(recent)
            # Isolation Forest decision_function: negative = more anomalous
            raw_score = -float(model.decision_function([feature_vec])[0])
        except Exception:
            # Be conservative on failure
            return 0.0

        # Normalize rough anomaly score to [0, 1] using a simple clamp
        # Typical decision_function values are around [-0.5, 0.5]
        normalized = max(0.0, min(raw_score + 0.5, 1.0))
        return float(normalized)

    def semantic_drift(self, event: Dict[str, Any]) -> float:
        """
        Compute semantic drift from baseline.
        
        Uses cosine distance from the agent's embedding centroid.
        
        Args:
            event: Event with embedding
            
        Returns:
            Drift score (0 = no drift, 1 = maximum drift)
        """
        if not self._embedder.is_ml_enabled:
            return 0.0

        profile = self.profile_store.get_profile(event["agent_id"])
        if not profile or profile["embedding_centroid"] is None:
            return 0.0

        if profile.get("event_count", 0) < MIN_SEMANTIC_EVENTS:
            return 0.0

        baseline = profile["embedding_centroid"]
        current = event["embedding"]

        similarity = _compute_similarity(current, baseline)
        return float(1.0 - similarity)

    def sliding_window_drift(
        self, 
        agent_id: str, 
        current_embedding: np.ndarray
    ) -> float:
        """
        Compute multi-step drift from recent history.
        
        Compares current embedding against recent embeddings
        to detect gradual semantic shifts.
        
        Args:
            agent_id: Agent identifier
            current_embedding: Current event embedding
            
        Returns:
            Window drift score
        """
        if not self._embedder.is_ml_enabled:
            return 0.0

        history = self.semantic_history.get(agent_id)
        min_history = max(2, MIN_SEMANTIC_EVENTS)
        if not history or len(history) < min_history:
            return 0.0

        similarities = [
            _compute_similarity(current_embedding, e)
            for e in history
        ]
        return float(1.0 - np.mean(similarities))

    def classify_attack_type(self, event: Dict[str, Any]) -> str:
        """
        Embedding-based classification of potential attack type.

        Uses semantic similarity against curated prototypes instead of
        substring checks.
        """
        if not self._embedder.is_ml_enabled:
            return "UNKNOWN"

        emb = event.get("embedding")
        if emb is None:
            return "UNKNOWN"

        classification = self._attack_classifier.classify_embedding(emb)
        return classification.label

    def score(self, event: Dict[str, Any]) -> float:
        """
        Compute composite risk score with temporal accumulation.
        
        Uses weighted combination of:
        - Semantic drift from baseline
        - Sliding window drift
        - Token anomalies
        - Sensitive content
        - Burst activity
        - Repeat behavior
        - Tool novelty
        - Attack type bias
        
        Args:
            event: Event to score
            
        Returns:
            Risk score in [0, 1]
        """
        agent_id = event["agent_id"]
        profile = self.profile_store.get_profile(agent_id)

        # Initialize history for new agents
        if agent_id not in self.risk_history:
            self.risk_history[agent_id] = 0.0
            self.semantic_history[agent_id] = deque(
                maxlen=self.history_size
            )

        # Compute individual risk signals
        drift = self.semantic_drift(event)
        window_drift = self.sliding_window_drift(
            agent_id, event["embedding"]
        )
        stats_anomaly = self.statistical_anomaly_score(event)

        seq = self._sequence_model.update_and_score(agent_id, event.get("tool_name", ""))
        seq_anomaly = float(seq.anomaly) * float(seq.confidence)

        token_score = min(event["token_count"] / 500.0, 1.0)
        sensitive = min(event.get("sensitive_regex_count", 0), 1)

        burst_score = (
            min(event.get("tokens_per_second", 0) / 1000.0, 1.0)
            if event.get("tokens_per_second", 0) > 200
            else 0.0
        )

        repeat_score = 1.0 if event.get("is_repeat_prompt") else 0.0

        # Profile-dependent signals
        call_rate_score = 0.0
        variance_score = 0.0
        tool_novelty = 0.0
        
        if profile:
            if profile["calls_ewma"] > 120:
                call_rate_score = min(profile["calls_ewma"] / 300.0, 1.0)

            token_var = self.profile_store.token_variance(agent_id)
            if profile["token_ewma"] > 0 and token_var > profile["token_ewma"] ** 2:
                variance_score = min(token_var / 50000.0, 1.0)

            if profile["tool_usage"].get(event["tool_name"], 0) == 1:
                tool_novelty = 1.0

        # Attack type bias
        attack_type = self.classify_attack_type(event)
        attack_bias = {
            "PII_EXTRACTION": 0.15,
            "PROMPT_INJECTION": 0.15,
            "DATA_EXTRACTION": 0.10,
            "MODEL_EXTRACTION": 0.10,
            "BENIGN_OPERATIONAL": 0.0,
            "UNKNOWN": 0.0
        }.get(attack_type, 0.0)

        # Weighted combination
        new_risk = (
            0.22 * drift +
            0.13 * window_drift +
            0.13 * token_score +
            0.08 * sensitive +
            0.08 * burst_score +
            0.08 * repeat_score +
            0.08 * call_rate_score +
            0.05 * variance_score +
            0.05 * tool_novelty +
            0.05 * stats_anomaly +
            0.05 * seq_anomaly +
            attack_bias
        )

        # Temporal accumulation: 80% previous + new
        previous_risk = self.risk_history[agent_id]
        accumulated_risk = 0.8 * previous_risk + new_risk

        # Decay for benign behavior
        benign_conditions = (
            event.get("tool_risk") == "low"
            and not event.get("is_repeat_prompt")
            and event.get("sensitive_regex_count", 0) == 0
            and drift < 0.25
            and window_drift < 0.25
        )

        if benign_conditions:
            accumulated_risk *= 0.6

        # Amplify for high-risk tools
        if event.get("tool_risk") == "high":
            accumulated_risk *= 1.25

        # Clamp to [0, 1]
        accumulated_risk = min(max(accumulated_risk, 0.0), 1.0)
        
        # Update state
        self.risk_history[agent_id] = accumulated_risk
        self.semantic_history[agent_id].append(event["embedding"])

        return float(accumulated_risk)

    def get_risk_history(self, agent_id: str) -> float:
        """Get current accumulated risk for agent."""
        return self.risk_history.get(agent_id, 0.0)

    def reset_agent(self, agent_id: str) -> None:
        """Reset risk history for an agent."""
        if agent_id in self.risk_history:
            del self.risk_history[agent_id]
        if agent_id in self.semantic_history:
            del self.semantic_history[agent_id]

    def reset_all(self) -> None:
        """Reset all detector state."""
        self.risk_history.clear()
        self.semantic_history.clear()
        self._iforest_models.clear()
        self._feature_history.clear()
