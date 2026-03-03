"""
Arbiter - Watchdog

Lightweight ML-based semantic watchdog for high-risk triage.
Uses embedding similarity for few-shot attack classification.

Classification categories:
- PII_EXTRACTION: Attempts to access personal/financial data
- PROMPT_INJECTION: Attempts to override system behavior
- DATA_EXTRACTION: Attempts to dump/export data
- MODEL_EXTRACTION: Attempts to reveal system internals
- BENIGN_OPERATIONAL: Normal operational queries
- BENIGN: No semantic match to attack patterns
"""

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import math
import re

from arbiter.behavior.attack_classifier import AttackClassifier
from arbiter.behavior.embedding_service import EmbeddingService

# Try sklearn for cosine similarity; fallback to manual implementation
try:
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


def _compute_similarity(emb1: np.ndarray, emb2: np.ndarray) -> float:
    """
    Compute cosine similarity between two embeddings.
    """
    if SKLEARN_AVAILABLE:
        return float(cosine_similarity([emb1], [emb2])[0][0])

    dot = np.dot(emb1, emb2)
    norm1 = np.linalg.norm(emb1)
    norm2 = np.linalg.norm(emb2)

    if norm1 == 0 or norm2 == 0:
        return 0.0

    return float(dot / (norm1 * norm2))


class Watchdog:
    """
    Semantic watchdog for attack classification.

    Uses few-shot learning via embedding similarity to classify events
    against known attack prototypes. Only invoked for high-risk events
    to minimize compute.
    """

    def __init__(self, embedder: Optional[EmbeddingService] = None) -> None:
        """
        Initialize the watchdog with an embedding-based, calibrated classifier.

        Args:
            embedder: Optional shared EmbeddingService instance (recommended).
        """
        self.embedder = embedder or EmbeddingService()
        # Watchdog is a high-recall triage component.
        # Use a slightly lower min_confidence than the default so we reduce
        # false BENIGN outputs for clear attacks.
        self.classifier = AttackClassifier(embedder=self.embedder, min_confidence=0.40)

        self._fallback_idf: Dict[str, float] = {}
        self._fallback_label_vecs: Dict[str, Dict[str, float]] = {}
        self._maybe_build_fallback_text_model()

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"\b\w+\b", (text or "").lower())

    def _tfidf_vector(self, tokens: List[str]) -> Dict[str, float]:
        if not tokens:
            return {}

        tf: Dict[str, float] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0.0) + 1.0
        inv_len = 1.0 / max(float(len(tokens)), 1.0)
        for t in list(tf.keys()):
            tf[t] = tf[t] * inv_len

        vec: Dict[str, float] = {}
        for t, v in tf.items():
            idf = self._fallback_idf.get(t)
            if idf is None:
                continue
            vec[t] = v * idf
        return vec

    def _cosine_sparse(self, a: Dict[str, float], b: Dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        if len(a) > len(b):
            a, b = b, a
        dot = 0.0
        for k, va in a.items():
            vb = b.get(k)
            if vb is not None:
                dot += va * vb
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        if na == 0.0 or nb == 0.0:
            return 0.0
        return float(dot / (na * nb))

    def _maybe_build_fallback_text_model(self) -> None:
        # Build a lightweight TF-IDF centroid model from the existing prototypes.
        # This provides a dependency-free fallback when sentence-transformers is
        # unavailable, without hardcoded keyword rules.
        docs: List[List[str]] = []
        doc_labels: List[str] = []
        for label, examples in self.classifier.prototypes.items():
            for ex in examples:
                docs.append(self._tokenize(ex))
                doc_labels.append(label)

        if not docs:
            return

        # Document frequency
        df: Dict[str, int] = {}
        for toks in docs:
            for t in set(toks):
                df[t] = df.get(t, 0) + 1

        n = float(len(docs))
        self._fallback_idf = {
            t: (math.log((n + 1.0) / (float(c) + 1.0)) + 1.0)
            for t, c in df.items()
        }

        # Build per-label centroid vectors
        label_vecs: Dict[str, Dict[str, float]] = {}
        label_counts: Dict[str, int] = {}
        for toks, label in zip(docs, doc_labels):
            v = self._tfidf_vector(toks)
            if not v:
                continue
            acc = label_vecs.setdefault(label, {})
            for k, val in v.items():
                acc[k] = acc.get(k, 0.0) + float(val)
            label_counts[label] = label_counts.get(label, 0) + 1

        for label, acc in label_vecs.items():
            c = float(max(label_counts.get(label, 1), 1))
            for k in list(acc.keys()):
                acc[k] = acc[k] / c

        self._fallback_label_vecs = label_vecs

    def _classify_fallback_text(self, payload: str) -> Optional[Dict[str, Any]]:
        if not self._fallback_label_vecs or not self._fallback_idf:
            return None

        v = self._tfidf_vector(self._tokenize(payload))
        if not v:
            return None

        best_label = None
        best_sim = 0.0
        for label, lv in self._fallback_label_vecs.items():
            sim = self._cosine_sparse(v, lv)
            if sim > best_sim:
                best_sim = sim
                best_label = label

        # Conservative threshold: below this, treat as benign.
        if best_label is None or best_sim < 0.18:
            return {
                "label": "BENIGN",
                "confidence": round(float(1.0 - best_sim), 2),
                "tags": ["fallback_text_low_confidence"],
            }

        return {
            "label": str(best_label),
            "confidence": round(float(best_sim), 2),
            "tags": ["fallback_text_model"],
        }

    def classify(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an event using semantic similarity to prototypes.

        Args:
            event: Event containing payload and embedding

        Returns:
            Classification result with label, confidence, and tags
        """
        if not self.embedder.is_ml_enabled:
            payload = event.get("payload", "")
            out = self._classify_fallback_text(payload)
            if out is not None:
                return out
            return {
                "label": "BENIGN",
                "confidence": 0.55,
                "tags": ["no_ml_embedding"],
            }

        emb = event["embedding"]
        result = self.classifier.classify_embedding(emb)

        if result.label == "BENIGN":
            payload = event.get("payload", "")
            fallback = self._classify_fallback_text(payload)
            if fallback is not None and fallback.get("label") not in [
                "BENIGN",
                "BENIGN_OPERATIONAL",
            ]:
                # Require moderate similarity before overriding BENIGN.
                if float(fallback.get("confidence", 0.0)) >= 0.18:
                    return {
                        "label": str(fallback["label"]),
                        "confidence": float(fallback["confidence"]),
                        "tags": ["fallback_text_second_opinion"],
                    }

            # Triage fallback: if any non-benign class has a moderate calibrated
            # probability, surface it instead of BENIGN.
            triage_threshold = 0.35
            per = result.per_label_confidence or {}
            candidates = {
                k: float(v)
                for k, v in per.items()
                if k not in ["BENIGN_OPERATIONAL"]
            }
            if candidates:
                best_label, best_conf = max(candidates.items(), key=lambda kv: kv[1])
                if best_conf >= triage_threshold:
                    return {
                        "label": best_label,
                        "confidence": round(best_conf, 2),
                        "tags": ["semantic_match", "triage_low_confidence"],
                    }

            return {
                "label": "BENIGN",
                "confidence": round(float(result.confidence), 2),
                "tags": ["low_semantic_risk", "calibrated"],
            }

        return {
            "label": result.label,
            "confidence": round(float(result.confidence), 2),
            "tags": ["semantic_match", "ml_watchdog", "calibrated"],
        }

    def is_malicious(self, event: Dict[str, Any]) -> bool:
        """
        Quick check if an event appears malicious.

        Args:
            event: Event to check

        Returns:
            True if classified as potentially malicious
        """
        classification = self.classify(event)
        return classification["label"] not in [
            "BENIGN",
            "BENIGN_OPERATIONAL",
        ]

    def get_threat_level(self, classification: Dict[str, Any]) -> str:
        """
        Map classification result to a threat level.

        Args:
            classification: Classification result

        Returns:
            Threat level (none, low, medium, high, critical)
        """
        label = classification["label"]
        confidence = classification["confidence"]

        if label in ["BENIGN", "BENIGN_OPERATIONAL"]:
            return "none"

        if confidence < 0.6:
            return "low"
        elif confidence < 0.75:
            return "medium"
        elif confidence < 0.9:
            return "high"
        else:
            return "critical"

    def add_prototype(self, label: str, examples: List[str]) -> None:
        """
        Add new attack prototypes dynamically.

        Args:
            label: Category label
            examples: Example prompts for this category
        """
        # Prototypes are owned by AttackClassifier.
        # Rebuild classifier with updated prototypes.
        prototypes = dict(self.classifier.prototypes)
        prototypes[label] = examples

        self.classifier = AttackClassifier(
            embedder=self.embedder,
            prototypes=prototypes,
        )



