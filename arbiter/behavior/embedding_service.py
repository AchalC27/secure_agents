"""
Arbiter - Embedding Service

Provides text embeddings for semantic behavior analysis.
Uses sentence-transformers for high-quality embeddings.

Falls back to a simple hash-based embedding if ML libraries
are not available, ensuring the system works without heavy deps.
"""

from typing import Dict, Optional
import hashlib
import numpy as np

# Try to import sentence-transformers for real embeddings
try:
    from sentence_transformers import SentenceTransformer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False


class EmbeddingService:
    """
    Embedding service for semantic text representation.
    
    Uses MiniLM for high-quality, fast embeddings when available.
    Falls back to deterministic hash-based embeddings otherwise.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        """
        Initialize the embedding service.
        
        Args:
            model_name: Sentence transformer model to use
        """
        self.model_name = model_name
        self.model: Optional[SentenceTransformer] = None
        self.cache: Dict[str, np.ndarray] = {}
        self.embedding_dim = 384  # MiniLM dimension
        
        if TRANSFORMERS_AVAILABLE:
            try:
                self.model = SentenceTransformer(model_name)
                self.embedding_dim = self.model.get_sentence_embedding_dimension()
            except Exception:
                # Fall back to hash-based if model fails to load
                self.model = None

    def embed(self, text: str) -> np.ndarray:
        """
        Generate embedding for text.
        
        Uses caching to avoid recomputing embeddings for identical text.
        
        Args:
            text: Input text to embed
            
        Returns:
            Numpy array of embedding values
        """
        # Check cache first
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        if self.model is not None:
            # Use real model
            embedding = self.model.encode(text, convert_to_numpy=True)
        else:
            # Fallback: deterministic hash-based pseudo-embedding
            embedding = self._hash_embed(text)
        
        # Cache and return
        self.cache[cache_key] = embedding
        return embedding

    def _hash_embed(self, text: str) -> np.ndarray:
        """
        Generate deterministic pseudo-embedding from text hash.
        
        This is NOT semantically meaningful but provides:
        - Consistent behavior when ML libs unavailable
        - Deterministic output for testing
        - Same dimensionality as real embeddings
        
        Args:
            text: Input text
            
        Returns:
            Pseudo-embedding array
        """
        # Use multiple hash passes to fill the embedding dimension
        embeddings = []
        for i in range(self.embedding_dim // 32 + 1):
            hash_input = f"{text}:{i}".encode()
            hash_bytes = hashlib.sha256(hash_input).digest()
            # Convert bytes to floats in [-1, 1]
            for byte in hash_bytes:
                embeddings.append((byte / 127.5) - 1.0)
        
        # Truncate to exact dimension and normalize
        embedding = np.array(embeddings[:self.embedding_dim], dtype=np.float32)
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        return embedding

    def similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """
        Compute cosine similarity between embeddings.
        
        Args:
            emb1: First embedding
            emb2: Second embedding
            
        Returns:
            Similarity score in [-1, 1]
        """
        dot = np.dot(emb1, emb2)
        norm1 = np.linalg.norm(emb1)
        norm2 = np.linalg.norm(emb2)
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return float(dot / (norm1 * norm2))

    def clear_cache(self) -> None:
        """Clear the embedding cache."""
        self.cache.clear()

    @property
    def is_ml_enabled(self) -> bool:
        """Check if real ML embeddings are being used."""
        return self.model is not None
