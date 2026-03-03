"""
Arbiter - Commitment Schemes Module

Implements cryptographic commitment schemes for binding values
without revealing them until opening.

Commitment schemes provide:
- Hiding: Commitment reveals nothing about the value
- Binding: Cannot change the value after commitment

References:
- Pedersen Commitments: Pedersen (1991)
- Hash Commitments: Standard construction

Used in:
- Zero-knowledge proofs (commit to values before proving)
- Credential issuance (commit to revocation handler)
- Verifiable computation (commit to inputs/outputs)
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from arbiter.common.errors import CommitmentError
from arbiter.common.utils import sha256_hash, bytes_to_base58


# =============================================================================
# Constants
# =============================================================================

# Default prime for Pedersen commitments (256-bit safe prime placeholder)
# Production should use a proper elliptic curve group
DEFAULT_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DEFAULT_GENERATOR_G = 2
DEFAULT_GENERATOR_H = 3  # Must be chosen such that log_g(h) is unknown


# =============================================================================
# Hash-based Commitments
# =============================================================================

@dataclass(frozen=True)
class HashCommitment:
    """Simple hash-based commitment.
    
    Commitment = H(value || randomness)
    
    Properties:
    - Computationally hiding (under SHA-256)
    - Computationally binding (under SHA-256)
    
    Attributes:
        commitment: The commitment value
        randomness: Random blinding factor (needed to open)
    """
    commitment: bytes
    randomness: bytes


def hash_commit(
    value: bytes,
    randomness: Optional[bytes] = None,
) -> HashCommitment:
    """Create a hash-based commitment to a value.
    
    Args:
        value: The value to commit to
        randomness: Optional blinding factor (generated if not provided)
        
    Returns:
        HashCommitment with commitment and randomness
    """
    if randomness is None:
        randomness = secrets.token_bytes(32)

    # Commitment = SHA-256(randomness || value)
    # Put randomness first to prevent length extension attacks
    commitment = sha256_hash(randomness + value)

    return HashCommitment(commitment=commitment, randomness=randomness)


def hash_open(
    commitment: HashCommitment,
    value: bytes,
) -> bool:
    """Verify that a commitment opens to the claimed value.
    
    Args:
        commitment: The commitment to verify
        value: The claimed committed value
        
    Returns:
        True if commitment opens to value
    """
    expected = sha256_hash(commitment.randomness + value)
    return secrets.compare_digest(commitment.commitment, expected)


# =============================================================================
# Pedersen Commitments
# =============================================================================

@dataclass
class PedersenParams:
    """Public parameters for Pedersen commitments.
    
    These must be generated such that log_g(h) is unknown.
    
    Attributes:
        p: Prime modulus
        g: Generator 1
        h: Generator 2 (discrete log to g unknown)
    """
    p: int
    g: int
    h: int
    
    @classmethod
    def default(cls) -> "PedersenParams":
        """Get default parameters (for testing only)."""
        return cls(p=DEFAULT_PRIME, g=DEFAULT_GENERATOR_G, h=DEFAULT_GENERATOR_H)


@dataclass(frozen=True)
class PedersenCommitment:
    """Pedersen commitment (additively homomorphic).
    
    Commitment = g^value * h^randomness mod p
    
    Properties:
    - Information-theoretically hiding
    - Computationally binding (under discrete log)
    - Additively homomorphic: C(v1) * C(v2) = C(v1 + v2)
    
    Attributes:
        commitment: The commitment value (integer mod p)
        randomness: Blinding factor
        params_hash: Hash of parameters used (for verification)
    """
    commitment: int
    randomness: int
    params_hash: str


def pedersen_commit(
    value: int,
    params: Optional[PedersenParams] = None,
    randomness: Optional[int] = None,
) -> PedersenCommitment:
    """Create a Pedersen commitment to an integer value.
    
    Args:
        value: Integer value to commit to
        params: Pedersen parameters (uses default if not provided)
        randomness: Optional blinding factor
        
    Returns:
        PedersenCommitment
    """
    if params is None:
        params = PedersenParams.default()

    if randomness is None:
        randomness = secrets.randbelow(params.p - 1) + 1

    # C = g^v * h^r mod p
    commitment = (
        pow(params.g, value % (params.p - 1), params.p) *
        pow(params.h, randomness % (params.p - 1), params.p)
    ) % params.p

    # Hash params for later verification
    params_hash = bytes_to_base58(
        sha256_hash(
            params.p.to_bytes(32, "big") +
            params.g.to_bytes(32, "big") +
            params.h.to_bytes(32, "big")
        )[:8]
    )

    return PedersenCommitment(
        commitment=commitment,
        randomness=randomness,
        params_hash=params_hash,
    )


def pedersen_open(
    commitment: PedersenCommitment,
    value: int,
    params: Optional[PedersenParams] = None,
) -> bool:
    """Verify that a Pedersen commitment opens to the claimed value.
    
    Args:
        commitment: The Pedersen commitment
        value: The claimed value
        params: Pedersen parameters
        
    Returns:
        True if commitment opens to value
    """
    if params is None:
        params = PedersenParams.default()

    # Verify params match
    expected_hash = bytes_to_base58(
        sha256_hash(
            params.p.to_bytes(32, "big") +
            params.g.to_bytes(32, "big") +
            params.h.to_bytes(32, "big")
        )[:8]
    )
    if expected_hash != commitment.params_hash:
        return False

    # Recompute commitment
    expected = (
        pow(params.g, value % (params.p - 1), params.p) *
        pow(params.h, commitment.randomness % (params.p - 1), params.p)
    ) % params.p

    return commitment.commitment == expected


def pedersen_add(
    c1: PedersenCommitment,
    c2: PedersenCommitment,
    params: Optional[PedersenParams] = None,
) -> PedersenCommitment:
    """Add two Pedersen commitments (homomorphic).
    
    C(v1, r1) * C(v2, r2) = C(v1 + v2, r1 + r2)
    
    Args:
        c1: First commitment
        c2: Second commitment
        params: Pedersen parameters
        
    Returns:
        Combined commitment
        
    Raises:
        CommitmentError: If commitments use different parameters
    """
    if c1.params_hash != c2.params_hash:
        raise CommitmentError(
            "Cannot add commitments with different parameters",
            operation="add",
        )

    if params is None:
        params = PedersenParams.default()

    # Multiply commitment values (addition in exponent)
    new_commitment = (c1.commitment * c2.commitment) % params.p
    new_randomness = (c1.randomness + c2.randomness) % (params.p - 1)

    return PedersenCommitment(
        commitment=new_commitment,
        randomness=new_randomness,
        params_hash=c1.params_hash,
    )


def pedersen_scalar_multiply(
    commitment: PedersenCommitment,
    scalar: int,
    params: Optional[PedersenParams] = None,
) -> PedersenCommitment:
    """Multiply a Pedersen commitment by a scalar.
    
    C(v, r)^k = C(k*v, k*r)
    
    Args:
        commitment: Commitment to scale
        scalar: Scalar multiplier
        params: Pedersen parameters
        
    Returns:
        Scaled commitment
    """
    if params is None:
        params = PedersenParams.default()

    # Raise commitment to power of scalar
    new_commitment = pow(commitment.commitment, scalar, params.p)
    new_randomness = (commitment.randomness * scalar) % (params.p - 1)

    return PedersenCommitment(
        commitment=new_commitment,
        randomness=new_randomness,
        params_hash=commitment.params_hash,
    )


# =============================================================================
# Vector Commitments
# =============================================================================

@dataclass(frozen=True)
class VectorCommitment:
    """Commitment to a vector of values.
    
    Allows opening individual positions without revealing others.
    Based on Merkle tree structure.
    
    Attributes:
        root: Merkle root (the commitment)
        size: Number of elements in vector
    """
    root: bytes
    size: int


@dataclass(frozen=True)
class VectorOpening:
    """Opening proof for a specific position in a vector commitment."""
    index: int
    value: bytes
    proof: list[bytes]  # Merkle proof


class VectorCommitter:
    """Create and verify vector commitments.
    
    Uses a Merkle tree internally for efficient proofs.
    """

    def __init__(self) -> None:
        self._leaves: list[bytes] = []
        self._tree: list[list[bytes]] = []

    def commit(self, values: list[bytes]) -> VectorCommitment:
        """Create a commitment to a vector of values.
        
        Args:
            values: List of values to commit to
            
        Returns:
            VectorCommitment (Merkle root)
        """
        if not values:
            raise CommitmentError("Cannot commit to empty vector", operation="commit")

        # Pad to power of 2
        n = 1
        while n < len(values):
            n *= 2
        
        self._leaves = [self._hash_leaf(v) for v in values]
        while len(self._leaves) < n:
            self._leaves.append(self._hash_leaf(b""))

        # Build tree
        self._tree = [self._leaves]
        current = self._leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                next_level.append(self._hash_node(left, right))
            self._tree.append(next_level)
            current = next_level

        root = self._tree[-1][0]
        return VectorCommitment(root=root, size=len(values))

    def open(self, index: int, value: bytes) -> VectorOpening:
        """Create an opening proof for a position.
        
        Args:
            index: Position in the vector
            value: Value at that position
            
        Returns:
            VectorOpening with Merkle proof
        """
        if index >= len(self._leaves):
            raise CommitmentError(
                f"Index {index} out of range",
                operation="open",
            )

        # Build Merkle proof
        proof = []
        idx = index
        for level in self._tree[:-1]:
            sibling_idx = idx ^ 1  # XOR with 1 to get sibling
            if sibling_idx < len(level):
                proof.append(level[sibling_idx])
            idx //= 2

        return VectorOpening(index=index, value=value, proof=proof)

    def verify(
        self,
        commitment: VectorCommitment,
        opening: VectorOpening,
    ) -> bool:
        """Verify an opening proof.
        
        Args:
            commitment: The vector commitment
            opening: Opening proof for a position
            
        Returns:
            True if opening is valid
        """
        # Compute root from leaf and proof
        current = self._hash_leaf(opening.value)
        idx = opening.index

        for sibling in opening.proof:
            if idx % 2 == 0:
                current = self._hash_node(current, sibling)
            else:
                current = self._hash_node(sibling, current)
            idx //= 2

        return secrets.compare_digest(current, commitment.root)

    @staticmethod
    def _hash_leaf(value: bytes) -> bytes:
        """Hash a leaf value with domain separation."""
        return sha256_hash(b"\x00" + value)

    @staticmethod
    def _hash_node(left: bytes, right: bytes) -> bytes:
        """Hash two nodes with domain separation."""
        return sha256_hash(b"\x01" + left + right)


# =============================================================================
# Utility Functions
# =============================================================================

def generate_pedersen_params(seed: Optional[bytes] = None) -> PedersenParams:
    """Generate Pedersen commitment parameters.
    
    PLACEHOLDER: Simplified generation.
    Production should use proper group selection.
    
    Args:
        seed: Optional seed for deterministic generation
        
    Returns:
        PedersenParams with safe generators
    """
    if seed:
        rng = hashlib.shake_256(seed)
        g = int.from_bytes(rng.digest(32), "big") % DEFAULT_PRIME
        h = int.from_bytes(rng.digest(32), "big") % DEFAULT_PRIME
    else:
        g = DEFAULT_GENERATOR_G
        h = DEFAULT_GENERATOR_H

    return PedersenParams(p=DEFAULT_PRIME, g=g, h=h)
