"""
Arbiter - Cryptographic Accumulators Module

Implements RSA-based cryptographic accumulators for efficient non-revocation proofs.
Accumulators allow:
- Adding elements to a set with constant-size representation
- Creating membership/non-membership witnesses
- Efficient batch updates for revocation

References:
- Benaloh & de Mare (1994): One-Way Accumulators
- Camenisch & Lysyanskaya (2002): Dynamic Accumulators
- Li, Li & Xue (2007): Universal Accumulators with Efficient Non-membership Proofs

Algorithm Mapping:
- Algorithm 1 (System Initialization): AccumulatorManager.__init__
- Algorithm 4 (Revocation): Accumulator.remove
- Algorithm 5 (Witness Update): Witness.update
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from arbiter.common.errors import AccumulatorError
from arbiter.common.utils import bytes_to_base58, sha256_hash


# =============================================================================
# Constants
# =============================================================================

# RSA modulus size for accumulator (bits)
RSA_BITS = 2048

# Default RSA modulus for testing (PLACEHOLDER)
# Production MUST use properly generated RSA modulus with unknown factorization
# This is a small test modulus - NOT SECURE
_TEST_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC5
_TEST_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43
DEFAULT_MODULUS = _TEST_P * _TEST_Q

# Generator for the accumulator (should be quadratic residue)
DEFAULT_GENERATOR = 65537


# =============================================================================
# Accumulator Structures
# =============================================================================

@dataclass
class AccumulatorPublicParams:
    """Public parameters for the accumulator.
    
    These parameters are generated once during system initialization
    and published for all parties to use.
    
    Attributes:
        modulus: RSA modulus n = p*q (p, q unknown to all)
        generator: Generator g, a quadratic residue mod n
        accumulator_id: Unique identifier for this accumulator
    """
    modulus: int
    generator: int
    accumulator_id: str = ""

    def __post_init__(self) -> None:
        if not self.accumulator_id:
            # Generate ID from parameters
            param_bytes = self.modulus.to_bytes(256, "big") + self.generator.to_bytes(32, "big")
            fingerprint = bytes_to_base58(sha256_hash(param_bytes)[:8])
            object.__setattr__(self, "accumulator_id", f"acc-{fingerprint}")


@dataclass
class AccumulatorState:
    """Current state of the accumulator.
    
    The accumulator value represents the entire set of
    non-revoked credentials in a single constant-size value.
    
    Attributes:
        value: Current accumulator value (g^(product of all elements) mod n)
        epoch: Version number (increments with each update)
        elements: Set of elements currently in the accumulator
    """
    value: int
    epoch: int = 0
    elements: Set[int] = field(default_factory=set)


@dataclass
class Witness:
    """Membership witness for an element in the accumulator.
    
    A witness allows proving that an element is (or was) in
    the accumulator without revealing the element itself.
    
    Implements Algorithm 2 (Credential Issuance) - witness generation
    and Algorithm 5 (Witness Update) - local update.
    
    Attributes:
        element: The element this witness is for
        witness_value: The witness value (accumulator without this element)
        epoch: Epoch when this witness was generated/updated
    """
    element: int
    witness_value: int
    epoch: int


# =============================================================================
# Accumulator Manager
# =============================================================================

class AccumulatorManager:
    """Manages a cryptographic accumulator for credential revocation.
    
    Implements Algorithm 1: System Initialization
    
    The accumulator allows efficient proofs of non-revocation:
    - Adding a credential: O(1) accumulator update
    - Revoking a credential: O(1) accumulator update
    - Proving non-revocation: O(1) witness verification
    
    Threat Model:
        The RSA modulus must be generated such that no party
        knows the factorization. In practice, use a trusted
        setup or distributed key generation.
    """

    def __init__(
        self,
        params: Optional[AccumulatorPublicParams] = None,
        initial_value: Optional[int] = None,
    ) -> None:
        """Initialize the accumulator manager.
        
        Algorithm 1: System Initialization
        - Generate RSA modulus n (or use provided)
        - Select generator g
        - Initialize accumulator to g
        
        Args:
            params: Public parameters (generated if not provided)
            initial_value: Initial accumulator value (defaults to generator)
        """
        if params is None:
            # PLACEHOLDER: Use test parameters
            # Production must use properly generated RSA modulus
            params = AccumulatorPublicParams(
                modulus=DEFAULT_MODULUS,
                generator=DEFAULT_GENERATOR,
            )

        self.params = params
        
        if initial_value is None:
            initial_value = params.generator
        
        self.state = AccumulatorState(
            value=initial_value,
            epoch=0,
            elements=set(),
        )
        
        # History for witness updates
        self._epoch_history: Dict[int, Tuple[int, Set[int], Set[int]]] = {}

    @property
    def current_value(self) -> int:
        """Get current accumulator value."""
        return self.state.value

    @property
    def current_epoch(self) -> int:
        """Get current epoch number."""
        return self.state.epoch

    def _hash_to_prime(self, element_bytes: bytes) -> int:
        """Hash element to a prime number.
        
        For security, accumulated elements must be prime.
        Uses repeated hashing until a prime is found.
        
        PLACEHOLDER: Uses simple primality test.
        Production should use cryptographically secure method.
        """
        candidate = int.from_bytes(sha256_hash(element_bytes), "big")
        # Ensure odd
        candidate |= 1
        
        # Simple primality check (PLACEHOLDER)
        # Real implementation should use Miller-Rabin
        while not self._is_probably_prime(candidate):
            candidate += 2
        
        return candidate

    def _is_probably_prime(self, n: int, k: int = 10) -> bool:
        """Miller-Rabin primality test.
        
        PLACEHOLDER: Simplified implementation.
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True

    def derive_element(self, handler_id: str) -> int:
        """Derive accumulator element from credential handler ID.
        
        Args:
            handler_id: Unique credential revocation handler
            
        Returns:
            Prime element for accumulator
        """
        return self._hash_to_prime(handler_id.encode())

    def add(self, element: int) -> Witness:
        """Add an element to the accumulator.
        
        Algorithm 2 (partial): Generate witness for new element
        
        Args:
            element: Prime element to add
            
        Returns:
            Witness for the added element
            
        Raises:
            AccumulatorError: If element already exists
        """
        if element in self.state.elements:
            raise AccumulatorError(
                f"Element already in accumulator",
                operation="add",
            )

        # Current value becomes the witness for new element
        witness = Witness(
            element=element,
            witness_value=self.state.value,
            epoch=self.state.epoch,
        )

        # Update accumulator: acc' = acc^element mod n
        old_value = self.state.value
        new_value = pow(self.state.value, element, self.params.modulus)
        
        # Record history for witness updates
        old_elements = self.state.elements.copy()
        self.state.elements.add(element)
        
        self.state = AccumulatorState(
            value=new_value,
            epoch=self.state.epoch + 1,
            elements=self.state.elements,
        )
        
        # Store epoch transition for witness updates
        self._epoch_history[self.state.epoch] = (
            old_value,
            {element},  # Added
            set(),  # Removed
        )

        return witness

    def remove(self, element: int) -> int:
        """Remove an element from the accumulator (revocation).
        
        Algorithm 4: Revocation
        - Remove element from accumulator
        - Publish new accumulator state
        
        This operation revokes a credential by removing its
        element from the accumulator. After removal:
        - Old witnesses for this element are invalid
        - Non-revocation proofs will fail
        
        Args:
            element: Prime element to remove
            
        Returns:
            New accumulator value
            
        Raises:
            AccumulatorError: If element not in accumulator
        """
        if element not in self.state.elements:
            raise AccumulatorError(
                "Element not in accumulator",
                operation="remove",
            )

        # To remove, we need the inverse of the element mod phi(n)
        # Since we don't know phi(n), we recompute from remaining elements
        # This is the PLACEHOLDER approach - real implementation needs
        # either the trapdoor or accumulated witnesses
        
        old_value = self.state.value
        self.state.elements.remove(element)
        
        # Recompute accumulator from scratch (PLACEHOLDER - inefficient)
        new_value = self.params.generator
        for e in self.state.elements:
            new_value = pow(new_value, e, self.params.modulus)
        
        self.state = AccumulatorState(
            value=new_value,
            epoch=self.state.epoch + 1,
            elements=self.state.elements,
        )
        
        # Store epoch transition
        self._epoch_history[self.state.epoch] = (
            old_value,
            set(),  # Added
            {element},  # Removed
        )

        return new_value

    def create_witness(self, element: int) -> Witness:
        """Create a membership witness for an element.
        
        The witness allows proving the element is in the accumulator
        without revealing which element it is.
        
        Args:
            element: Element to create witness for
            
        Returns:
            Membership witness
            
        Raises:
            AccumulatorError: If element not in accumulator
        """
        if element not in self.state.elements:
            raise AccumulatorError(
                "Element not in accumulator",
                operation="create_witness",
            )

        # Witness = accumulator with element removed
        # w = g^(product of all OTHER elements)
        witness_value = self.params.generator
        for e in self.state.elements:
            if e != element:
                witness_value = pow(witness_value, e, self.params.modulus)

        return Witness(
            element=element,
            witness_value=witness_value,
            epoch=self.state.epoch,
        )

    def verify_witness(self, witness: Witness) -> bool:
        """Verify a membership witness.
        
        Checks that w^element = accumulator mod n
        
        If the element was revoked, this will return False.
        
        Args:
            witness: Witness to verify
            
        Returns:
            True if witness is valid for current accumulator
        """
        # Compute w^element mod n
        computed = pow(witness.witness_value, witness.element, self.params.modulus)
        return computed == self.state.value

    def get_update_info(
        self,
        from_epoch: int,
        to_epoch: Optional[int] = None,
    ) -> Tuple[List[int], List[int]]:
        """Get accumulator updates between epochs.
        
        Used by credential holders to update their witnesses locally.
        
        Args:
            from_epoch: Starting epoch
            to_epoch: Ending epoch (defaults to current)
            
        Returns:
            Tuple of (added_elements, removed_elements)
        """
        if to_epoch is None:
            to_epoch = self.state.epoch

        added: List[int] = []
        removed: List[int] = []

        for epoch in range(from_epoch + 1, to_epoch + 1):
            if epoch in self._epoch_history:
                _, epoch_added, epoch_removed = self._epoch_history[epoch]
                added.extend(epoch_added)
                removed.extend(epoch_removed)

        return added, removed


def update_witness(
    witness: Witness,
    added_elements: List[int],
    removed_elements: List[int],
    params: AccumulatorPublicParams,
    new_epoch: int,
) -> Witness:
    """Update a witness for accumulator changes.
    
    Algorithm 5: Witness Update
    
    Allows credential holders to update their witnesses locally
    without contacting the issuer, based on published updates.
    
    For each added element e_add:
        w' = w^e_add mod n
    
    For removed elements, more complex (requires inverse).
    PLACEHOLDER: Simplified handling.
    
    Args:
        witness: Current witness
        added_elements: Elements added since witness epoch
        removed_elements: Elements removed since witness epoch
        params: Accumulator public parameters
        new_epoch: Target epoch after update
        
    Returns:
        Updated witness
        
    Raises:
        AccumulatorError: If update fails (e.g., own element was revoked)
    """
    # Check if our element was revoked
    if witness.element in removed_elements:
        raise AccumulatorError(
            "Cannot update witness: element was revoked",
            operation="witness_update",
        )

    new_witness_value = witness.witness_value

    # Update for added elements
    for added in added_elements:
        if added != witness.element:
            new_witness_value = pow(new_witness_value, added, params.modulus)

    # PLACEHOLDER: Removed elements handling
    # Real implementation requires extended Euclidean algorithm
    # and access to the removed elements' inverses

    return Witness(
        element=witness.element,
        witness_value=new_witness_value,
        epoch=new_epoch,
    )


# =============================================================================
# Non-Membership Proofs (for revocation checking)
# =============================================================================

@dataclass
class NonMembershipWitness:
    """Witness for proving an element is NOT in the accumulator.
    
    Used to prove that a specific credential handler has been revoked.
    """
    element: int
    witness_a: int
    witness_b: int
    epoch: int


def create_non_membership_proof(
    manager: AccumulatorManager,
    element: int,
) -> NonMembershipWitness:
    """Create a proof that element is NOT in the accumulator.
    
    PLACEHOLDER: Simplified non-membership witness.
    Real implementation uses Bezout coefficients.
    
    Args:
        manager: Accumulator manager
        element: Element to prove non-membership for
        
    Returns:
        Non-membership witness
        
    Raises:
        AccumulatorError: If element IS in accumulator
    """
    if element in manager.state.elements:
        raise AccumulatorError(
            "Element is in accumulator (cannot prove non-membership)",
            operation="non_membership_proof",
        )

    # PLACEHOLDER: Create fake witness
    # Real implementation computes (a, b) such that:
    # a*element + b*product(all_elements) = 1 (via extended GCD)
    witness_a = sha256_hash(str(element).encode())
    witness_b = sha256_hash(str(manager.state.value).encode())

    return NonMembershipWitness(
        element=element,
        witness_a=int.from_bytes(witness_a[:16], "big"),
        witness_b=int.from_bytes(witness_b[:16], "big"),
        epoch=manager.state.epoch,
    )
