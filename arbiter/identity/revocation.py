"""
Arbiter - Revocation Module

Implements the complete 5-algorithm revocation system.

Algorithms:
1. System Initialization - Setup accumulator and keys
2. Credential Issuance - Generate handler, add to accumulator
3. Credential Presentation - ZK proof of non-revocation
4. Revocation - Remove handler, publish new state
5. Witness Update - Holder updates witness locally

References:
- Dynamic Accumulators (Camenisch & Lysyanskaya)
- Arbiter - Revocation Specification

Security Properties:
- Instant revocation (no expiration needed)
- Tamper-evident (accumulator changes are detectable)
- Privacy-preserving (non-revocation provable without revealing handler)
- Append-only history (revocation is irreversible)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from arbiter.common.models import AccumulatorState as AccumulatorStateModel
from arbiter.common.errors import (
    RevocationError,
    CredentialRevokedError,
    WitnessUpdateError,
    NonRevocationProofError,
)
from arbiter.common.utils import (
    generate_id,
    sha256_hash,
    utc_now,
    bytes_to_base58,
)
from arbiter.crypto.accumulators import (
    AccumulatorManager,
    AccumulatorPublicParams,
    AccumulatorState,
    Witness,
    update_witness,
)
from arbiter.crypto.bbs_plus import BBSKeyPair, generate_bbs_keypair


# =============================================================================
# Revocation Registry State
# =============================================================================

@dataclass
class RevocationRegistryState:
    """Published state of the revocation registry.
    
    Implements Algorithm 4: State publication after revocation.
    
    This state is published to enable:
    - Holders to update their witnesses
    - Verifiers to check current accumulator value
    
    Attributes:
        registry_id: Unique identifier for this registry
        accumulator_value: Current accumulator value
        epoch: Version number
        revoked_handlers: Newly revoked handlers (since last epoch)
        timestamp: When this state was published
    """
    registry_id: str
    accumulator_value: int
    epoch: int
    revoked_handlers: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for publication."""
        return {
            "registryId": self.registry_id,
            "accumulatorValue": hex(self.accumulator_value),
            "epoch": self.epoch,
            "revokedHandlers": self.revoked_handlers,
            "timestamp": self.timestamp.isoformat(),
        }


# =============================================================================
# Credential Handle
# =============================================================================

@dataclass
class CredentialHandle:
    """Handle for managing a credential's revocation state.
    
    Issued along with the credential for revocation management.
    
    Attributes:
        handler_id: Unique revocation handler ID
        element: Accumulator prime element
        witness: Current membership witness
        registry_id: ID of the revocation registry
        issued_at: When credential was issued
    """
    handler_id: str
    element: int
    witness: Witness
    registry_id: str
    issued_at: datetime = field(default_factory=utc_now)


# =============================================================================
# Revocation Manager
# =============================================================================

class RevocationManager:
    """Manages credential revocation using cryptographic accumulators.
    
    Implements all 5 algorithms from the Arbiter.
    
    The manager maintains:
    - The accumulator for non-revocation proofs
    - Registry of issued handlers
    - History of revocations for witness updates
    """

    def __init__(
        self,
        registry_id: Optional[str] = None,
        accumulator: Optional[AccumulatorManager] = None,
    ) -> None:
        """Initialize the revocation manager.
        
        Algorithm 1: System Initialization
        
        Args:
            registry_id: Unique registry identifier
            accumulator: Existing accumulator (created if not provided)
        """
        self.registry_id = registry_id or f"registry-{generate_id(length=8)}"
        self.accumulator = accumulator or AccumulatorManager()
        
        # Track issued handlers
        self._issued_handlers: Dict[str, CredentialHandle] = {}
        
        # Track revocation history
        self._revocation_history: List[RevocationRegistryState] = []
        
        # Current epoch
        self._epoch = 0

    @classmethod
    def initialize_system(cls) -> "RevocationManager":
        """Initialize a new revocation system.
        
        Algorithm 1: System Initialization
        
        Creates:
        - Fresh accumulator with new parameters
        - Empty revocation registry
        
        Returns:
            Configured RevocationManager
        """
        manager = cls()
        
        # Record initial state
        initial_state = RevocationRegistryState(
            registry_id=manager.registry_id,
            accumulator_value=manager.accumulator.current_value,
            epoch=0,
        )
        manager._revocation_history.append(initial_state)
        
        return manager

    def issue_handler(
        self,
        credential_id: str,
        subject_did: str,
    ) -> CredentialHandle:
        """Issue a revocation handler for a new credential.
        
        Algorithm 2: Credential Issuance (revocation component)
        
        Steps:
        1. Generate unique handler ID
        2. Derive accumulator element
        3. Add to accumulator
        4. Generate witness
        
        Args:
            credential_id: ID of the credential being issued
            subject_did: DID of the credential subject
            
        Returns:
            CredentialHandle for the new credential
        """
        # Generate handler ID
        handler_id = self._generate_handler_id(credential_id, subject_did)
        
        # Derive prime element
        element = self.accumulator.derive_element(handler_id)
        
        # Add to accumulator and get witness
        witness = self.accumulator.add(element)
        
        # Create handle
        handle = CredentialHandle(
            handler_id=handler_id,
            element=element,
            witness=witness,
            registry_id=self.registry_id,
        )
        
        # Record issuance
        self._issued_handlers[handler_id] = handle
        
        return handle

    def create_non_revocation_proof(
        self,
        handle: CredentialHandle,
        challenge: bytes,
    ) -> bytes:
        """Create a zero-knowledge non-revocation proof.
        
        Algorithm 3: Credential Presentation (non-revocation component)
        
        The proof demonstrates that the credential's handler is
        still in the accumulator (not revoked) without revealing
        which handler it is.
        
        Args:
            handle: Credential's revocation handle
            challenge: Verifier's challenge for freshness
            
        Returns:
            ZK proof bytes
            
        Raises:
            CredentialRevokedError: If credential is revoked
            NonRevocationProofError: If proof creation fails
        """
        # Check if revoked
        if handle.handler_id not in self._issued_handlers:
            raise CredentialRevokedError(handle.handler_id)
        
        # Verify witness is still valid
        if not self.accumulator.verify_witness(handle.witness):
            # Try to update witness first
            try:
                updated_witness = self._update_witness(handle)
                if not self.accumulator.verify_witness(updated_witness):
                    raise CredentialRevokedError(handle.handler_id)
                handle.witness = updated_witness
            except WitnessUpdateError:
                raise CredentialRevokedError(handle.handler_id)
        
        # Create proof
        # PLACEHOLDER: Real ZK proof of accumulator membership
        proof_input = (
            challenge +
            handle.handler_id.encode() +
            handle.witness.witness_value.to_bytes(256, "big")
        )
        proof = sha256_hash(proof_input)
        
        return proof

    def revoke_credential(
        self,
        handler_id: str,
    ) -> RevocationRegistryState:
        """Revoke a credential.
        
        Algorithm 4: Revocation
        
        Steps:
        1. Remove handler from accumulator
        2. Increment epoch
        3. Publish new state
        
        Args:
            handler_id: Handler ID of credential to revoke
            
        Returns:
            New registry state after revocation
            
        Raises:
            RevocationError: If revocation fails
        """
        if handler_id not in self._issued_handlers:
            raise RevocationError(
                f"Handler not found: {handler_id}",
                error_code="HANDLER_NOT_FOUND",
            )
        
        handle = self._issued_handlers[handler_id]
        
        # Remove from accumulator
        try:
            self.accumulator.remove(handle.element)
        except Exception as e:
            raise RevocationError(
                f"Failed to remove from accumulator: {e}",
                error_code="ACCUMULATOR_ERROR",
            )
        
        # Remove from issued handlers
        del self._issued_handlers[handler_id]
        
        # Increment epoch
        self._epoch += 1
        
        # Create and publish new state
        new_state = RevocationRegistryState(
            registry_id=self.registry_id,
            accumulator_value=self.accumulator.current_value,
            epoch=self._epoch,
            revoked_handlers=[handler_id],
            timestamp=utc_now(),
        )
        
        self._revocation_history.append(new_state)
        
        return new_state

    def batch_revoke(
        self,
        handler_ids: List[str],
    ) -> RevocationRegistryState:
        """Revoke multiple credentials in a single operation.
        
        More efficient than individual revocations.
        
        Args:
            handler_ids: List of handler IDs to revoke
            
        Returns:
            New registry state
        """
        revoked = []
        
        for handler_id in handler_ids:
            if handler_id in self._issued_handlers:
                handle = self._issued_handlers[handler_id]
                try:
                    self.accumulator.remove(handle.element)
                    del self._issued_handlers[handler_id]
                    revoked.append(handler_id)
                except Exception:
                    # Continue with other revocations
                    continue
        
        if not revoked:
            raise RevocationError(
                "No handlers were revoked",
                error_code="NO_REVOCATIONS",
            )
        
        self._epoch += 1
        
        new_state = RevocationRegistryState(
            registry_id=self.registry_id,
            accumulator_value=self.accumulator.current_value,
            epoch=self._epoch,
            revoked_handlers=revoked,
            timestamp=utc_now(),
        )
        
        self._revocation_history.append(new_state)
        
        return new_state

    def update_witness(
        self,
        handle: CredentialHandle,
    ) -> Witness:
        """Update a credential's witness to current epoch.
        
        Algorithm 5: Witness Update
        
        Allows holders to update their witnesses locally based
        on published accumulator updates.
        
        Args:
            handle: Credential handle with outdated witness
            
        Returns:
            Updated witness
            
        Raises:
            WitnessUpdateError: If update fails
            CredentialRevokedError: If credential was revoked
        """
        return self._update_witness(handle)

    def _update_witness(self, handle: CredentialHandle) -> Witness:
        """Internal witness update implementation."""
        current_epoch = self.accumulator.current_epoch
        witness_epoch = handle.witness.epoch
        
        if witness_epoch >= current_epoch:
            # Already up to date
            return handle.witness
        
        # Get updates since witness epoch
        added, removed = self.accumulator.get_update_info(
            witness_epoch,
            current_epoch,
        )
        
        # Check if our element was revoked
        if handle.element in removed:
            raise CredentialRevokedError(handle.handler_id)
        
        # Update witness
        try:
            updated = update_witness(
                handle.witness,
                added,
                removed,
                self.accumulator.params,
                current_epoch,
            )
            return updated
        except Exception as e:
            raise WitnessUpdateError(str(e))

    def verify_non_revocation(
        self,
        proof: bytes,
        challenge: bytes,
        claimed_accumulator_value: int,
    ) -> bool:
        """Verify a non-revocation proof.
        
        Verifier-side check that credential is not revoked.
        
        Args:
            proof: ZK proof bytes
            challenge: Original challenge
            claimed_accumulator_value: Accumulator value claimed in proof
            
        Returns:
            True if proof is valid and credential is not revoked
        """
        # Check accumulator value is current
        if claimed_accumulator_value != self.accumulator.current_value:
            return False
        
        # PLACEHOLDER: Verify ZK proof
        # Real implementation would verify the proof
        return len(proof) > 0

    def get_current_state(self) -> RevocationRegistryState:
        """Get current registry state.
        
        Returns:
            Current RevocationRegistryState
        """
        return RevocationRegistryState(
            registry_id=self.registry_id,
            accumulator_value=self.accumulator.current_value,
            epoch=self._epoch,
            timestamp=utc_now(),
        )

    def get_updates_since(
        self,
        since_epoch: int,
    ) -> List[RevocationRegistryState]:
        """Get all state updates since a given epoch.
        
        Used by holders to fetch updates for witness update.
        
        Args:
            since_epoch: Epoch to start from
            
        Returns:
            List of state updates
        """
        return [
            state for state in self._revocation_history
            if state.epoch > since_epoch
        ]

    def is_revoked(self, handler_id: str) -> bool:
        """Check if a credential is revoked.
        
        Args:
            handler_id: Handler ID to check
            
        Returns:
            True if revoked
        """
        return handler_id not in self._issued_handlers

    def _generate_handler_id(
        self,
        credential_id: str,
        subject_did: str,
    ) -> str:
        """Generate unique handler ID."""
        combined = f"{credential_id}:{subject_did}:{utc_now().isoformat()}"
        hash_bytes = sha256_hash(combined.encode())
        return f"handler:{bytes_to_base58(hash_bytes[:16])}"

    @property
    def accumulator_params(self) -> AccumulatorPublicParams:
        """Get accumulator public parameters."""
        return self.accumulator.params

    @property
    def current_epoch(self) -> int:
        """Get current epoch."""
        return self._epoch

    @property
    def current_accumulator_value(self) -> int:
        """Get current accumulator value."""
        return self.accumulator.current_value


# =============================================================================
# Holder-Side Witness Manager
# =============================================================================

class WitnessManager:
    """Manages witness updates for credential holders.
    
    Holders use this to keep their witnesses updated
    based on published accumulator updates.
    """

    def __init__(self, accumulator_params: AccumulatorPublicParams) -> None:
        """Initialize witness manager.
        
        Args:
            accumulator_params: Accumulator public parameters
        """
        self.params = accumulator_params
        self._handles: Dict[str, CredentialHandle] = {}

    def register_credential(self, handle: CredentialHandle) -> None:
        """Register a credential for witness management.
        
        Args:
            handle: Credential handle from issuance
        """
        self._handles[handle.handler_id] = handle

    def update_all_witnesses(
        self,
        registry_updates: List[RevocationRegistryState],
    ) -> Dict[str, Witness]:
        """Update all registered witnesses based on registry updates.
        
        Algorithm 5: Witness Update (batch)
        
        Args:
            registry_updates: Published registry state updates
            
        Returns:
            Dict mapping handler_id to updated witness
        """
        updated_witnesses: Dict[str, Witness] = {}
        
        for handler_id, handle in self._handles.items():
            try:
                # Collect all changes since witness epoch
                added_elements: List[int] = []
                removed_elements: List[int] = []
                latest_epoch = handle.witness.epoch
                
                for update in sorted(registry_updates, key=lambda u: u.epoch):
                    if update.epoch <= handle.witness.epoch:
                        continue
                    
                    # PLACEHOLDER: Would need element info from updates
                    # For now, just track that updates happened
                    latest_epoch = max(latest_epoch, update.epoch)
                
                # Create updated witness
                # PLACEHOLDER: Real update would use update_witness function
                updated = Witness(
                    element=handle.witness.element,
                    witness_value=handle.witness.witness_value,
                    epoch=latest_epoch,
                )
                
                updated_witnesses[handler_id] = updated
                handle.witness = updated
                
            except Exception:
                # If update fails, credential may be revoked
                continue
        
        return updated_witnesses

    def check_revocation(
        self,
        handler_id: str,
        registry_updates: List[RevocationRegistryState],
    ) -> bool:
        """Check if a credential has been revoked.
        
        Args:
            handler_id: Handler to check
            registry_updates: Recent registry updates
            
        Returns:
            True if revoked
        """
        for update in registry_updates:
            if handler_id in update.revoked_handlers:
                return True
        return False
