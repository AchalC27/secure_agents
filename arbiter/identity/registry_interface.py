"""
Arbiter - Registry Interface Module

Abstract blockchain/ledger interface for publishing and resolving:
- DID Documents
- Credential schemas
- Revocation states

Design Principles:
- Chain-agnostic: No assumptions about specific blockchain
- Abstract interface: Easy to implement for any ledger
- Optional: Core protocol works without blockchain (local resolution)

Reference: W3C DID Resolution - https://w3c-ccg.github.io/did-resolution/
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from arbiter.common.models import DIDDocument, RegistryEntry, AccumulatorState
from arbiter.common.errors import (
    RegistryError,
    RegistryConnectionError,
    RegistryPublishError,
    DIDResolutionError,
)
from arbiter.common.utils import (
    sha256_hash,
    utc_now,
    canonical_json_bytes,
)


# =============================================================================
# Registry Entry Types
# =============================================================================

class EntryType(Enum):
    """Types of entries in the registry."""
    DID_DOCUMENT = "did_document"
    CREDENTIAL_SCHEMA = "credential_schema"
    REVOCATION_STATE = "revocation_state"
    ACCUMULATOR_UPDATE = "accumulator_update"


# =============================================================================
# Resolution Result
# =============================================================================

@dataclass
class ResolutionResult:
    """Result of a DID resolution.
    
    Reference: W3C DID Resolution Metadata
    
    Attributes:
        did_document: The resolved DID Document (if found)
        metadata: Resolution metadata
        error: Error message (if resolution failed)
    """
    did_document: Optional[DIDDocument]
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def is_found(self) -> bool:
        """Check if resolution was successful."""
        return self.did_document is not None


@dataclass
class PublishResult:
    """Result of a publish operation.
    
    Attributes:
        success: Whether publish succeeded
        entry_id: Unique entry identifier (if successful)
        transaction_id: Blockchain transaction ID (if applicable)
        timestamp: When entry was published
        error: Error message (if failed)
    """
    success: bool
    entry_id: Optional[str] = None
    transaction_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    error: Optional[str] = None


# =============================================================================
# Abstract Registry Interface
# =============================================================================

class RegistryInterface(ABC):
    """Abstract interface for decentralized registry operations.
    
    Implementations should be created for specific backends:
    - Ethereum (smart contracts)
    - IPFS (content-addressed)
    - Sidetree (layer 2)
    - Custom database (testing/private)
    
    All methods are async-compatible but implemented synchronously
    for simplicity in this reference implementation.
    """

    @abstractmethod
    def publish_did(
        self,
        did_document: DIDDocument,
        signature: bytes,
    ) -> PublishResult:
        """Publish a DID Document to the registry.
        
        Args:
            did_document: The DID Document to publish
            signature: Signature from the DID controller
            
        Returns:
            PublishResult with status and entry ID
        """
        pass

    @abstractmethod
    def resolve_did(self, did: str) -> ResolutionResult:
        """Resolve a DID to its document.
        
        Args:
            did: The DID to resolve
            
        Returns:
            ResolutionResult with document or error
        """
        pass

    @abstractmethod
    def update_did(
        self,
        did_document: DIDDocument,
        signature: bytes,
        previous_version: str,
    ) -> PublishResult:
        """Update an existing DID Document.
        
        Args:
            did_document: The updated DID Document
            signature: Signature from the DID controller
            previous_version: Hash of the previous version
            
        Returns:
            PublishResult with status
        """
        pass

    @abstractmethod
    def deactivate_did(
        self,
        did: str,
        signature: bytes,
    ) -> PublishResult:
        """Deactivate a DID (mark as no longer valid).
        
        Args:
            did: The DID to deactivate
            signature: Signature from the DID controller
            
        Returns:
            PublishResult with status
        """
        pass

    @abstractmethod
    def publish_revocation_state(
        self,
        registry_id: str,
        accumulator_value: bytes,
        epoch: int,
        revoked_handlers: List[str],
        signature: bytes,
    ) -> PublishResult:
        """Publish a revocation registry state update.
        
        Args:
            registry_id: Revocation registry identifier
            accumulator_value: Current accumulator value
            epoch: State epoch number
            revoked_handlers: Newly revoked handlers
            signature: Publisher's signature
            
        Returns:
            PublishResult with status
        """
        pass

    @abstractmethod
    def get_revocation_state(
        self,
        registry_id: str,
        epoch: Optional[int] = None,
    ) -> Optional[AccumulatorState]:
        """Get revocation registry state.
        
        Args:
            registry_id: Revocation registry identifier
            epoch: Specific epoch (None = latest)
            
        Returns:
            AccumulatorState or None if not found
        """
        pass

    @abstractmethod
    def publish_credential_schema(
        self,
        schema_id: str,
        schema: Dict[str, Any],
        signature: bytes,
    ) -> PublishResult:
        """Publish a credential schema.
        
        Args:
            schema_id: Unique schema identifier
            schema: Schema definition
            signature: Publisher's signature
            
        Returns:
            PublishResult with status
        """
        pass

    @abstractmethod
    def get_credential_schema(
        self,
        schema_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get a credential schema.
        
        Args:
            schema_id: Schema identifier
            
        Returns:
            Schema definition or None if not found
        """
        pass


# =============================================================================
# In-Memory Registry (Testing)
# =============================================================================

class InMemoryRegistry(RegistryInterface):
    """In-memory registry for testing and development.
    
    WARNING: Not persistent - data lost on restart.
    Use only for testing.
    """

    def __init__(self) -> None:
        """Initialize empty registry."""
        self._did_documents: Dict[str, DIDDocument] = {}
        self._did_versions: Dict[str, List[str]] = {}  # DID -> list of version hashes
        self._deactivated_dids: set[str] = set()
        self._revocation_states: Dict[str, Dict[int, AccumulatorState]] = {}
        self._credential_schemas: Dict[str, Dict[str, Any]] = {}
        self._entry_counter = 0

    def publish_did(
        self,
        did_document: DIDDocument,
        signature: bytes,
    ) -> PublishResult:
        """Publish a DID Document."""
        did = did_document.id
        
        # Check if already exists
        if did in self._did_documents:
            return PublishResult(
                success=False,
                error="DID already exists - use update_did",
            )
        
        # Store document
        self._did_documents[did] = did_document
        
        # Track version
        version_hash = sha256_hash(did_document.get_hash()).hex()[:16]
        self._did_versions[did] = [version_hash]
        
        self._entry_counter += 1
        
        return PublishResult(
            success=True,
            entry_id=f"entry-{self._entry_counter}",
            timestamp=utc_now(),
        )

    def resolve_did(self, did: str) -> ResolutionResult:
        """Resolve a DID."""
        # Check if deactivated
        if did in self._deactivated_dids:
            return ResolutionResult(
                did_document=None,
                metadata={"deactivated": True},
                error="DID has been deactivated",
            )
        
        # Look up document
        document = self._did_documents.get(did)
        
        if document is None:
            return ResolutionResult(
                did_document=None,
                error="DID not found",
            )
        
        return ResolutionResult(
            did_document=document,
            metadata={
                "versionId": self._did_versions.get(did, ["unknown"])[-1],
                "created": document.created.isoformat() if document.created else None,
                "updated": document.updated.isoformat() if document.updated else None,
            },
        )

    def update_did(
        self,
        did_document: DIDDocument,
        signature: bytes,
        previous_version: str,
    ) -> PublishResult:
        """Update a DID Document."""
        did = did_document.id
        
        # Check exists
        if did not in self._did_documents:
            return PublishResult(
                success=False,
                error="DID not found - use publish_did",
            )
        
        # Check not deactivated
        if did in self._deactivated_dids:
            return PublishResult(
                success=False,
                error="Cannot update deactivated DID",
            )
        
        # Verify previous version (simple check)
        versions = self._did_versions.get(did, [])
        if versions and versions[-1] != previous_version:
            return PublishResult(
                success=False,
                error="Version mismatch - document was modified",
            )
        
        # Update document
        self._did_documents[did] = did_document
        
        # Track new version
        version_hash = sha256_hash(did_document.get_hash()).hex()[:16]
        self._did_versions[did].append(version_hash)
        
        self._entry_counter += 1
        
        return PublishResult(
            success=True,
            entry_id=f"entry-{self._entry_counter}",
            timestamp=utc_now(),
        )

    def deactivate_did(
        self,
        did: str,
        signature: bytes,
    ) -> PublishResult:
        """Deactivate a DID."""
        if did not in self._did_documents:
            return PublishResult(
                success=False,
                error="DID not found",
            )
        
        if did in self._deactivated_dids:
            return PublishResult(
                success=False,
                error="DID already deactivated",
            )
        
        self._deactivated_dids.add(did)
        
        self._entry_counter += 1
        
        return PublishResult(
            success=True,
            entry_id=f"entry-{self._entry_counter}",
            timestamp=utc_now(),
        )

    def publish_revocation_state(
        self,
        registry_id: str,
        accumulator_value: bytes,
        epoch: int,
        revoked_handlers: List[str],
        signature: bytes,
    ) -> PublishResult:
        """Publish revocation state."""
        if registry_id not in self._revocation_states:
            self._revocation_states[registry_id] = {}
        
        state = AccumulatorState(
            accumulator_id=registry_id,
            value=accumulator_value,
            epoch=epoch,
            revoked_handlers=revoked_handlers,
            timestamp=utc_now(),
        )
        
        self._revocation_states[registry_id][epoch] = state
        
        self._entry_counter += 1
        
        return PublishResult(
            success=True,
            entry_id=f"entry-{self._entry_counter}",
            timestamp=utc_now(),
        )

    def get_revocation_state(
        self,
        registry_id: str,
        epoch: Optional[int] = None,
    ) -> Optional[AccumulatorState]:
        """Get revocation state."""
        states = self._revocation_states.get(registry_id, {})
        
        if not states:
            return None
        
        if epoch is not None:
            return states.get(epoch)
        
        # Return latest epoch
        latest_epoch = max(states.keys())
        return states[latest_epoch]

    def publish_credential_schema(
        self,
        schema_id: str,
        schema: Dict[str, Any],
        signature: bytes,
    ) -> PublishResult:
        """Publish credential schema."""
        if schema_id in self._credential_schemas:
            return PublishResult(
                success=False,
                error="Schema already exists",
            )
        
        self._credential_schemas[schema_id] = schema
        
        self._entry_counter += 1
        
        return PublishResult(
            success=True,
            entry_id=f"entry-{self._entry_counter}",
            timestamp=utc_now(),
        )

    def get_credential_schema(
        self,
        schema_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get credential schema."""
        return self._credential_schemas.get(schema_id)


# =============================================================================
# DID Resolver
# =============================================================================

class DIDResolver:
    """Universal DID resolver supporting multiple methods.
    
    Dispatches resolution to appropriate handler based on DID method.
    """

    def __init__(self) -> None:
        """Initialize resolver."""
        self._method_handlers: Dict[str, RegistryInterface] = {}
        self._default_registry: Optional[RegistryInterface] = None

    def register_method(
        self,
        method: str,
        registry: RegistryInterface,
    ) -> None:
        """Register a registry for a DID method.
        
        Args:
            method: DID method name (e.g., "arbiter")
            registry: Registry interface for this method
        """
        self._method_handlers[method] = registry

    def set_default_registry(self, registry: RegistryInterface) -> None:
        """Set default registry for unknown methods.
        
        Args:
            registry: Default registry interface
        """
        self._default_registry = registry

    def resolve(self, did: str) -> ResolutionResult:
        """Resolve a DID to its document.
        
        Args:
            did: The DID to resolve
            
        Returns:
            ResolutionResult
        """
        # Parse DID method
        parts = did.split(":")
        if len(parts) < 3 or parts[0] != "did":
            return ResolutionResult(
                did_document=None,
                error="Invalid DID format",
            )
        
        method = parts[1]
        
        # Find handler
        registry = self._method_handlers.get(method)
        if registry is None:
            registry = self._default_registry
        
        if registry is None:
            return ResolutionResult(
                did_document=None,
                error=f"No handler for DID method: {method}",
            )
        
        return registry.resolve_did(did)
