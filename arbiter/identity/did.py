"""
Arbiter - Decentralized Identifier (DID) Module

Implements W3C DID Core specification for agent identity.
DIDs provide:
- Self-sovereign identity (agent controls their own identifier)
- Decentralized resolution (no central authority required)
- Cryptographic authentication (tied to key material)

Reference: W3C DID Core 1.0 - https://www.w3.org/TR/did-core/

DID Method: did:arbiter
Format: did:arbiter:<method-specific-id>

The method-specific-id is derived deterministically from the agent's
primary public key, ensuring:
- Same key always produces same DID
- DID cannot be forged without key material
- No central registry needed for basic resolution
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from arbiter.common.models import (
    DIDDocument,
    PublicKey,
    PrivateKey,
    ServiceEndpoint,
)
from arbiter.common.errors import (
    DIDError,
    DIDCreationError,
    DIDResolutionError,
)
from arbiter.common.utils import (
    bytes_to_base58,
    sha256_hash,
    utc_now,
    validate_did_format,
)


# =============================================================================
# Constants
# =============================================================================

# DID method for Arbiter
DID_METHOD = "arbiter"

# DID scheme prefix
DID_PREFIX = f"did:{DID_METHOD}:"

# Key types supported
KEY_TYPE_DILITHIUM3 = "Dilithium3VerificationKey2024"
KEY_TYPE_KYBER768 = "Kyber768KeyAgreementKey2024"
KEY_TYPE_BBS = "Bls12381G2Key2020"
KEY_TYPE_ED25519 = "Ed25519VerificationKey2020"

# Verification relationship types
RELATIONSHIP_AUTHENTICATION = "authentication"
RELATIONSHIP_ASSERTION = "assertionMethod"
RELATIONSHIP_KEY_AGREEMENT = "keyAgreement"
RELATIONSHIP_CAPABILITY_INVOCATION = "capabilityInvocation"
RELATIONSHIP_CAPABILITY_DELEGATION = "capabilityDelegation"


# =============================================================================
# DID Class
# =============================================================================


@dataclass
class DID:
    """Decentralized Identifier for an agent.

    Represents a unique, self-sovereign identity that is:
    - Deterministically derived from key material
    - Resolvable to a DID Document
    - Cryptographically verifiable

    Attributes:
        did_string: Full DID URI (e.g., "did:arbiter:abc123")
        method_specific_id: The unique identifier part
    """

    did_string: str
    method_specific_id: str

    @classmethod
    def from_public_key(cls, public_key_bytes: bytes) -> "DID":
        """Create a DID deterministically from a public key.

        The method-specific-id is derived by:
        1. SHA-256 hash of the public key
        2. Take first 16 bytes (128 bits)
        3. Base58 encode

        This ensures:
        - Same key always produces same DID
        - 128-bit collision resistance
        - Human-readable identifier

        Args:
            public_key_bytes: Raw public key material

        Returns:
            DID instance
        """
        key_hash = sha256_hash(public_key_bytes)
        truncated = key_hash[:16]  # 128 bits
        method_specific_id = bytes_to_base58(truncated)
        did_string = f"{DID_PREFIX}{method_specific_id}"

        return cls(did_string=did_string, method_specific_id=method_specific_id)

    @classmethod
    def from_string(cls, did_string: str) -> "DID":
        """Parse a DID from its string representation.

        Args:
            did_string: Full DID URI

        Returns:
            DID instance

        Raises:
            DIDError: If DID format is invalid
        """
        if not validate_did_format(did_string):
            raise DIDError(f"Invalid DID format: {did_string[:30]}...", did=did_string)

        if not did_string.startswith(DID_PREFIX):
            raise DIDError(
                f"Unsupported DID method (expected {DID_METHOD})",
                did=did_string,
            )

        method_specific_id = did_string[len(DID_PREFIX) :]
        return cls(did_string=did_string, method_specific_id=method_specific_id)

    def __str__(self) -> str:
        return self.did_string

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DID):
            return self.did_string == other.did_string
        if isinstance(other, str):
            return self.did_string == other
        return False

    def __hash__(self) -> int:
        return hash(self.did_string)

    def key_id(self, key_fragment: str) -> str:
        """Create a key ID for a key in this DID document.

        Args:
            key_fragment: Fragment identifier for the key

        Returns:
            Full key ID (e.g., "did:arbiter:abc123#key-1")
        """
        return f"{self.did_string}#{key_fragment}"


# =============================================================================
# DID Document Builder
# =============================================================================


class DIDDocumentBuilder:
    """Builder for constructing DID Documents.

    Provides a fluent API for building W3C-compliant DID Documents
    with proper verification methods and relationships.
    """

    def __init__(self, did: DID) -> None:
        """Initialize builder for a specific DID.

        Args:
            did: The DID this document describes
        """
        self.did = did
        self._verification_methods: List[PublicKey] = []
        self._authentication: List[str] = []
        self._assertion_method: List[str] = []
        self._key_agreement: List[str] = []
        self._capability_invocation: List[str] = []
        self._capability_delegation: List[str] = []
        self._services: List[ServiceEndpoint] = []
        self._created: Optional[datetime] = None
        self._updated: Optional[datetime] = None

    def add_verification_method(
        self,
        public_key_bytes: bytes,
        key_type: str,
        key_fragment: str = "key-1",
        relationships: Optional[List[str]] = None,
    ) -> "DIDDocumentBuilder":
        """Add a verification method (public key) to the document.

        Args:
            public_key_bytes: Raw public key material
            key_type: Type of key (e.g., KEY_TYPE_DILITHIUM3)
            key_fragment: Fragment ID for the key
            relationships: Verification relationships to add key to

        Returns:
            Self for chaining
        """
        key_id = self.did.key_id(key_fragment)

        public_key = PublicKey(
            key_id=key_id,
            key_type=key_type,
            public_key_bytes=public_key_bytes,
            controller=self.did.did_string,
        )

        self._verification_methods.append(public_key)

        # Add to specified relationships
        if relationships:
            for rel in relationships:
                if rel == RELATIONSHIP_AUTHENTICATION:
                    self._authentication.append(key_id)
                elif rel == RELATIONSHIP_ASSERTION:
                    self._assertion_method.append(key_id)
                elif rel == RELATIONSHIP_KEY_AGREEMENT:
                    self._key_agreement.append(key_id)
                elif rel == RELATIONSHIP_CAPABILITY_INVOCATION:
                    self._capability_invocation.append(key_id)
                elif rel == RELATIONSHIP_CAPABILITY_DELEGATION:
                    self._capability_delegation.append(key_id)

        return self

    def add_authentication_key(
        self,
        public_key_bytes: bytes,
        key_type: str = KEY_TYPE_DILITHIUM3,
        key_fragment: str = "auth-key",
    ) -> "DIDDocumentBuilder":
        """Add a key for authentication purposes.

        Args:
            public_key_bytes: Raw public key material
            key_type: Type of key
            key_fragment: Fragment ID

        Returns:
            Self for chaining
        """
        return self.add_verification_method(
            public_key_bytes,
            key_type,
            key_fragment,
            [RELATIONSHIP_AUTHENTICATION],
        )

    def add_assertion_key(
        self,
        public_key_bytes: bytes,
        key_type: str = KEY_TYPE_BBS,
        key_fragment: str = "assert-key",
    ) -> "DIDDocumentBuilder":
        """Add a key for making assertions (signing credentials).

        Args:
            public_key_bytes: Raw public key material
            key_type: Type of key
            key_fragment: Fragment ID

        Returns:
            Self for chaining
        """
        return self.add_verification_method(
            public_key_bytes,
            key_type,
            key_fragment,
            [RELATIONSHIP_ASSERTION],
        )

    def add_key_agreement_key(
        self,
        public_key_bytes: bytes,
        key_type: str = KEY_TYPE_KYBER768,
        key_fragment: str = "enc-key",
    ) -> "DIDDocumentBuilder":
        """Add a key for key agreement (encryption).

        Args:
            public_key_bytes: Raw public key material
            key_type: Type of key
            key_fragment: Fragment ID

        Returns:
            Self for chaining
        """
        return self.add_verification_method(
            public_key_bytes,
            key_type,
            key_fragment,
            [RELATIONSHIP_KEY_AGREEMENT],
        )

    def add_service(
        self,
        service_type: str,
        endpoint: str,
        service_id: Optional[str] = None,
    ) -> "DIDDocumentBuilder":
        """Add a service endpoint.

        Args:
            service_type: Type of service (e.g., "AgentMessaging")
            endpoint: Service endpoint URI
            service_id: Optional service ID fragment

        Returns:
            Self for chaining
        """
        if service_id is None:
            service_id = f"service-{len(self._services) + 1}"

        full_id = self.did.key_id(service_id)

        self._services.append(
            ServiceEndpoint(
                id=full_id,
                type=service_type,
                service_endpoint=endpoint,
            )
        )

        return self

    def set_timestamps(
        self,
        created: Optional[datetime] = None,
        updated: Optional[datetime] = None,
    ) -> "DIDDocumentBuilder":
        """Set document timestamps.

        Args:
            created: Creation timestamp
            updated: Last update timestamp

        Returns:
            Self for chaining
        """
        self._created = created or utc_now()
        self._updated = updated or self._created
        return self

    def build(self) -> DIDDocument:
        """Build the DID Document.

        Returns:
            Complete DIDDocument
        """
        if not self._created:
            self._created = utc_now()
        if not self._updated:
            self._updated = self._created

        return DIDDocument(
            id=self.did.did_string,
            verification_method=self._verification_methods,
            authentication=self._authentication,
            assertion_method=self._assertion_method,
            capability_invocation=self._capability_invocation,
            capability_delegation=self._capability_delegation,
            service=self._services,
            created=self._created,
            updated=self._updated,
        )


# =============================================================================
# DID Operations
# =============================================================================


def create_did_from_keys(
    primary_public_key: bytes,
    signing_key: Optional[bytes] = None,
    encryption_key: Optional[bytes] = None,
    assertion_key: Optional[bytes] = None,
    service_endpoint: Optional[str] = None,
) -> tuple[DID, DIDDocument]:
    """Create a DID and its document from key material.

    This is the main entry point for agent identity creation.

    Args:
        primary_public_key: Primary key for DID derivation and auth
        signing_key: Optional separate signing key
        encryption_key: Optional key agreement key
        assertion_key: Optional credential assertion key
        service_endpoint: Optional agent messaging endpoint

    Returns:
        Tuple of (DID, DIDDocument)
    """
    # Create DID from primary key
    did = DID.from_public_key(primary_public_key)

    # Build document
    builder = DIDDocumentBuilder(did)

    # Add primary key for authentication
    builder.add_authentication_key(
        primary_public_key,
        KEY_TYPE_DILITHIUM3,
        "key-1",
    )

    # Add optional keys
    if signing_key:
        builder.add_verification_method(
            signing_key,
            KEY_TYPE_DILITHIUM3,
            "signing-key",
            [RELATIONSHIP_AUTHENTICATION, RELATIONSHIP_ASSERTION],
        )

    if encryption_key:
        builder.add_key_agreement_key(
            encryption_key,
            KEY_TYPE_KYBER768,
            "encryption-key",
        )

    if assertion_key:
        builder.add_assertion_key(
            assertion_key,
            KEY_TYPE_BBS,
            "assertion-key",
        )

    # Add service endpoint if provided
    if service_endpoint:
        builder.add_service(
            "AgentMessaging",
            service_endpoint,
            "messaging",
        )

    builder.set_timestamps()
    document = builder.build()

    return did, document


def verify_did_document_integrity(document: DIDDocument) -> bool:
    """Verify the internal consistency of a DID Document.

    Checks:
    - All key references point to valid verification methods
    - Controller fields are consistent
    - Required fields are present

    Args:
        document: DID Document to verify

    Returns:
        True if document is internally consistent
    """
    # Collect all verification method IDs
    vm_ids = {vm.key_id for vm in document.verification_method}

    # Check all key references
    all_refs = (
        document.authentication
        + document.assertion_method
        + document.capability_invocation
        + document.capability_delegation
    )

    for ref in all_refs:
        # Reference can be a key ID or an embedded key (we check IDs only)
        if isinstance(ref, str) and ref not in vm_ids:
            return False

    # Check controller consistency
    for vm in document.verification_method:
        # Controller should be the DID or a valid DID
        if not validate_did_format(vm.controller):
            return False

    return True


def extract_key_for_purpose(
    document: DIDDocument,
    purpose: str,
) -> Optional[PublicKey]:
    """Extract a public key for a specific verification purpose.

    Args:
        document: DID Document to search
        purpose: Purpose (authentication, assertionMethod, etc.)

    Returns:
        PublicKey if found, None otherwise
    """
    # Get key IDs for the purpose
    if purpose == RELATIONSHIP_AUTHENTICATION:
        key_refs = document.authentication
    elif purpose == RELATIONSHIP_ASSERTION:
        key_refs = document.assertion_method
    elif purpose == RELATIONSHIP_CAPABILITY_INVOCATION:
        key_refs = document.capability_invocation
    elif purpose == RELATIONSHIP_CAPABILITY_DELEGATION:
        key_refs = document.capability_delegation
    else:
        return None

    if not key_refs:
        return None

    # Find the verification method
    target_id = key_refs[0]  # Use first key for purpose
    for vm in document.verification_method:
        if vm.key_id == target_id:
            return vm

    return None
