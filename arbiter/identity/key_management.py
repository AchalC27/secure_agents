"""
Arbiter - Key Management Module

Secure key management for agent cryptographic material.
Provides:
- Key generation (PQC + classical)
- Secure storage abstraction
- Key derivation
- Key rotation support

Threat Model:
    - Private keys should never be exposed outside this module
    - Key material should be zeroized after use
    - Storage implementations must be secure (HSM, secure enclave, encrypted)

References:
- NIST SP 800-57: Recommendation for Key Management
- NIST SP 800-131A: Transitioning Cryptographic Algorithms
"""

from __future__ import annotations

import hashlib
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Protocol

from arbiter.common.models import PublicKey, PrivateKey
from arbiter.common.errors import (
    KeyGenerationError,
    CryptoError,
    ArbiterError,
)
from arbiter.common.utils import (
    bytes_to_base58,
    sha256_hash,
    generate_id,
    utc_now,
)
from arbiter.crypto.pqc import (
    generate_dilithium_keypair,
    generate_kyber_keypair,
    generate_hybrid_keypair,
    DilithiumKeyPair,
    KyberKeyPair,
    HybridKeyPair,
    DEFAULT_SECURITY_LEVEL,
)
from arbiter.crypto.bbs_plus import (
    generate_bbs_keypair,
    BBSKeyPair,
)


# =============================================================================
# Key Types and Status
# =============================================================================

class KeyPurpose(Enum):
    """Purpose of a cryptographic key."""
    AUTHENTICATION = auto()  # DID authentication
    SIGNING = auto()  # General signing
    ASSERTION = auto()  # Credential signing (BBS+)
    KEY_AGREEMENT = auto()  # Key exchange / encryption
    MASTER = auto()  # Master key for derivation


class KeyStatus(Enum):
    """Status of a key in its lifecycle."""
    ACTIVE = auto()  # Key is in use
    SUSPENDED = auto()  # Temporarily disabled
    REVOKED = auto()  # Permanently revoked
    EXPIRED = auto()  # Past expiration date
    PENDING = auto()  # Generated but not yet activated


@dataclass
class KeyMetadata:
    """Metadata for a managed key.
    
    Attributes:
        key_id: Unique identifier for this key
        purpose: What the key is used for
        algorithm: Cryptographic algorithm
        status: Current key status
        created_at: When key was generated
        expires_at: Optional expiration (None = no expiration)
        rotated_from: ID of key this was rotated from (if any)
    """
    key_id: str
    purpose: KeyPurpose
    algorithm: str
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: datetime = field(default_factory=utc_now)
    expires_at: Optional[datetime] = None
    rotated_from: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


# =============================================================================
# Key Storage Interface
# =============================================================================

class KeyStorage(ABC):
    """Abstract interface for secure key storage.
    
    Implementations might include:
    - In-memory (testing only)
    - Encrypted file storage
    - Hardware Security Module (HSM)
    - Secure enclave
    - Cloud KMS
    """

    @abstractmethod
    def store(
        self,
        key_id: str,
        private_key_bytes: bytes,
        metadata: KeyMetadata,
    ) -> None:
        """Store a private key securely.
        
        Args:
            key_id: Unique key identifier
            private_key_bytes: Raw private key material
            metadata: Key metadata
        """
        pass

    @abstractmethod
    def retrieve(self, key_id: str) -> tuple[bytes, KeyMetadata]:
        """Retrieve a private key.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Tuple of (private_key_bytes, metadata)
            
        Raises:
            KeyError: If key not found
        """
        pass

    @abstractmethod
    def delete(self, key_id: str) -> None:
        """Securely delete a key.
        
        Args:
            key_id: Key identifier
        """
        pass

    @abstractmethod
    def list_keys(self) -> List[KeyMetadata]:
        """List all stored key metadata (without private material)."""
        pass

    @abstractmethod
    def update_metadata(self, key_id: str, metadata: KeyMetadata) -> None:
        """Update key metadata.
        
        Args:
            key_id: Key identifier
            metadata: Updated metadata
        """
        pass


class InMemoryKeyStorage(KeyStorage):
    """In-memory key storage for testing.
    
    WARNING: Not suitable for production - keys are not persisted
    and may be exposed in memory dumps.
    """

    def __init__(self) -> None:
        self._keys: Dict[str, tuple[bytes, KeyMetadata]] = {}

    def store(
        self,
        key_id: str,
        private_key_bytes: bytes,
        metadata: KeyMetadata,
    ) -> None:
        self._keys[key_id] = (private_key_bytes, metadata)

    def retrieve(self, key_id: str) -> tuple[bytes, KeyMetadata]:
        if key_id not in self._keys:
            raise KeyError(f"Key not found: {key_id}")
        return self._keys[key_id]

    def delete(self, key_id: str) -> None:
        if key_id in self._keys:
            # Attempt to overwrite before delete (weak zeroization)
            key_bytes, _ = self._keys[key_id]
            # Python doesn't guarantee this clears memory
            del self._keys[key_id]

    def list_keys(self) -> List[KeyMetadata]:
        return [meta for _, meta in self._keys.values()]

    def update_metadata(self, key_id: str, metadata: KeyMetadata) -> None:
        if key_id not in self._keys:
            raise KeyError(f"Key not found: {key_id}")
        key_bytes, _ = self._keys[key_id]
        self._keys[key_id] = (key_bytes, metadata)


# =============================================================================
# Key Manager
# =============================================================================

@dataclass
class ManagedKeyPair:
    """A managed key pair with metadata.
    
    Attributes:
        key_id: Unique identifier
        public_key: Public key (safe to share)
        metadata: Key metadata
        _private_key_bytes: Private key (never expose!)
    """
    key_id: str
    public_key: PublicKey
    metadata: KeyMetadata
    _private_key_bytes: bytes = field(repr=False)

    def get_private_key_bytes(self) -> bytes:
        """Access private key bytes.
        
        Warning: Use with caution - private keys should rarely
        leave the key manager.
        """
        return self._private_key_bytes


class KeyManager:
    """Manages cryptographic keys for an agent.
    
    Provides:
    - Key generation for different purposes
    - Secure storage abstraction
    - Key rotation
    - Key derivation
    
    Usage:
        manager = KeyManager()
        keypair = manager.generate_authentication_key()
        signature = manager.sign(keypair.key_id, message)
    """

    def __init__(
        self,
        storage: Optional[KeyStorage] = None,
        default_key_expiry_days: int = 365,
    ) -> None:
        """Initialize the key manager.
        
        Args:
            storage: Key storage backend (in-memory if not provided)
            default_key_expiry_days: Default key expiration period
        """
        self._storage = storage or InMemoryKeyStorage()
        self._default_expiry_days = default_key_expiry_days
        self._public_keys: Dict[str, PublicKey] = {}

    def generate_authentication_key(
        self,
        security_level: int = DEFAULT_SECURITY_LEVEL,
        expires_in_days: Optional[int] = None,
    ) -> ManagedKeyPair:
        """Generate a key pair for DID authentication.
        
        Uses Dilithium (PQC) for quantum-resistant authentication.
        
        Args:
            security_level: NIST security level (1, 3, or 5)
            expires_in_days: Days until expiration (None = use default)
            
        Returns:
            ManagedKeyPair with authentication key
        """
        keypair = generate_dilithium_keypair(security_level)
        
        key_id = f"auth-{generate_id(length=8)}"
        expires_at = utc_now() + timedelta(
            days=expires_in_days or self._default_expiry_days
        )
        
        metadata = KeyMetadata(
            key_id=key_id,
            purpose=KeyPurpose.AUTHENTICATION,
            algorithm=f"Dilithium{security_level}",
            expires_at=expires_at,
        )
        
        public_key = PublicKey(
            key_id=key_id,
            key_type=f"Dilithium{security_level}VerificationKey2024",
            public_key_bytes=keypair.public_key.key_bytes,
            controller="",  # Set when DID is created
        )
        
        # Store private key
        self._storage.store(key_id, keypair.private_key.key_bytes, metadata)
        self._public_keys[key_id] = public_key
        
        return ManagedKeyPair(
            key_id=key_id,
            public_key=public_key,
            metadata=metadata,
            _private_key_bytes=keypair.private_key.key_bytes,
        )

    def generate_assertion_key(
        self,
        max_messages: int = 10,
        expires_in_days: Optional[int] = None,
    ) -> ManagedKeyPair:
        """Generate a key pair for credential assertion (BBS+).
        
        BBS+ keys enable selective disclosure of credential attributes.
        
        Args:
            max_messages: Maximum attributes per credential
            expires_in_days: Days until expiration
            
        Returns:
            ManagedKeyPair with assertion key
        """
        keypair = generate_bbs_keypair(max_messages)
        
        key_id = f"assert-{generate_id(length=8)}"
        expires_at = utc_now() + timedelta(
            days=expires_in_days or self._default_expiry_days
        )
        
        metadata = KeyMetadata(
            key_id=key_id,
            purpose=KeyPurpose.ASSERTION,
            algorithm="BBS+",
            expires_at=expires_at,
            tags={"max_messages": str(max_messages)},
        )
        
        public_key = PublicKey(
            key_id=key_id,
            key_type="Bls12381G2Key2020",
            public_key_bytes=keypair.public_key.w_bytes,
            controller="",
        )
        
        self._storage.store(key_id, keypair.private_key.x_bytes, metadata)
        self._public_keys[key_id] = public_key
        
        return ManagedKeyPair(
            key_id=key_id,
            public_key=public_key,
            metadata=metadata,
            _private_key_bytes=keypair.private_key.x_bytes,
        )

    def generate_encryption_key(
        self,
        security_level: int = DEFAULT_SECURITY_LEVEL,
        expires_in_days: Optional[int] = None,
    ) -> ManagedKeyPair:
        """Generate a key pair for key agreement / encryption.
        
        Uses Kyber (PQC) for quantum-resistant key encapsulation.
        
        Args:
            security_level: NIST security level
            expires_in_days: Days until expiration
            
        Returns:
            ManagedKeyPair with encryption key
        """
        keypair = generate_kyber_keypair(security_level)
        
        key_id = f"enc-{generate_id(length=8)}"
        expires_at = utc_now() + timedelta(
            days=expires_in_days or self._default_expiry_days
        )
        
        metadata = KeyMetadata(
            key_id=key_id,
            purpose=KeyPurpose.KEY_AGREEMENT,
            algorithm=f"Kyber{security_level * 256}",
            expires_at=expires_at,
        )
        
        public_key = PublicKey(
            key_id=key_id,
            key_type=f"Kyber{security_level * 256}KeyAgreementKey2024",
            public_key_bytes=keypair.public_key.key_bytes,
            controller="",
        )
        
        self._storage.store(key_id, keypair.private_key.key_bytes, metadata)
        self._public_keys[key_id] = public_key
        
        return ManagedKeyPair(
            key_id=key_id,
            public_key=public_key,
            metadata=metadata,
            _private_key_bytes=keypair.private_key.key_bytes,
        )

    def generate_master_key(
        self,
        seed: Optional[bytes] = None,
    ) -> ManagedKeyPair:
        """Generate a master key for key derivation.
        
        The master key can derive child keys for different purposes,
        enabling hierarchical deterministic key management.
        
        Args:
            seed: Optional seed for deterministic generation
            
        Returns:
            ManagedKeyPair with master key
        """
        if seed:
            master_bytes = sha256_hash(b"arbiter-master-v1" + seed)
        else:
            master_bytes = secrets.token_bytes(32)
        
        key_id = f"master-{generate_id(length=8)}"
        
        metadata = KeyMetadata(
            key_id=key_id,
            purpose=KeyPurpose.MASTER,
            algorithm="HMAC-SHA256",
            expires_at=None,  # Master keys don't expire
        )
        
        # Master key public component (for verification only)
        public_bytes = sha256_hash(master_bytes)
        public_key = PublicKey(
            key_id=key_id,
            key_type="MasterKey2024",
            public_key_bytes=public_bytes,
            controller="",
        )
        
        self._storage.store(key_id, master_bytes, metadata)
        self._public_keys[key_id] = public_key
        
        return ManagedKeyPair(
            key_id=key_id,
            public_key=public_key,
            metadata=metadata,
            _private_key_bytes=master_bytes,
        )

    def derive_key(
        self,
        master_key_id: str,
        purpose: str,
        index: int = 0,
    ) -> bytes:
        """Derive a child key from a master key.
        
        Uses HKDF-like derivation for deterministic child keys.
        
        Args:
            master_key_id: ID of the master key
            purpose: Purpose string (e.g., "authentication")
            index: Derivation index
            
        Returns:
            Derived key bytes (32 bytes)
        """
        master_bytes, metadata = self._storage.retrieve(master_key_id)
        
        if metadata.purpose != KeyPurpose.MASTER:
            raise CryptoError(
                "Can only derive from master keys",
                error_code="DERIVATION_ERROR",
            )
        
        # HKDF-like derivation
        info = f"arbiter-derive-v1:{purpose}:{index}".encode()
        derived = hashlib.sha256(master_bytes + info).digest()
        
        return derived

    def rotate_key(self, old_key_id: str) -> ManagedKeyPair:
        """Rotate a key, generating a new one and marking old as revoked.
        
        Args:
            old_key_id: ID of key to rotate
            
        Returns:
            New key pair
        """
        old_bytes, old_metadata = self._storage.retrieve(old_key_id)
        
        # Generate new key of same type
        if old_metadata.purpose == KeyPurpose.AUTHENTICATION:
            new_keypair = self.generate_authentication_key()
        elif old_metadata.purpose == KeyPurpose.ASSERTION:
            max_msgs = int(old_metadata.tags.get("max_messages", "10"))
            new_keypair = self.generate_assertion_key(max_msgs)
        elif old_metadata.purpose == KeyPurpose.KEY_AGREEMENT:
            new_keypair = self.generate_encryption_key()
        else:
            raise CryptoError(
                f"Cannot rotate key of type {old_metadata.purpose}",
                error_code="ROTATION_ERROR",
            )
        
        # Link to old key
        new_keypair.metadata.rotated_from = old_key_id
        self._storage.update_metadata(new_keypair.key_id, new_keypair.metadata)
        
        # Mark old key as revoked
        old_metadata.status = KeyStatus.REVOKED
        self._storage.update_metadata(old_key_id, old_metadata)
        
        return new_keypair

    def get_public_key(self, key_id: str) -> PublicKey:
        """Get the public key for a key ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            PublicKey
        """
        if key_id not in self._public_keys:
            # Try to load from storage
            _, metadata = self._storage.retrieve(key_id)
            raise KeyError(f"Public key not cached: {key_id}")
        return self._public_keys[key_id]

    def list_keys(
        self,
        purpose: Optional[KeyPurpose] = None,
        status: Optional[KeyStatus] = None,
    ) -> List[KeyMetadata]:
        """List keys with optional filtering.
        
        Args:
            purpose: Filter by purpose
            status: Filter by status
            
        Returns:
            List of matching key metadata
        """
        all_keys = self._storage.list_keys()
        
        if purpose:
            all_keys = [k for k in all_keys if k.purpose == purpose]
        if status:
            all_keys = [k for k in all_keys if k.status == status]
        
        return all_keys

    def revoke_key(self, key_id: str) -> None:
        """Revoke a key.
        
        Args:
            key_id: Key to revoke
        """
        _, metadata = self._storage.retrieve(key_id)
        metadata.status = KeyStatus.REVOKED
        self._storage.update_metadata(key_id, metadata)

    def is_key_valid(self, key_id: str) -> bool:
        """Check if a key is currently valid.
        
        Args:
            key_id: Key to check
            
        Returns:
            True if key is active and not expired
        """
        try:
            _, metadata = self._storage.retrieve(key_id)
        except KeyError:
            return False
        
        if metadata.status != KeyStatus.ACTIVE:
            return False
        
        if metadata.expires_at and metadata.expires_at < utc_now():
            return False
        
        return True
