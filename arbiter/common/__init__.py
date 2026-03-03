"""
Arbiter - Common Layer Package

Shared utilities used across all Arbiter components.

- Models: Core data structures (DIDs, VCs, Policies, etc.)
- Errors: Hierarchical exception classes
- Utils: Encoding, hashing, validation utilities
"""

from arbiter.common.models import (
    # DID Models
    DIDDocument,
    PublicKey,
    PrivateKey,
    ServiceEndpoint,
    # Credential Models
    VerifiableCredential,
    CredentialSubject,
    RevocationInfo,
    Proof,
    VerifiablePresentation,
    # ZKP Models
    ZKProof,
    ProofType,
    # Policy Models
    Policy,
    PolicyRule,
    Condition,
    ConditionOperator,
    Effect,
    AccessRequest,
    AccessDecision,
    # Registry Models
    RegistryEntry,
    AccumulatorState,
    # Encryption Models
    EncryptedValue,
)

from arbiter.common.errors import (
    # Base
    ArbiterError,
    # Crypto
    CryptoError,
    KeyGenerationError,
    SignatureError,
    SignatureVerificationError,
    EncryptionError,
    DecryptionError,
    # Identity
    IdentityError,
    DIDError,
    DIDCreationError,
    DIDResolutionError,
    CredentialError,
    CredentialIssuanceError,
    CredentialVerificationError,
    CredentialRevokedError,
    # Revocation
    RevocationError,
    WitnessUpdateError,
    NonRevocationProofError,
    AccumulatorError,
    # Authorization
    AuthorizationError,
    AccessDeniedError,
    PolicyError,
    PolicyNotFoundError,
    PolicyValidationError,
    # Registry
    RegistryError,
    RegistryConnectionError,
    RegistryPublishError,
    # Verification
    VerificationError,
    ProofError,
    TrustDecisionError,
    # Commitment
    CommitmentError,
)

from arbiter.common.utils import (
    # Encoding
    bytes_to_base58,
    base58_to_bytes,
    bytes_to_multibase,
    multibase_to_bytes,
    # Hashing
    sha256_hash,
    sha3_256_hash,
    # ID Generation
    generate_id,
    generate_deterministic_id,
    generate_nonce,
    generate_challenge,
    # Time
    utc_now,
    is_expired,
    # Serialization
    canonical_json,
    canonical_json_bytes,
    hash_json,
    # Validation
    validate_did_format,
    validate_uri,
    # Security
    constant_time_compare,
)

__all__ = [
    # DID Models
    "DIDDocument",
    "PublicKey",
    "PrivateKey",
    "ServiceEndpoint",
    # Credential Models
    "VerifiableCredential",
    "CredentialSubject",
    "RevocationInfo",
    "Proof",
    "VerifiablePresentation",
    # ZKP Models
    "ZKProof",
    "ProofType",
    # Policy Models
    "Policy",
    "PolicyRule",
    "Condition",
    "ConditionOperator",
    "Effect",
    "AccessRequest",
    "AccessDecision",
    # Registry Models
    "RegistryEntry",
    "AccumulatorState",
    # Encryption Models
    "EncryptedValue",
    # Errors - Base
    "ArbiterError",
    # Errors - Crypto
    "CryptoError",
    "KeyGenerationError",
    "SignatureError",
    "SignatureVerificationError",
    "EncryptionError",
    "DecryptionError",
    # Errors - Identity
    "IdentityError",
    "DIDError",
    "DIDCreationError",
    "DIDResolutionError",
    "CredentialError",
    "CredentialIssuanceError",
    "CredentialVerificationError",
    "CredentialRevokedError",
    # Errors - Revocation
    "RevocationError",
    "WitnessUpdateError",
    "NonRevocationProofError",
    "AccumulatorError",
    # Errors - Authorization
    "AuthorizationError",
    "AccessDeniedError",
    "PolicyError",
    "PolicyNotFoundError",
    "PolicyValidationError",
    # Errors - Registry
    "RegistryError",
    "RegistryConnectionError",
    "RegistryPublishError",
    # Errors - Verification
    "VerificationError",
    "ProofError",
    "TrustDecisionError",
    # Errors - Commitment
    "CommitmentError",
    # Utils - Encoding
    "bytes_to_base58",
    "base58_to_bytes",
    "bytes_to_multibase",
    "multibase_to_bytes",
    # Utils - Hashing
    "sha256_hash",
    "sha3_256_hash",
    # Utils - ID Generation
    "generate_id",
    "generate_deterministic_id",
    "generate_nonce",
    "generate_challenge",
    # Utils - Time
    "utc_now",
    "is_expired",
    # Utils - Serialization
    "canonical_json",
    "canonical_json_bytes",
    "hash_json",
    # Utils - Validation
    "validate_did_format",
    "validate_uri",
    # Utils - Security
    "constant_time_compare",
]
