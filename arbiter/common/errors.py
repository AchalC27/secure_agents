"""
Arbiter - Custom Exceptions

Hierarchical exception structure for precise error handling across all layers.
All exceptions include context information for debugging while avoiding
sensitive data leakage.

Threat Model Note:
    Exception messages should NEVER contain:
    - Private key material
    - Full credential contents
    - Internal system paths in production
"""

from __future__ import annotations

from typing import Any, Optional


class ArbiterError(Exception):
    """Base exception for all Arbiter errors.
    
    Attributes:
        message: Human-readable error description
        error_code: Machine-readable error code for programmatic handling
        context: Additional context (sanitized for security)
    """

    def __init__(
        self,
        message: str,
        error_code: str = "ARBITER_ERROR",
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize error for logging/transmission (sanitized)."""
        return {
            "error": self.error_code,
            "message": self.message,
            "context": self.context,
        }


# =============================================================================
# Cryptographic Errors
# =============================================================================

class CryptoError(ArbiterError):
    """Base exception for cryptographic operation failures."""

    def __init__(
        self,
        message: str,
        error_code: str = "CRYPTO_ERROR",
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, error_code, context)


class KeyGenerationError(CryptoError):
    """Failed to generate cryptographic keys."""

    def __init__(self, message: str, key_type: str) -> None:
        super().__init__(
            message,
            error_code="KEY_GENERATION_FAILED",
            context={"key_type": key_type},
        )


class SignatureError(CryptoError):
    """Signature creation or verification failed."""

    def __init__(self, message: str, operation: str = "unknown") -> None:
        super().__init__(
            message,
            error_code="SIGNATURE_ERROR",
            context={"operation": operation},
        )


class SignatureVerificationError(SignatureError):
    """Signature verification failed - possible tampering or invalid signature."""

    def __init__(self, message: str = "Signature verification failed") -> None:
        super().__init__(message, operation="verify")
        self.error_code = "SIGNATURE_VERIFICATION_FAILED"


class EncryptionError(CryptoError):
    """Encryption operation failed."""

    def __init__(self, message: str, operation: str = "encrypt") -> None:
        super().__init__(
            message,
            error_code="ENCRYPTION_ERROR",
            context={"operation": operation},
        )


class DecryptionError(CryptoError):
    """Decryption operation failed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="DECRYPTION_ERROR")


class AccumulatorError(CryptoError):
    """Cryptographic accumulator operation failed."""

    def __init__(self, message: str, operation: str) -> None:
        super().__init__(
            message,
            error_code="ACCUMULATOR_ERROR",
            context={"operation": operation},
        )


class CommitmentError(CryptoError):
    """Commitment scheme operation failed."""

    def __init__(self, message: str, operation: str) -> None:
        super().__init__(
            message,
            error_code="COMMITMENT_ERROR",
            context={"operation": operation},
        )


class ProofError(CryptoError):
    """Zero-knowledge proof operation failed."""

    def __init__(self, message: str, proof_type: str) -> None:
        super().__init__(
            message,
            error_code="PROOF_ERROR",
            context={"proof_type": proof_type},
        )


# =============================================================================
# Identity Layer Errors
# =============================================================================

class IdentityError(ArbiterError):
    """Base exception for identity-related errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "IDENTITY_ERROR",
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, error_code, context)


class DIDError(IdentityError):
    """DID-related operation failed."""

    def __init__(self, message: str, did: Optional[str] = None) -> None:
        # Truncate DID for security
        safe_did = did[:20] + "..." if did and len(did) > 20 else did
        super().__init__(
            message,
            error_code="DID_ERROR",
            context={"did_prefix": safe_did} if safe_did else {},
        )


class DIDResolutionError(DIDError):
    """Failed to resolve a DID to its document."""

    def __init__(self, did: str, reason: str = "not found") -> None:
        super().__init__(f"DID resolution failed: {reason}", did)
        self.error_code = "DID_RESOLUTION_FAILED"


class DIDCreationError(DIDError):
    """Failed to create a new DID."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.error_code = "DID_CREATION_FAILED"


class CredentialError(IdentityError):
    """Verifiable Credential operation failed."""

    def __init__(
        self,
        message: str,
        credential_id: Optional[str] = None,
        error_code: str = "CREDENTIAL_ERROR",
    ) -> None:
        # Truncate credential ID for security
        safe_id = credential_id[:20] + "..." if credential_id and len(credential_id) > 20 else credential_id
        super().__init__(
            message,
            error_code=error_code,
            context={"credential_id_prefix": safe_id} if safe_id else {},
        )


class CredentialIssuanceError(CredentialError):
    """Failed to issue a credential."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="CREDENTIAL_ISSUANCE_FAILED")


class CredentialVerificationError(CredentialError):
    """Credential verification failed."""

    def __init__(self, message: str, credential_id: Optional[str] = None) -> None:
        super().__init__(message, credential_id, "CREDENTIAL_VERIFICATION_FAILED")


class CredentialExpiredError(CredentialError):
    """Credential has expired."""

    def __init__(self, credential_id: str) -> None:
        super().__init__("Credential has expired", credential_id, "CREDENTIAL_EXPIRED")


# =============================================================================
# Revocation Errors
# =============================================================================

class RevocationError(IdentityError):
    """Base exception for revocation-related errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "REVOCATION_ERROR",
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, error_code, context)


class CredentialRevokedError(RevocationError):
    """Credential has been revoked and is no longer valid."""

    def __init__(self, handler_id: Optional[str] = None) -> None:
        safe_handler = handler_id[:10] + "..." if handler_id and len(handler_id) > 10 else handler_id
        super().__init__(
            "Credential has been revoked",
            error_code="CREDENTIAL_REVOKED",
            context={"handler_prefix": safe_handler} if safe_handler else {},
        )


class WitnessUpdateError(RevocationError):
    """Failed to update witness for non-revocation proof."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="WITNESS_UPDATE_FAILED")


class NonRevocationProofError(RevocationError):
    """Failed to create or verify non-revocation proof."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="NON_REVOCATION_PROOF_FAILED")


# =============================================================================
# Authorization Errors (ABAC)
# =============================================================================

class AuthorizationError(ArbiterError):
    """Base exception for authorization-related errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "AUTHORIZATION_ERROR",
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, error_code, context)


class AccessDeniedError(AuthorizationError):
    """Access to resource was denied by policy."""

    def __init__(
        self,
        resource_id: str,
        action: str,
        reason: str = "Policy denied access",
    ) -> None:
        super().__init__(
            reason,
            error_code="ACCESS_DENIED",
            context={"resource": resource_id, "action": action},
        )


class PolicyError(AuthorizationError):
    """Policy-related operation failed."""

    def __init__(self, message: str, policy_id: Optional[str] = None) -> None:
        super().__init__(
            message,
            error_code="POLICY_ERROR",
            context={"policy_id": policy_id} if policy_id else {},
        )


class PolicyNotFoundError(PolicyError):
    """Requested policy was not found."""

    def __init__(self, policy_id: str) -> None:
        super().__init__(f"Policy not found: {policy_id}", policy_id)
        self.error_code = "POLICY_NOT_FOUND"


class PolicyValidationError(PolicyError):
    """Policy failed validation."""

    def __init__(self, message: str, policy_id: Optional[str] = None) -> None:
        super().__init__(message, policy_id)
        self.error_code = "POLICY_VALIDATION_FAILED"


class AttributeError(AuthorizationError):
    """Failed to retrieve required attribute."""

    def __init__(self, attribute_id: str, category: str) -> None:
        super().__init__(
            f"Failed to retrieve attribute: {attribute_id}",
            error_code="ATTRIBUTE_ERROR",
            context={"attribute_id": attribute_id, "category": category},
        )


# =============================================================================
# Registry/Ledger Errors
# =============================================================================

class RegistryError(ArbiterError):
    """Base exception for registry/ledger operations."""

    def __init__(
        self,
        message: str,
        error_code: str = "REGISTRY_ERROR",
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, error_code, context)


class RegistryConnectionError(RegistryError):
    """Failed to connect to registry/ledger."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="REGISTRY_CONNECTION_FAILED")


class RegistryPublishError(RegistryError):
    """Failed to publish to registry/ledger."""

    def __init__(self, message: str, entry_type: str) -> None:
        super().__init__(
            message,
            error_code="REGISTRY_PUBLISH_FAILED",
            context={"entry_type": entry_type},
        )


# =============================================================================
# Verification Errors
# =============================================================================

class VerificationError(ArbiterError):
    """Verification operation failed."""

    def __init__(
        self,
        message: str,
        verification_type: str,
        error_code: str = "VERIFICATION_FAILED",
    ) -> None:
        super().__init__(
            message,
            error_code=error_code,
            context={"verification_type": verification_type},
        )


class TrustDecisionError(VerificationError):
    """Failed to make trust decision."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "trust_decision", "TRUST_DECISION_FAILED")


# =============================================================================
# Homomorphic Encryption Errors
# =============================================================================

class HomomorphicError(CryptoError):
    """Homomorphic encryption operation failed."""

    def __init__(self, message: str, operation: str) -> None:
        super().__init__(
            message,
            error_code="HOMOMORPHIC_ERROR",
            context={"operation": operation},
        )


class HomomorphicKeyMismatchError(HomomorphicError):
    """Attempted operation on values encrypted with different keys."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot perform operation on values encrypted with different keys",
            operation="mixed_key_operation",
        )
        self.error_code = "HOMOMORPHIC_KEY_MISMATCH"
