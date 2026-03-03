"""
Arbiter - Identity Layer Package

Provides decentralized identity management for AI agents.

Components:
- DID: Decentralized Identifiers (W3C compliant)
- Key Management: PQC + classical key handling
- VC Issuer: Verifiable Credentials with BBS+
- ZKP Proofs: Zero-knowledge proof generation
- Verification Hub: Stateless trust verification
- Revocation: 5-algorithm revocation system
- Registry: Blockchain/ledger interface
"""

from arbiter.identity.did import (
    DID,
    DIDDocumentBuilder,
    create_did_from_keys,
    verify_did_document_integrity,
    extract_key_for_purpose,
    DID_METHOD,
    KEY_TYPE_DILITHIUM3,
    KEY_TYPE_KYBER768,
    KEY_TYPE_BBS,
    RELATIONSHIP_AUTHENTICATION,
    RELATIONSHIP_ASSERTION,
)

from arbiter.identity.key_management import (
    KeyManager,
    KeyPurpose,
    KeyStatus,
    KeyMetadata,
    ManagedKeyPair,
    KeyStorage,
    InMemoryKeyStorage,
)

from arbiter.identity.vc_issuer import (
    VCIssuer,
    IssuerConfig,
    CredentialRequest,
    IssuedCredentialBundle,
    verify_credential_signature,
    CREDENTIAL_TYPE_AGENT_IDENTITY,
    CREDENTIAL_TYPE_CAPABILITY,
)

from arbiter.identity.zkp_proofs import (
    ProofGenerator,
    ProofVerifier,
    ProofRequest,
    create_proof_request,
)

from arbiter.identity.verification_hub import (
    VerificationHub,
    VerificationContext,
    VerificationResult,
    TrustDecision,
    quick_verify,
)

from arbiter.identity.revocation import (
    RevocationManager,
    RevocationRegistryState,
    CredentialHandle,
    WitnessManager,
)

from arbiter.identity.registry_interface import (
    RegistryInterface,
    InMemoryRegistry,
    DIDResolver,
    ResolutionResult,
    PublishResult,
)

__all__ = [
    # DID
    "DID",
    "DIDDocumentBuilder",
    "create_did_from_keys",
    "verify_did_document_integrity",
    "extract_key_for_purpose",
    "DID_METHOD",
    "KEY_TYPE_DILITHIUM3",
    "KEY_TYPE_KYBER768",
    "KEY_TYPE_BBS",
    "RELATIONSHIP_AUTHENTICATION",
    "RELATIONSHIP_ASSERTION",
    # Key Management
    "KeyManager",
    "KeyPurpose",
    "KeyStatus",
    "KeyMetadata",
    "ManagedKeyPair",
    "KeyStorage",
    "InMemoryKeyStorage",
    # VC Issuer
    "VCIssuer",
    "IssuerConfig",
    "CredentialRequest",
    "IssuedCredentialBundle",
    "verify_credential_signature",
    "CREDENTIAL_TYPE_AGENT_IDENTITY",
    "CREDENTIAL_TYPE_CAPABILITY",
    # ZKP
    "ProofGenerator",
    "ProofVerifier",
    "ProofRequest",
    "create_proof_request",
    # Verification
    "VerificationHub",
    "VerificationContext",
    "VerificationResult",
    "TrustDecision",
    "quick_verify",
    # Revocation
    "RevocationManager",
    "RevocationRegistryState",
    "CredentialHandle",
    "WitnessManager",
    # Registry
    "RegistryInterface",
    "InMemoryRegistry",
    "DIDResolver",
    "ResolutionResult",
    "PublishResult",
]
