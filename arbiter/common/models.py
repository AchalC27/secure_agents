"""
Arbiter - Common Data Models

This module defines all core data structures used across the Identity and Integrity layers.
All models are designed to be:
- Immutable where possible (frozen dataclasses)
- Fully type-hinted
- JSON-serializable

References:
- W3C DID Core Specification: https://www.w3.org/TR/did-core/
- W3C Verifiable Credentials: https://www.w3.org/TR/vc-data-model/
- NIST ABAC Guide: https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-162.pdf
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Optional


# =============================================================================
# Cryptographic Material Types
# =============================================================================

@dataclass(frozen=True)
class PublicKey:
    """Public key with algorithm metadata.
    
    Attributes:
        key_id: Unique identifier for this key (e.g., "did:arbiter:abc#key-1")
        key_type: Algorithm type (e.g., "Dilithium3", "Ed25519", "BBS+")
        public_key_bytes: Raw public key material
        controller: DID of the entity controlling this key
    """
    key_id: str
    key_type: str
    public_key_bytes: bytes
    controller: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to W3C-compatible verification method format."""
        return {
            "id": self.key_id,
            "type": self.key_type,
            "controller": self.controller,
            "publicKeyMultibase": _bytes_to_multibase(self.public_key_bytes),
        }


@dataclass(frozen=True)
class PrivateKey:
    """Private key material - NEVER serialize or transmit.
    
    Threat Model Note:
        This structure should only exist in secure memory.
        Key material should be zeroized after use in production.
    """
    key_id: str
    key_type: str
    private_key_bytes: bytes
    public_key: PublicKey


# =============================================================================
# DID (Decentralized Identifier) Models
# =============================================================================

@dataclass(frozen=True)
class ServiceEndpoint:
    """Service endpoint for DID Document.
    
    Defines how to interact with the agent for specific purposes.
    """
    id: str
    type: str
    service_endpoint: str


@dataclass
class DIDDocument:
    """W3C DID Document structure.
    
    Reference: https://www.w3.org/TR/did-core/#did-document-properties
    
    The DID Document is the core identity document that:
    - Lists all verification methods (public keys)
    - Defines service endpoints
    - Specifies authentication and assertion methods
    
    Attributes:
        id: The DID this document describes (e.g., "did:arbiter:abc123")
        verification_method: List of public keys
        authentication: Key IDs usable for authentication
        assertion_method: Key IDs usable for signing credentials
        service: Service endpoints for agent communication
        created: Document creation timestamp
        updated: Last modification timestamp
    """
    id: str
    verification_method: list[PublicKey] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    assertion_method: list[str] = field(default_factory=list)
    capability_invocation: list[str] = field(default_factory=list)
    capability_delegation: list[str] = field(default_factory=list)
    service: list[ServiceEndpoint] = field(default_factory=list)
    created: Optional[datetime] = None
    updated: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to W3C DID Document JSON format."""
        doc: dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/bls12381-2020/v1",
            ],
            "id": self.id,
            "verificationMethod": [vm.to_dict() for vm in self.verification_method],
        }
        if self.authentication:
            doc["authentication"] = self.authentication
        if self.assertion_method:
            doc["assertionMethod"] = self.assertion_method
        if self.capability_invocation:
            doc["capabilityInvocation"] = self.capability_invocation
        if self.capability_delegation:
            doc["capabilityDelegation"] = self.capability_delegation
        if self.service:
            doc["service"] = [
                {"id": s.id, "type": s.type, "serviceEndpoint": s.service_endpoint}
                for s in self.service
            ]
        if self.created:
            doc["created"] = self.created.isoformat()
        if self.updated:
            doc["updated"] = self.updated.isoformat()
        return doc

    def get_hash(self) -> bytes:
        """Compute deterministic hash of DID Document for integrity verification."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).digest()


# =============================================================================
# Verifiable Credentials Models
# =============================================================================

@dataclass(frozen=True)
class CredentialSubject:
    """Subject of a Verifiable Credential with claims.
    
    Attributes:
        id: DID of the credential subject (the agent)
        claims: Key-value pairs of credential claims/attributes
    """
    id: str
    claims: dict[str, Any]


@dataclass(frozen=True)
class RevocationInfo:
    """Revocation information embedded in credential.
    
    Implements Algorithm 2 (Credential Issuance) revocation handler.
    
    Attributes:
        handler_id: Unique revocation handler for this credential
        accumulator_id: ID of the accumulator containing this credential
        witness: Membership witness for non-revocation proof
    """
    handler_id: str
    accumulator_id: str
    witness: bytes


@dataclass(frozen=True)
class Proof:
    """Cryptographic proof attached to a credential or presentation.
    
    Attributes:
        type: Proof type (e.g., "BBS+Signature2020", "ZKProof")
        created: Proof creation timestamp
        verification_method: Key ID used to create proof
        proof_purpose: Purpose of proof (e.g., "assertionMethod")
        proof_value: The actual cryptographic proof bytes
    """
    type: str
    created: datetime
    verification_method: str
    proof_purpose: str
    proof_value: bytes

    def to_dict(self) -> dict[str, Any]:
        """Serialize proof to JSON format."""
        return {
            "type": self.type,
            "created": self.created.isoformat(),
            "verificationMethod": self.verification_method,
            "proofPurpose": self.proof_purpose,
            "proofValue": _bytes_to_multibase(self.proof_value),
        }


@dataclass
class VerifiableCredential:
    """W3C Verifiable Credential with BBS+ signature support.
    
    Reference: https://www.w3.org/TR/vc-data-model/
    
    This credential supports:
    - Selective disclosure via BBS+ signatures
    - Embedded revocation handler for instant revocation
    - Zero-knowledge presentation without revealing full credential
    
    Attributes:
        context: JSON-LD context
        id: Unique credential identifier
        type: Credential types (must include "VerifiableCredential")
        issuer: DID of the credential issuer
        issuance_date: When credential was issued
        expiration_date: Optional expiration timestamp
        credential_subject: The subject and their claims
        revocation: Revocation information for non-revocation proofs
        proof: Issuer's cryptographic signature (BBS+)
    """
    id: str
    issuer: str
    issuance_date: datetime
    credential_subject: CredentialSubject
    revocation: RevocationInfo
    context: list[str] = field(default_factory=lambda: [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/bbs/v1",
    ])
    type: list[str] = field(default_factory=lambda: ["VerifiableCredential"])
    expiration_date: Optional[datetime] = None
    proof: Optional[Proof] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize credential to W3C VC JSON format."""
        vc: dict[str, Any] = {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date.isoformat(),
            "credentialSubject": {
                "id": self.credential_subject.id,
                **self.credential_subject.claims,
            },
            "credentialStatus": {
                "type": "AccumulatorRevocation2024",
                "handlerId": self.revocation.handler_id,
                "accumulatorId": self.revocation.accumulator_id,
            },
        }
        if self.expiration_date:
            vc["expirationDate"] = self.expiration_date.isoformat()
        if self.proof:
            vc["proof"] = self.proof.to_dict()
        return vc

    def get_messages(self) -> list[bytes]:
        """Extract messages for BBS+ signing.
        
        Each claim becomes a separate message, enabling selective disclosure.
        """
        messages = [
            self.id.encode(),
            self.issuer.encode(),
            self.issuance_date.isoformat().encode(),
            self.credential_subject.id.encode(),
        ]
        for key, value in sorted(self.credential_subject.claims.items()):
            messages.append(f"{key}:{json.dumps(value)}".encode())
        return messages


# =============================================================================
# Zero-Knowledge Proof Models
# =============================================================================

class ProofType(Enum):
    """Types of zero-knowledge proofs supported."""
    CREDENTIAL_VALIDITY = auto()
    NON_REVOCATION = auto()
    CAPABILITY_POSSESSION = auto()
    SELECTIVE_DISCLOSURE = auto()


@dataclass(frozen=True)
class ZKProof:
    """Zero-Knowledge Proof for privacy-preserving verification.
    
    Implements Algorithm 3 (Credential Presentation).
    
    This proof allows an agent to prove:
    - They possess a valid credential
    - The credential is not revoked
    - They possess specific capabilities
    WITHOUT revealing the actual credential or identity details.
    
    Attributes:
        proof_type: What this proof demonstrates
        challenge: Verifier's challenge (for non-interactivity)
        proof_data: The actual ZK proof bytes
        disclosed_attributes: Attribute names being revealed (for selective disclosure)
        disclosed_values: Values of disclosed attributes
        accumulator_value: Current accumulator state (for non-revocation)
    """
    proof_type: ProofType
    challenge: bytes
    proof_data: bytes
    disclosed_attributes: list[str] = field(default_factory=list)
    disclosed_values: dict[str, Any] = field(default_factory=dict)
    accumulator_value: Optional[bytes] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize ZK proof to JSON format."""
        return {
            "type": self.proof_type.name,
            "challenge": _bytes_to_multibase(self.challenge),
            "proofData": _bytes_to_multibase(self.proof_data),
            "disclosedAttributes": self.disclosed_attributes,
            "disclosedValues": self.disclosed_values,
            "accumulatorValue": _bytes_to_multibase(self.accumulator_value) if self.accumulator_value else None,
        }


@dataclass
class VerifiablePresentation:
    """Verifiable Presentation wrapping ZK proofs.
    
    An agent creates a presentation to prove claims to a verifier
    without revealing the underlying credential.
    
    Attributes:
        holder: DID of the presenting agent
        verifiable_credential: Reference to the underlying credential (not revealed)
        zkp_proofs: Zero-knowledge proofs for various claims
        challenge: Verifier's challenge to prevent replay
        domain: Intended audience/verifier domain
    """
    holder: str
    challenge: bytes
    domain: str
    zkp_proofs: list[ZKProof] = field(default_factory=list)
    credential_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize presentation to JSON format."""
        return {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": self.holder,
            "challenge": _bytes_to_multibase(self.challenge),
            "domain": self.domain,
            "proof": [p.to_dict() for p in self.zkp_proofs],
        }


# =============================================================================
# ABAC (Attribute-Based Access Control) Models
# =============================================================================

class Effect(Enum):
    """Policy decision effects."""
    PERMIT = "permit"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


class ConditionOperator(Enum):
    """Operators for policy conditions."""
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN_OR_EQUAL = "lte"
    CONTAINS = "contains"
    IN = "in"
    REGEX = "regex"


@dataclass(frozen=True)
class Condition:
    """Single condition in a policy rule.
    
    Attributes:
        attribute_category: Category of attribute (subject, resource, action, environment)
        attribute_id: Specific attribute to check
        operator: Comparison operator
        value: Expected value for comparison
    """
    attribute_category: str  # subject, resource, action, environment
    attribute_id: str
    operator: ConditionOperator
    value: Any


@dataclass(frozen=True)
class PolicyRule:
    """Single rule within a policy.
    
    All conditions must be satisfied for the rule to apply (AND logic).
    
    Attributes:
        rule_id: Unique identifier for this rule
        effect: What happens if rule matches (PERMIT or DENY)
        conditions: List of conditions that must all be true
        description: Human-readable rule description
    """
    rule_id: str
    effect: Effect
    conditions: list[Condition]
    description: str = ""


@dataclass
class Policy:
    """ABAC Policy containing multiple rules.
    
    Reference: NIST SP 800-162 - Guide to ABAC
    
    Policies are evaluated deterministically:
    1. First matching DENY rule wins
    2. If no DENY, first matching PERMIT wins
    3. If no match, NOT_APPLICABLE
    
    Attributes:
        policy_id: Unique policy identifier
        version: Policy version for updates
        rules: Ordered list of rules to evaluate
        target: Optional pre-filter (resource type, action type)
        created: Creation timestamp
        updated: Last update timestamp
    """
    policy_id: str
    version: str
    rules: list[PolicyRule]
    target: Optional[dict[str, Any]] = None
    created: Optional[datetime] = None
    updated: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy to JSON format."""
        return {
            "policyId": self.policy_id,
            "version": self.version,
            "target": self.target,
            "rules": [
                {
                    "ruleId": r.rule_id,
                    "effect": r.effect.value,
                    "conditions": [
                        {
                            "category": c.attribute_category,
                            "attributeId": c.attribute_id,
                            "operator": c.operator.value,
                            "value": c.value,
                        }
                        for c in r.conditions
                    ],
                    "description": r.description,
                }
                for r in self.rules
            ],
            "created": self.created.isoformat() if self.created else None,
            "updated": self.updated.isoformat() if self.updated else None,
        }


@dataclass
class AccessRequest:
    """Access request to be evaluated by ABAC.
    
    Attributes:
        request_id: Unique request identifier
        subject_did: DID of the requesting agent
        resource_id: Identifier of the resource being accessed
        action: Action being performed
        environment: Environmental context (time, location, etc.)
        presentation: Optional ZK presentation proving attributes
    """
    request_id: str
    subject_did: str
    resource_id: str
    action: str
    environment: dict[str, Any] = field(default_factory=dict)
    presentation: Optional[VerifiablePresentation] = None


@dataclass(frozen=True)
class AccessDecision:
    """Access decision from PDP.
    
    Attributes:
        request_id: ID of the request this decision is for
        effect: The decision (PERMIT/DENY/etc.)
        policy_id: ID of the policy that made the decision
        rule_id: ID of the specific rule that matched
        reason: Human-readable explanation
        obligations: Actions that must be taken if permitted
    """
    request_id: str
    effect: Effect
    policy_id: Optional[str] = None
    rule_id: Optional[str] = None
    reason: str = ""
    obligations: list[dict[str, Any]] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)


# =============================================================================
# Homomorphic Encryption Models
# =============================================================================

@dataclass(frozen=True)
class EncryptedValue:
    """Paillier-encrypted value.
    
    Supports homomorphic operations:
    - Addition of encrypted values
    - Scalar multiplication
    
    Threat Model Note:
        The plaintext value is NEVER accessible to agents.
        Only the aggregator/authority can decrypt.
    
    Attributes:
        ciphertext: The encrypted value
        public_key_hash: Hash of the public key used for encryption
    """
    ciphertext: int  # Paillier ciphertext is an integer
    public_key_hash: str


# =============================================================================
# Registry/Ledger Models
# =============================================================================

@dataclass(frozen=True)
class RegistryEntry:
    """Entry in the decentralized registry.
    
    Attributes:
        entry_type: Type of entry (did, credential, revocation)
        entry_id: Unique identifier
        data_hash: Hash of the stored data
        timestamp: When entry was created
        signature: Signature from the entry creator
    """
    entry_type: str
    entry_id: str
    data_hash: bytes
    timestamp: datetime
    signature: bytes


@dataclass
class AccumulatorState:
    """Current state of the cryptographic accumulator.
    
    Implements Algorithm 4 (Revocation) state publication.
    
    Attributes:
        accumulator_id: Unique accumulator identifier
        value: Current accumulator value
        epoch: Version/epoch number (monotonically increasing)
        revoked_handlers: List of revoked credential handlers
        timestamp: When this state was published
    """
    accumulator_id: str
    value: bytes
    epoch: int
    revoked_handlers: list[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None


# =============================================================================
# Utility Functions
# =============================================================================

def _bytes_to_multibase(data: bytes) -> str:
    """Encode bytes to multibase format (base58btc).
    
    Multibase prefix 'z' indicates base58btc encoding.
    """
    if not data:
        return ""
    # Base58 alphabet (Bitcoin style)
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    if num == 0:
        return "z" + alphabet[0]
    
    result = []
    while num:
        num, remainder = divmod(num, 58)
        result.append(alphabet[remainder])
    
    # Handle leading zeros
    for byte in data:
        if byte == 0:
            result.append(alphabet[0])
        else:
            break
    
    return "z" + "".join(reversed(result))


def multibase_to_bytes(encoded: str) -> bytes:
    """Decode multibase (base58btc) to bytes."""
    if not encoded or encoded[0] != "z":
        raise ValueError("Invalid multibase encoding (expected base58btc with 'z' prefix)")
    
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = encoded[1:]
    
    num = 0
    for char in data:
        num = num * 58 + alphabet.index(char)
    
    # Calculate byte length
    byte_length = (num.bit_length() + 7) // 8
    if byte_length == 0:
        byte_length = 1
    
    return num.to_bytes(byte_length, "big")
