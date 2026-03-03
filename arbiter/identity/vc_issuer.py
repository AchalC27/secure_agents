"""
Arbiter - Verifiable Credentials Issuer Module

Implements credential issuance using BBS+ signatures for selective disclosure.

References:
- W3C Verifiable Credentials Data Model: https://www.w3.org/TR/vc-data-model/
- BBS+ Signatures: https://identity.foundation/bbs-signature/
- Algorithm 2: Credential Issuance (from Arbiter specification)

Credential Flow:
1. Issuer creates credential with claims
2. Issuer signs using BBS+ (enabling selective disclosure)
3. Credential includes revocation handler
4. Holder can later prove claims without revealing full credential
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from arbiter.common.models import (
    VerifiableCredential,
    CredentialSubject,
    RevocationInfo,
    Proof,
)
from arbiter.common.errors import (
    CredentialIssuanceError,
    CredentialError,
)
from arbiter.common.utils import (
    generate_id,
    sha256_hash,
    utc_now,
    bytes_to_base58,
)
from arbiter.crypto.bbs_plus import (
    BBSKeyPair,
    BBSPrivateKey,
    BBSPublicKey,
    BBSSignature,
    bbs_sign,
    bbs_verify,
    generate_bbs_keypair,
)
from arbiter.crypto.accumulators import (
    AccumulatorManager,
    Witness,
)


# =============================================================================
# Credential Types
# =============================================================================

# Standard credential types
CREDENTIAL_TYPE_AGENT_IDENTITY = "AgentIdentityCredential"
CREDENTIAL_TYPE_CAPABILITY = "CapabilityCredential"
CREDENTIAL_TYPE_AUTHORIZATION = "AuthorizationCredential"
CREDENTIAL_TYPE_MEMBERSHIP = "MembershipCredential"


# =============================================================================
# Issuer Configuration
# =============================================================================

@dataclass
class IssuerConfig:
    """Configuration for credential issuer.
    
    Attributes:
        issuer_did: DID of the issuing authority
        signing_key: BBS+ key pair for signing credentials
        accumulator: Accumulator manager for revocation
        default_validity_days: Default credential validity period
        max_claims: Maximum claims per credential
    """
    issuer_did: str
    signing_key: BBSKeyPair
    accumulator: AccumulatorManager
    default_validity_days: int = 365
    max_claims: int = 10


# =============================================================================
# Credential Request
# =============================================================================

@dataclass
class CredentialRequest:
    """Request for a new credential.
    
    Submitted by an agent to request credential issuance.
    
    Attributes:
        subject_did: DID of the credential subject
        credential_type: Type of credential requested
        claims: Requested claims/attributes
        validity_days: Requested validity period (optional)
    """
    subject_did: str
    credential_type: str
    claims: Dict[str, Any]
    validity_days: Optional[int] = None


# =============================================================================
# Issued Credential Bundle
# =============================================================================

@dataclass
class IssuedCredentialBundle:
    """Complete credential bundle returned to holder.
    
    Algorithm 2 (Credential Issuance) output.
    
    Attributes:
        credential: The signed Verifiable Credential
        witness: Accumulator witness for non-revocation proofs
        handler_element: The prime element added to accumulator
        signature: Raw BBS+ signature for proof generation
    """
    credential: VerifiableCredential
    witness: Witness
    handler_element: int
    signature: BBSSignature


# =============================================================================
# Verifiable Credentials Issuer
# =============================================================================

class VCIssuer:
    """Verifiable Credentials Issuer using BBS+ signatures.
    
    Implements Algorithm 2: Credential Issuance
    
    The issuer:
    1. Creates credentials with specified claims
    2. Signs using BBS+ for selective disclosure
    3. Generates revocation handler and adds to accumulator
    4. Issues witness for non-revocation proofs
    
    Security Properties:
    - Only issuer can create credentials (signature)
    - Credentials support selective disclosure (BBS+)
    - Instant revocation via accumulator
    - Non-revocation provable without revealing credential
    """

    def __init__(self, config: IssuerConfig) -> None:
        """Initialize the issuer.
        
        Args:
            config: Issuer configuration including keys and accumulator
        """
        self.config = config
        self._issued_count = 0

    @classmethod
    def create(
        cls,
        issuer_did: str,
        max_claims: int = 10,
        default_validity_days: int = 365,
    ) -> "VCIssuer":
        """Create a new issuer with fresh keys.
        
        Args:
            issuer_did: DID of the issuing authority
            max_claims: Maximum claims per credential
            default_validity_days: Default validity period
            
        Returns:
            Configured VCIssuer instance
        """
        # Generate BBS+ key pair
        signing_key = generate_bbs_keypair(max_claims + 5)  # +5 for metadata
        
        # Initialize accumulator
        accumulator = AccumulatorManager()
        
        config = IssuerConfig(
            issuer_did=issuer_did,
            signing_key=signing_key,
            accumulator=accumulator,
            default_validity_days=default_validity_days,
            max_claims=max_claims,
        )
        
        return cls(config)

    def issue_credential(
        self,
        request: CredentialRequest,
    ) -> IssuedCredentialBundle:
        """Issue a new Verifiable Credential.
        
        Algorithm 2: Credential Issuance
        
        Steps:
        1. Validate request
        2. Create credential structure
        3. Generate revocation handler
        4. Add handler to accumulator (get witness)
        5. Sign with BBS+
        6. Return complete bundle
        
        Args:
            request: Credential request from subject
            
        Returns:
            IssuedCredentialBundle with credential and witness
            
        Raises:
            CredentialIssuanceError: If issuance fails
        """
        try:
            # Validate request
            self._validate_request(request)
            
            # Generate credential ID
            credential_id = self._generate_credential_id()
            
            # Calculate validity
            validity_days = request.validity_days or self.config.default_validity_days
            issuance_date = utc_now()
            expiration_date = issuance_date + timedelta(days=validity_days)
            
            # Create credential subject
            subject = CredentialSubject(
                id=request.subject_did,
                claims=request.claims,
            )
            
            # Generate revocation handler (unique identifier for this credential)
            handler_id = self._generate_handler_id(credential_id, request.subject_did)
            
            # Derive accumulator element from handler
            handler_element = self.config.accumulator.derive_element(handler_id)
            
            # Add to accumulator and get witness
            # Algorithm 2: Add revocation handler to accumulator
            witness = self.config.accumulator.add(handler_element)
            
            # Create revocation info
            revocation_info = RevocationInfo(
                handler_id=handler_id,
                accumulator_id=self.config.accumulator.params.accumulator_id,
                witness=witness.witness_value.to_bytes(256, "big"),
            )
            
            # Create credential (without proof first)
            credential = VerifiableCredential(
                id=credential_id,
                issuer=self.config.issuer_did,
                issuance_date=issuance_date,
                expiration_date=expiration_date,
                credential_subject=subject,
                revocation=revocation_info,
                type=["VerifiableCredential", request.credential_type],
            )
            
            # Get messages for BBS+ signing
            messages = credential.get_messages()
            
            # Sign with BBS+
            signature = bbs_sign(
                self.config.signing_key.private_key,
                messages,
            )
            
            # Create proof
            proof = Proof(
                type="BBSSignature2020",
                created=issuance_date,
                verification_method=f"{self.config.issuer_did}#assertion-key",
                proof_purpose="assertionMethod",
                proof_value=signature.to_bytes(),
            )
            
            # Attach proof to credential
            credential.proof = proof
            
            self._issued_count += 1
            
            return IssuedCredentialBundle(
                credential=credential,
                witness=witness,
                handler_element=handler_element,
                signature=signature,
            )
            
        except Exception as e:
            if isinstance(e, CredentialIssuanceError):
                raise
            raise CredentialIssuanceError(str(e)) from e

    def issue_agent_identity_credential(
        self,
        subject_did: str,
        agent_name: str,
        agent_type: str,
        capabilities: List[str],
        **additional_claims: Any,
    ) -> IssuedCredentialBundle:
        """Issue an Agent Identity credential.
        
        Convenience method for common agent identity credentials.
        
        Args:
            subject_did: DID of the agent
            agent_name: Human-readable agent name
            agent_type: Type of agent (e.g., "research", "assistant")
            capabilities: List of agent capabilities
            **additional_claims: Extra claims to include
            
        Returns:
            IssuedCredentialBundle
        """
        claims = {
            "agentName": agent_name,
            "agentType": agent_type,
            "capabilities": capabilities,
            **additional_claims,
        }
        
        request = CredentialRequest(
            subject_did=subject_did,
            credential_type=CREDENTIAL_TYPE_AGENT_IDENTITY,
            claims=claims,
        )
        
        return self.issue_credential(request)

    def issue_capability_credential(
        self,
        subject_did: str,
        capability: str,
        resource: str,
        actions: List[str],
        constraints: Optional[Dict[str, Any]] = None,
    ) -> IssuedCredentialBundle:
        """Issue a Capability credential.
        
        Grants specific capabilities to an agent.
        
        Args:
            subject_did: DID of the agent
            capability: Capability being granted
            resource: Resource the capability applies to
            actions: Allowed actions
            constraints: Optional constraints on the capability
            
        Returns:
            IssuedCredentialBundle
        """
        claims = {
            "capability": capability,
            "resource": resource,
            "actions": actions,
            "constraints": constraints or {},
        }
        
        request = CredentialRequest(
            subject_did=subject_did,
            credential_type=CREDENTIAL_TYPE_CAPABILITY,
            claims=claims,
        )
        
        return self.issue_credential(request)

    def get_public_key(self) -> BBSPublicKey:
        """Get the issuer's public key for verification.
        
        Returns:
            BBS+ public key
        """
        return self.config.signing_key.public_key

    def get_accumulator_value(self) -> bytes:
        """Get current accumulator value for non-revocation verification.
        
        Returns:
            Current accumulator value as bytes
        """
        return self.config.accumulator.current_value.to_bytes(256, "big")

    def get_accumulator_epoch(self) -> int:
        """Get current accumulator epoch.
        
        Returns:
            Current epoch number
        """
        return self.config.accumulator.current_epoch

    def _validate_request(self, request: CredentialRequest) -> None:
        """Validate a credential request.
        
        Args:
            request: Request to validate
            
        Raises:
            CredentialIssuanceError: If request is invalid
        """
        if not request.subject_did:
            raise CredentialIssuanceError("Subject DID is required")
        
        if not request.credential_type:
            raise CredentialIssuanceError("Credential type is required")
        
        if len(request.claims) > self.config.max_claims:
            raise CredentialIssuanceError(
                f"Too many claims: {len(request.claims)} > {self.config.max_claims}"
            )

    def _generate_credential_id(self) -> str:
        """Generate a unique credential identifier.
        
        Returns:
            URN-formatted credential ID
        """
        unique_part = generate_id(length=16)
        return f"urn:arbiter:credential:{unique_part}"

    def _generate_handler_id(
        self,
        credential_id: str,
        subject_did: str,
    ) -> str:
        """Generate a unique revocation handler ID.
        
        Deterministic based on credential and subject.
        
        Args:
            credential_id: Credential identifier
            subject_did: Subject DID
            
        Returns:
            Handler ID
        """
        combined = f"{credential_id}:{subject_did}:{self._issued_count}"
        hash_bytes = sha256_hash(combined.encode())
        return f"handler:{bytes_to_base58(hash_bytes[:16])}"


# =============================================================================
# Credential Verification (for Issuer-side)
# =============================================================================

def verify_credential_signature(
    credential: VerifiableCredential,
    issuer_public_key: BBSPublicKey,
) -> bool:
    """Verify a credential's BBS+ signature.
    
    This verifies the issuer's signature on the credential.
    It does NOT check revocation status (use ZKP for that).
    
    Args:
        credential: Credential to verify
        issuer_public_key: Issuer's BBS+ public key
        
    Returns:
        True if signature is valid
    """
    if not credential.proof:
        return False
    
    if credential.proof.type != "BBSSignature2020":
        return False
    
    try:
        # Reconstruct signature from proof
        signature = BBSSignature.from_bytes(credential.proof.proof_value)
        
        # Get messages
        messages = credential.get_messages()
        
        # Verify
        return bbs_verify(issuer_public_key, messages, signature)
        
    except Exception:
        return False
