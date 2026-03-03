"""
Arbiter - Zero-Knowledge Proofs Module

Implements zero-knowledge proof generation for privacy-preserving verification.

ZK proofs enable agents to prove:
- Credential validity (without revealing the credential)
- Non-revocation (without revealing revocation handler)
- Capability possession (without revealing full capabilities)
- Attribute predicates (e.g., age > 18 without revealing actual age)

References:
- Algorithm 3: Credential Presentation (Arbiter)
- BBS+ Selective Disclosure
- Schnorr Protocol for discrete log proofs

Threat Model:
    Proofs must be:
    - Zero-knowledge: Verifier learns nothing beyond the proven statement
    - Sound: Cannot forge proofs for false statements
    - Non-transferable: Proofs are bound to specific verifier/challenge
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from arbiter.common.models import (
    ZKProof,
    ProofType,
    VerifiablePresentation,
    VerifiableCredential,
    Proof,
)
from arbiter.common.errors import ProofError
from arbiter.common.utils import (
    sha256_hash,
    bytes_to_base58,
    utc_now,
    generate_challenge,
)
from arbiter.crypto.bbs_plus import (
    BBSSignature,
    BBSPublicKey,
    BBSProof,
    bbs_create_proof,
    bbs_verify_proof,
)
from arbiter.crypto.accumulators import (
    AccumulatorPublicParams,
    Witness,
)
from arbiter.crypto.commitments import (
    hash_commit,
    HashCommitment,
)


# =============================================================================
# Proof Request
# =============================================================================

@dataclass
class ProofRequest:
    """Request specifying what proofs are needed.
    
    Sent by a verifier to specify requirements.
    
    Attributes:
        challenge: Unique challenge to prevent replay
        domain: Verifier's domain (for binding)
        required_proofs: Types of proofs required
        required_attributes: Attributes that must be disclosed
        predicate_requirements: Predicates that must be proven
        nonce: Additional nonce for freshness
    """
    challenge: bytes
    domain: str
    required_proofs: List[ProofType]
    required_attributes: List[str] = field(default_factory=list)
    predicate_requirements: Dict[str, Any] = field(default_factory=dict)
    nonce: bytes = field(default_factory=lambda: secrets.token_bytes(32))


# =============================================================================
# Proof Generator
# =============================================================================

class ProofGenerator:
    """Generates zero-knowledge proofs for credentials.
    
    Implements Algorithm 3: Credential Presentation
    
    The generator creates proofs that:
    - Prove credential validity (BBS+ signature)
    - Prove non-revocation (accumulator witness)
    - Selectively disclose attributes
    - Prove predicates without revealing values
    """

    def __init__(
        self,
        holder_did: str,
        credential: VerifiableCredential,
        signature: BBSSignature,
        witness: Witness,
        handler_element: int,
    ) -> None:
        """Initialize proof generator with credential data.
        
        Args:
            holder_did: DID of the credential holder
            credential: The credential to prove
            signature: BBS+ signature on credential
            witness: Accumulator witness for non-revocation
            handler_element: The accumulator element
        """
        self.holder_did = holder_did
        self.credential = credential
        self.signature = signature
        self.witness = witness
        self.handler_element = handler_element

    def generate_presentation(
        self,
        request: ProofRequest,
        issuer_public_key: BBSPublicKey,
        accumulator_value: int,
        disclosed_attributes: Optional[List[str]] = None,
    ) -> VerifiablePresentation:
        """Generate a verifiable presentation with required proofs.
        
        Algorithm 3: Credential Presentation
        
        Steps:
        1. Create BBS+ selective disclosure proof
        2. Create non-revocation proof
        3. Create any additional required proofs
        4. Bundle into verifiable presentation
        
        Args:
            request: Proof request from verifier
            issuer_public_key: Issuer's public key for proof generation
            accumulator_value: Current accumulator value
            disclosed_attributes: Attributes to reveal (optional)
            
        Returns:
            VerifiablePresentation with all required proofs
        """
        zkp_proofs: List[ZKProof] = []
        
        # Determine which attributes to disclose
        disclose = set(disclosed_attributes or [])
        disclose.update(request.required_attributes)
        
        # Generate credential validity proof
        if ProofType.CREDENTIAL_VALIDITY in request.required_proofs:
            validity_proof = self._generate_validity_proof(
                request.challenge,
                issuer_public_key,
                list(disclose),
            )
            zkp_proofs.append(validity_proof)
        
        # Generate non-revocation proof
        if ProofType.NON_REVOCATION in request.required_proofs:
            non_revocation_proof = self._generate_non_revocation_proof(
                request.challenge,
                accumulator_value,
            )
            zkp_proofs.append(non_revocation_proof)
        
        # Generate capability possession proof
        if ProofType.CAPABILITY_POSSESSION in request.required_proofs:
            capability_proof = self._generate_capability_proof(
                request.challenge,
                request.predicate_requirements,
            )
            zkp_proofs.append(capability_proof)
        
        # Generate selective disclosure proof
        if ProofType.SELECTIVE_DISCLOSURE in request.required_proofs:
            disclosure_proof = self._generate_selective_disclosure_proof(
                request.challenge,
                issuer_public_key,
                list(disclose),
            )
            zkp_proofs.append(disclosure_proof)
        
        # Create presentation
        presentation = VerifiablePresentation(
            holder=self.holder_did,
            challenge=request.challenge,
            domain=request.domain,
            zkp_proofs=zkp_proofs,
            credential_id=self.credential.id,
        )
        
        return presentation

    def _generate_validity_proof(
        self,
        challenge: bytes,
        issuer_public_key: BBSPublicKey,
        disclosed_attributes: List[str],
    ) -> ZKProof:
        """Generate proof of credential validity.
        
        Proves the holder possesses a credential validly signed
        by the issuer, without revealing the full credential.
        
        Args:
            challenge: Verifier's challenge
            issuer_public_key: Issuer's public key
            disclosed_attributes: Attributes to reveal
            
        Returns:
            ZKProof for credential validity
        """
        # Get all messages from credential
        messages = self.credential.get_messages()
        
        # Determine which indices to disclose
        disclosed_indices = self._get_attribute_indices(disclosed_attributes)
        
        # Create BBS+ proof
        bbs_proof = bbs_create_proof(
            issuer_public_key,
            self.signature,
            messages,
            disclosed_indices,
            challenge,
        )
        
        # Extract disclosed values
        disclosed_values = {}
        claims = self.credential.credential_subject.claims
        for attr in disclosed_attributes:
            if attr in claims:
                disclosed_values[attr] = claims[attr]
        
        return ZKProof(
            proof_type=ProofType.CREDENTIAL_VALIDITY,
            challenge=challenge,
            proof_data=bbs_proof.proof_bytes,
            disclosed_attributes=disclosed_attributes,
            disclosed_values=disclosed_values,
        )

    def _generate_non_revocation_proof(
        self,
        challenge: bytes,
        accumulator_value: int,
    ) -> ZKProof:
        """Generate proof of non-revocation.
        
        Algorithm 3: Non-revocation proof component
        
        Proves the credential's revocation handler is still in
        the accumulator (not revoked) without revealing the handler.
        
        Args:
            challenge: Verifier's challenge
            accumulator_value: Current accumulator value
            
        Returns:
            ZKProof for non-revocation
        """
        # PLACEHOLDER: In production, this would be a proper
        # zero-knowledge proof of accumulator membership
        
        # Create commitment to handler element
        handler_bytes = self.handler_element.to_bytes(32, "big")
        commitment = hash_commit(handler_bytes)
        
        # Create "proof" that witness^element = accumulator
        # Real ZK proof would hide element while proving this relation
        witness_bytes = self.witness.witness_value.to_bytes(256, "big")
        acc_bytes = accumulator_value.to_bytes(256, "big")
        
        proof_input = (
            challenge +
            commitment.commitment +
            witness_bytes +
            acc_bytes
        )
        proof_data = sha256_hash(proof_input) + commitment.randomness
        
        return ZKProof(
            proof_type=ProofType.NON_REVOCATION,
            challenge=challenge,
            proof_data=proof_data,
            accumulator_value=acc_bytes,
        )

    def _generate_capability_proof(
        self,
        challenge: bytes,
        requirements: Dict[str, Any],
    ) -> ZKProof:
        """Generate proof of capability possession.
        
        Proves the credential grants specific capabilities
        without revealing all capabilities.
        
        Args:
            challenge: Verifier's challenge
            requirements: Required capabilities to prove
            
        Returns:
            ZKProof for capability possession
        """
        claims = self.credential.credential_subject.claims
        
        # Check if credential has capabilities
        capabilities = claims.get("capabilities", [])
        
        # Prove each required capability
        proven_capabilities = []
        for required in requirements.get("required_capabilities", []):
            if required in capabilities:
                proven_capabilities.append(required)
        
        # Create proof
        proof_input = challenge + str(proven_capabilities).encode()
        proof_data = sha256_hash(proof_input)
        
        return ZKProof(
            proof_type=ProofType.CAPABILITY_POSSESSION,
            challenge=challenge,
            proof_data=proof_data,
            disclosed_attributes=["capabilities"],
            disclosed_values={"proven_capabilities": proven_capabilities},
        )

    def _generate_selective_disclosure_proof(
        self,
        challenge: bytes,
        issuer_public_key: BBSPublicKey,
        disclosed_attributes: List[str],
    ) -> ZKProof:
        """Generate selective disclosure proof.
        
        Reveals only specified attributes while hiding others.
        
        Args:
            challenge: Verifier's challenge
            issuer_public_key: Issuer's public key
            disclosed_attributes: Attributes to reveal
            
        Returns:
            ZKProof with selective disclosure
        """
        messages = self.credential.get_messages()
        disclosed_indices = self._get_attribute_indices(disclosed_attributes)
        
        bbs_proof = bbs_create_proof(
            issuer_public_key,
            self.signature,
            messages,
            disclosed_indices,
            challenge,
        )
        
        # Get disclosed values
        disclosed_values = {}
        claims = self.credential.credential_subject.claims
        for attr in disclosed_attributes:
            if attr in claims:
                disclosed_values[attr] = claims[attr]
        
        return ZKProof(
            proof_type=ProofType.SELECTIVE_DISCLOSURE,
            challenge=challenge,
            proof_data=bbs_proof.proof_bytes,
            disclosed_attributes=disclosed_attributes,
            disclosed_values=disclosed_values,
        )

    def _get_attribute_indices(self, attributes: List[str]) -> List[int]:
        """Map attribute names to message indices.
        
        The credential messages are structured as:
        0: credential ID
        1: issuer
        2: issuance date
        3: subject ID
        4+: claims (sorted by key)
        
        Args:
            attributes: Attribute names to map
            
        Returns:
            List of message indices
        """
        # Fixed message indices
        attribute_map = {
            "_credential_id": 0,
            "_issuer": 1,
            "_issuance_date": 2,
            "_subject_id": 3,
        }
        
        # Map claims (sorted)
        sorted_claims = sorted(self.credential.credential_subject.claims.keys())
        for i, key in enumerate(sorted_claims):
            attribute_map[key] = 4 + i
        
        indices = []
        for attr in attributes:
            if attr in attribute_map:
                indices.append(attribute_map[attr])
        
        return indices


# =============================================================================
# Proof Verification
# =============================================================================

class ProofVerifier:
    """Verifies zero-knowledge proofs.
    
    Stateless verifier that validates proofs without
    needing access to the original credential.
    """

    def __init__(
        self,
        issuer_public_key: BBSPublicKey,
        accumulator_params: AccumulatorPublicParams,
    ) -> None:
        """Initialize verifier.
        
        Args:
            issuer_public_key: Issuer's public key
            accumulator_params: Accumulator parameters for non-revocation
        """
        self.issuer_public_key = issuer_public_key
        self.accumulator_params = accumulator_params

    def verify_proof(
        self,
        proof: ZKProof,
        expected_challenge: bytes,
        current_accumulator_value: Optional[int] = None,
    ) -> bool:
        """Verify a single ZK proof.
        
        Args:
            proof: Proof to verify
            expected_challenge: Expected challenge value
            current_accumulator_value: Current accumulator (for non-revocation)
            
        Returns:
            True if proof is valid
        """
        # Verify challenge matches
        if proof.challenge != expected_challenge:
            return False
        
        if proof.proof_type == ProofType.CREDENTIAL_VALIDITY:
            return self._verify_validity_proof(proof)
        
        elif proof.proof_type == ProofType.NON_REVOCATION:
            if current_accumulator_value is None:
                return False
            return self._verify_non_revocation_proof(proof, current_accumulator_value)
        
        elif proof.proof_type == ProofType.CAPABILITY_POSSESSION:
            return self._verify_capability_proof(proof)
        
        elif proof.proof_type == ProofType.SELECTIVE_DISCLOSURE:
            return self._verify_selective_disclosure_proof(proof)
        
        return False

    def verify_presentation(
        self,
        presentation: VerifiablePresentation,
        expected_challenge: bytes,
        expected_domain: str,
        current_accumulator_value: Optional[int] = None,
    ) -> bool:
        """Verify a complete verifiable presentation.
        
        Args:
            presentation: Presentation to verify
            expected_challenge: Expected challenge
            expected_domain: Expected domain
            current_accumulator_value: Current accumulator value
            
        Returns:
            True if all proofs are valid
        """
        # Verify challenge and domain
        if presentation.challenge != expected_challenge:
            return False
        
        if presentation.domain != expected_domain:
            return False
        
        # Verify all proofs
        for proof in presentation.zkp_proofs:
            if not self.verify_proof(proof, expected_challenge, current_accumulator_value):
                return False
        
        return True

    def _verify_validity_proof(self, proof: ZKProof) -> bool:
        """Verify credential validity proof."""
        # PLACEHOLDER: Would use BBS+ proof verification
        # bbs_verify_proof(self.issuer_public_key, bbs_proof, total_messages)
        return len(proof.proof_data) > 0

    def _verify_non_revocation_proof(
        self,
        proof: ZKProof,
        accumulator_value: int,
    ) -> bool:
        """Verify non-revocation proof."""
        if not proof.accumulator_value:
            return False
        
        # PLACEHOLDER: Would verify ZK proof of accumulator membership
        claimed_acc = int.from_bytes(proof.accumulator_value, "big")
        return claimed_acc == accumulator_value

    def _verify_capability_proof(self, proof: ZKProof) -> bool:
        """Verify capability possession proof."""
        # Check that proven capabilities are present
        proven = proof.disclosed_values.get("proven_capabilities", [])
        return len(proven) > 0

    def _verify_selective_disclosure_proof(self, proof: ZKProof) -> bool:
        """Verify selective disclosure proof."""
        # PLACEHOLDER: Would use BBS+ selective disclosure verification
        return len(proof.proof_data) > 0


# =============================================================================
# Utility Functions
# =============================================================================

def create_proof_request(
    domain: str,
    required_proofs: Optional[List[ProofType]] = None,
    required_attributes: Optional[List[str]] = None,
    predicate_requirements: Optional[Dict[str, Any]] = None,
) -> ProofRequest:
    """Create a new proof request with fresh challenge.
    
    Args:
        domain: Verifier's domain
        required_proofs: Types of proofs required
        required_attributes: Attributes that must be disclosed
        predicate_requirements: Predicates to prove
        
    Returns:
        ProofRequest with fresh challenge
    """
    return ProofRequest(
        challenge=generate_challenge(),
        domain=domain,
        required_proofs=required_proofs or [
            ProofType.CREDENTIAL_VALIDITY,
            ProofType.NON_REVOCATION,
        ],
        required_attributes=required_attributes or [],
        predicate_requirements=predicate_requirements or {},
    )
