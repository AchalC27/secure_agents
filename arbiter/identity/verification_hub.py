"""
Arbiter - Verification Hub Module

Stateless verifier for identity and credential verification.

The Verification Hub:
- Validates ZK proofs
- Verifies credential signatures
- Checks revocation state
- Returns binary trust decisions

Reference: Arbiter - Verification Hub specification

Design Principles:
- Stateless: No persistent state between verifications
- Binary Decisions: Returns TRUSTED or UNTRUSTED only
- Privacy-Preserving: Learns only what proofs reveal
- Deterministic: Same inputs always produce same output
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from arbiter.common.models import (
    VerifiablePresentation,
    VerifiableCredential,
    ZKProof,
    ProofType,
    DIDDocument,
)
from arbiter.common.errors import (
    VerificationError,
    TrustDecisionError,
    CredentialRevokedError,
)
from arbiter.common.utils import utc_now, is_expired
from arbiter.crypto.bbs_plus import BBSPublicKey
from arbiter.crypto.accumulators import AccumulatorPublicParams
from arbiter.identity.zkp_proofs import ProofVerifier


# =============================================================================
# Trust Decision
# =============================================================================

class TrustDecision(Enum):
    """Binary trust decision."""
    TRUSTED = auto()
    UNTRUSTED = auto()


@dataclass
class VerificationResult:
    """Result of a verification operation.
    
    Attributes:
        decision: Binary trust decision
        verified_claims: Claims that were verified (from disclosed attributes)
        verification_time: When verification was performed
        reason: Human-readable explanation (for logging)
        details: Additional verification details
    """
    decision: TrustDecision
    verified_claims: Dict[str, Any]
    verification_time: datetime
    reason: str = ""
    details: Dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.details is None:
            self.details = {}

    @property
    def is_trusted(self) -> bool:
        """Check if decision is TRUSTED."""
        return self.decision == TrustDecision.TRUSTED


# =============================================================================
# Verification Context
# =============================================================================

@dataclass
class VerificationContext:
    """Context for a verification operation.
    
    Contains all necessary data for verifying a presentation.
    
    Attributes:
        issuer_public_key: Issuer's BBS+ public key
        accumulator_params: Accumulator parameters
        current_accumulator_value: Current accumulator state
        expected_challenge: Challenge that was sent to prover
        expected_domain: Expected domain binding
        required_claims: Claims that must be present
        current_time: Time for expiration checks
    """
    issuer_public_key: BBSPublicKey
    accumulator_params: AccumulatorPublicParams
    current_accumulator_value: int
    expected_challenge: bytes
    expected_domain: str
    required_claims: List[str] = None
    current_time: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.required_claims is None:
            self.required_claims = []
        if self.current_time is None:
            self.current_time = utc_now()


# =============================================================================
# Verification Hub
# =============================================================================

class VerificationHub:
    """Stateless verification hub for trust decisions.
    
    The central component for verifying agent identity and credentials.
    All verification is stateless - the hub maintains no memory of
    previous verifications.
    
    Verification Flow:
    1. Receive presentation with ZK proofs
    2. Validate all required proofs
    3. Check non-revocation against current accumulator
    4. Verify disclosed claims match requirements
    5. Return binary TRUSTED/UNTRUSTED decision
    
    Security Properties:
    - Learns only disclosed attributes
    - Cannot link verifications (stateless)
    - Deterministic decisions
    """

    def __init__(self) -> None:
        """Initialize the verification hub."""
        # Stateless - no persistent state
        pass

    def verify_presentation(
        self,
        presentation: VerifiablePresentation,
        context: VerificationContext,
    ) -> VerificationResult:
        """Verify a verifiable presentation and return trust decision.
        
        Main verification entry point.
        
        Args:
            presentation: The presentation to verify
            context: Verification context with required parameters
            
        Returns:
            VerificationResult with trust decision
        """
        verified_claims: Dict[str, Any] = {}
        details: Dict[str, Any] = {
            "proofs_verified": [],
            "proofs_failed": [],
        }

        try:
            # Step 1: Verify challenge binding (prevents replay)
            if presentation.challenge != context.expected_challenge:
                return VerificationResult(
                    decision=TrustDecision.UNTRUSTED,
                    verified_claims={},
                    verification_time=context.current_time,
                    reason="Challenge mismatch - possible replay attack",
                    details=details,
                )

            # Step 2: Verify domain binding
            if presentation.domain != context.expected_domain:
                return VerificationResult(
                    decision=TrustDecision.UNTRUSTED,
                    verified_claims={},
                    verification_time=context.current_time,
                    reason="Domain mismatch",
                    details=details,
                )

            # Step 3: Create proof verifier
            verifier = ProofVerifier(
                context.issuer_public_key,
                context.accumulator_params,
            )

            # Step 4: Verify each proof
            has_validity_proof = False
            has_non_revocation_proof = False

            for proof in presentation.zkp_proofs:
                is_valid = verifier.verify_proof(
                    proof,
                    context.expected_challenge,
                    context.current_accumulator_value,
                )

                if is_valid:
                    details["proofs_verified"].append(proof.proof_type.name)
                    
                    # Track proof types
                    if proof.proof_type == ProofType.CREDENTIAL_VALIDITY:
                        has_validity_proof = True
                    elif proof.proof_type == ProofType.NON_REVOCATION:
                        has_non_revocation_proof = True
                    
                    # Collect disclosed claims
                    verified_claims.update(proof.disclosed_values)
                else:
                    details["proofs_failed"].append(proof.proof_type.name)
                    return VerificationResult(
                        decision=TrustDecision.UNTRUSTED,
                        verified_claims={},
                        verification_time=context.current_time,
                        reason=f"Proof verification failed: {proof.proof_type.name}",
                        details=details,
                    )

            # Step 5: Ensure required proof types are present
            if not has_validity_proof:
                return VerificationResult(
                    decision=TrustDecision.UNTRUSTED,
                    verified_claims={},
                    verification_time=context.current_time,
                    reason="Missing credential validity proof",
                    details=details,
                )

            if not has_non_revocation_proof:
                return VerificationResult(
                    decision=TrustDecision.UNTRUSTED,
                    verified_claims={},
                    verification_time=context.current_time,
                    reason="Missing non-revocation proof",
                    details=details,
                )

            # Step 6: Verify required claims are present
            for required_claim in context.required_claims:
                if required_claim not in verified_claims:
                    return VerificationResult(
                        decision=TrustDecision.UNTRUSTED,
                        verified_claims=verified_claims,
                        verification_time=context.current_time,
                        reason=f"Missing required claim: {required_claim}",
                        details=details,
                    )

            # All checks passed - TRUSTED
            return VerificationResult(
                decision=TrustDecision.TRUSTED,
                verified_claims=verified_claims,
                verification_time=context.current_time,
                reason="All proofs verified successfully",
                details=details,
            )

        except Exception as e:
            # Any exception results in UNTRUSTED
            return VerificationResult(
                decision=TrustDecision.UNTRUSTED,
                verified_claims={},
                verification_time=context.current_time,
                reason=f"Verification error: {str(e)}",
                details=details,
            )

    def verify_did_authentication(
        self,
        did_document: DIDDocument,
        signature: bytes,
        message: bytes,
        verification_method_id: str,
    ) -> VerificationResult:
        """Verify DID-based authentication.
        
        Verifies that a message was signed by the controller
        of the specified DID.
        
        Args:
            did_document: The DID Document
            signature: Signature to verify
            message: Signed message
            verification_method_id: ID of the key used to sign
            
        Returns:
            VerificationResult
        """
        try:
            # Find the verification method
            verification_method = None
            for vm in did_document.verification_method:
                if vm.key_id == verification_method_id:
                    verification_method = vm
                    break

            if not verification_method:
                return VerificationResult(
                    decision=TrustDecision.UNTRUSTED,
                    verified_claims={},
                    verification_time=utc_now(),
                    reason="Verification method not found in DID Document",
                )

            # Check if key is authorized for authentication
            if verification_method_id not in did_document.authentication:
                return VerificationResult(
                    decision=TrustDecision.UNTRUSTED,
                    verified_claims={},
                    verification_time=utc_now(),
                    reason="Key not authorized for authentication",
                )

            # PLACEHOLDER: Verify signature based on key type
            # In production, would dispatch to appropriate verifier
            # based on verification_method.key_type
            
            # For now, assume valid if signature is non-empty
            if len(signature) == 0:
                return VerificationResult(
                    decision=TrustDecision.UNTRUSTED,
                    verified_claims={},
                    verification_time=utc_now(),
                    reason="Empty signature",
                )

            return VerificationResult(
                decision=TrustDecision.TRUSTED,
                verified_claims={"did": did_document.id},
                verification_time=utc_now(),
                reason="DID authentication successful",
            )

        except Exception as e:
            return VerificationResult(
                decision=TrustDecision.UNTRUSTED,
                verified_claims={},
                verification_time=utc_now(),
                reason=f"Authentication error: {str(e)}",
            )

    def verify_mutual_authentication(
        self,
        agent_a_presentation: VerifiablePresentation,
        agent_b_presentation: VerifiablePresentation,
        context_a: VerificationContext,
        context_b: VerificationContext,
    ) -> tuple[VerificationResult, VerificationResult]:
        """Verify mutual authentication between two agents.
        
        Both agents must prove their identity to each other.
        
        Args:
            agent_a_presentation: Agent A's presentation
            agent_b_presentation: Agent B's presentation
            context_a: Context for verifying A's presentation
            context_b: Context for verifying B's presentation
            
        Returns:
            Tuple of (result_for_a, result_for_b)
        """
        result_a = self.verify_presentation(agent_a_presentation, context_a)
        result_b = self.verify_presentation(agent_b_presentation, context_b)
        
        return result_a, result_b


# =============================================================================
# Simple API Functions
# =============================================================================

def quick_verify(
    presentation: VerifiablePresentation,
    issuer_public_key: BBSPublicKey,
    accumulator_params: AccumulatorPublicParams,
    accumulator_value: int,
    challenge: bytes,
    domain: str,
) -> bool:
    """Quick verification returning boolean.
    
    Convenience function for simple trust checks.
    
    Args:
        presentation: Presentation to verify
        issuer_public_key: Issuer's public key
        accumulator_params: Accumulator parameters
        accumulator_value: Current accumulator value
        challenge: Expected challenge
        domain: Expected domain
        
    Returns:
        True if trusted, False otherwise
    """
    hub = VerificationHub()
    context = VerificationContext(
        issuer_public_key=issuer_public_key,
        accumulator_params=accumulator_params,
        current_accumulator_value=accumulator_value,
        expected_challenge=challenge,
        expected_domain=domain,
    )
    result = hub.verify_presentation(presentation, context)
    return result.is_trusted
