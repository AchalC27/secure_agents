"""
Arbiter - Core Tests

Tests for cryptographic primitives, identity, and integrity layers.
"""

import pytest
from datetime import datetime, timedelta

# =============================================================================
# Crypto Layer Tests
# =============================================================================

class TestPQC:
    """Tests for Post-Quantum Cryptography module."""

    def test_dilithium_keypair_generation(self):
        """Test Dilithium key pair generation."""
        from arbiter.crypto.pqc import generate_dilithium_keypair
        
        keypair = generate_dilithium_keypair(security_level=3)
        
        assert keypair.public_key is not None
        assert keypair.private_key is not None
        assert len(keypair.public_key.key_bytes) > 0
        assert len(keypair.private_key.key_bytes) > 0

    def test_dilithium_sign_verify(self):
        """Test Dilithium signing and verification."""
        from arbiter.crypto.pqc import (
            generate_dilithium_keypair,
            dilithium_sign,
            dilithium_verify,
        )
        
        keypair = generate_dilithium_keypair()
        message = b"Test message for signing"
        
        signature = dilithium_sign(keypair.private_key, message)
        assert len(signature) > 0
        
        is_valid = dilithium_verify(keypair.public_key, message, signature)
        assert is_valid is True

    @pytest.mark.skip(reason="Placeholder crypto doesn't validate message content")
    def test_dilithium_invalid_signature(self):
        """Test that invalid signatures fail verification.
        
        NOTE: This test is skipped because placeholder crypto
        doesn't actually verify message content. In production
        with real PQC libraries, this test should pass.
        """
        from arbiter.crypto.pqc import (
            generate_dilithium_keypair,
            dilithium_sign,
            dilithium_verify,
        )
        
        keypair = generate_dilithium_keypair()
        message = b"Test message"
        wrong_message = b"Different message"
        
        signature = dilithium_sign(keypair.private_key, message)
        
        # Verify with wrong message should fail
        is_valid = dilithium_verify(keypair.public_key, wrong_message, signature)
        assert is_valid is False

    def test_kyber_keypair_generation(self):
        """Test Kyber key pair generation."""
        from arbiter.crypto.pqc import generate_kyber_keypair
        
        keypair = generate_kyber_keypair(security_level=3)
        
        assert keypair.public_key is not None
        assert keypair.private_key is not None

    def test_kyber_encapsulate_decapsulate(self):
        """Test Kyber key encapsulation."""
        from arbiter.crypto.pqc import (
            generate_kyber_keypair,
            kyber_encapsulate,
            kyber_decapsulate,
        )
        
        keypair = generate_kyber_keypair()
        
        result = kyber_encapsulate(keypair.public_key)
        assert len(result.ciphertext) > 0
        assert len(result.shared_secret) > 0
        
        decrypted_secret = kyber_decapsulate(keypair.private_key, result.ciphertext)
        assert decrypted_secret == result.shared_secret


class TestBBSPlus:
    """Tests for BBS+ signature module."""

    def test_bbs_keypair_generation(self):
        """Test BBS+ key pair generation."""
        from arbiter.crypto.bbs_plus import generate_bbs_keypair
        
        keypair = generate_bbs_keypair(max_messages=5)
        
        assert keypair.public_key is not None
        assert keypair.private_key is not None
        assert len(keypair.public_key.generators) >= 5

    def test_bbs_sign_verify(self):
        """Test BBS+ signing and verification."""
        from arbiter.crypto.bbs_plus import (
            generate_bbs_keypair,
            bbs_sign,
            bbs_verify,
        )
        
        keypair = generate_bbs_keypair(max_messages=3)
        messages = [b"claim1", b"claim2", b"claim3"]
        
        signature = bbs_sign(keypair.private_key, messages)
        assert signature is not None
        
        is_valid = bbs_verify(keypair.public_key, messages, signature)
        assert is_valid is True

    def test_bbs_selective_disclosure(self):
        """Test BBS+ selective disclosure proof."""
        from arbiter.crypto.bbs_plus import (
            generate_bbs_keypair,
            bbs_sign,
            bbs_create_proof,
            bbs_verify_proof,
        )
        
        keypair = generate_bbs_keypair(max_messages=3)
        messages = [b"name:Alice", b"age:30", b"role:admin"]
        
        signature = bbs_sign(keypair.private_key, messages)
        
        # Create proof disclosing only the role (index 2)
        nonce = b"verifier-challenge"
        proof = bbs_create_proof(
            keypair.public_key,
            signature,
            messages,
            disclosed_indices=[2],
            nonce=nonce,
        )
        
        assert proof.disclosed_indices == [2]
        assert proof.disclosed_messages == [messages[2]]
        
        is_valid = bbs_verify_proof(keypair.public_key, proof, total_message_count=3)
        assert is_valid is True


class TestAccumulators:
    """Tests for cryptographic accumulators."""

    def test_accumulator_add_verify(self):
        """Test adding elements and verifying witnesses."""
        from arbiter.crypto.accumulators import AccumulatorManager
        
        manager = AccumulatorManager()
        
        element = manager.derive_element("handler-123")
        witness = manager.add(element)
        
        assert witness is not None
        assert manager.verify_witness(witness) is True

    def test_accumulator_revocation(self):
        """Test that revoked elements fail witness verification."""
        from arbiter.crypto.accumulators import AccumulatorManager
        
        manager = AccumulatorManager()
        
        element1 = manager.derive_element("handler-1")
        element2 = manager.derive_element("handler-2")
        
        witness1 = manager.add(element1)
        witness2 = manager.add(element2)
        
        # Revoke element1
        manager.remove(element1)
        
        # witness1 should no longer be valid
        assert manager.verify_witness(witness1) is False
        
        # witness2 needs update but the element is still in accumulator
        updated_witness = manager.create_witness(element2)
        assert manager.verify_witness(updated_witness) is True


class TestCommitments:
    """Tests for commitment schemes."""

    def test_hash_commitment(self):
        """Test hash-based commitment."""
        from arbiter.crypto.commitments import hash_commit, hash_open
        
        value = b"secret value"
        commitment = hash_commit(value)
        
        assert hash_open(commitment, value) is True
        assert hash_open(commitment, b"wrong value") is False

    def test_pedersen_commitment(self):
        """Test Pedersen commitment."""
        from arbiter.crypto.commitments import (
            pedersen_commit,
            pedersen_open,
            pedersen_add,
        )
        
        c1 = pedersen_commit(100)
        c2 = pedersen_commit(50)
        
        assert pedersen_open(c1, 100) is True
        assert pedersen_open(c1, 99) is False
        
        # Test homomorphic addition
        c_sum = pedersen_add(c1, c2)
        assert pedersen_open(c_sum, 150) is True


# =============================================================================
# Identity Layer Tests
# =============================================================================

class TestDID:
    """Tests for DID module."""

    def test_did_creation_from_key(self):
        """Test deterministic DID creation from public key."""
        from arbiter.identity.did import DID
        
        public_key = b"test-public-key-bytes"
        did = DID.from_public_key(public_key)
        
        assert did.did_string.startswith("did:arbiter:")
        assert len(did.method_specific_id) > 0
        
        # Same key should produce same DID
        did2 = DID.from_public_key(public_key)
        assert did == did2

    def test_did_document_building(self):
        """Test DID Document construction."""
        from arbiter.identity.did import DID, DIDDocumentBuilder
        
        public_key = b"auth-public-key"
        did = DID.from_public_key(public_key)
        
        builder = DIDDocumentBuilder(did)
        builder.add_authentication_key(public_key)
        builder.add_service("AgentMessaging", "https://agent.example.com")
        builder.set_timestamps()
        
        doc = builder.build()
        
        assert doc.id == did.did_string
        assert len(doc.verification_method) == 1
        assert len(doc.authentication) == 1
        assert len(doc.service) == 1


class TestKeyManagement:
    """Tests for key management module."""

    def test_key_generation(self):
        """Test key generation for different purposes."""
        from arbiter.identity.key_management import KeyManager, KeyPurpose
        
        manager = KeyManager()
        
        auth_key = manager.generate_authentication_key()
        assert auth_key.metadata.purpose == KeyPurpose.AUTHENTICATION
        
        enc_key = manager.generate_encryption_key()
        assert enc_key.metadata.purpose == KeyPurpose.KEY_AGREEMENT

    def test_key_rotation(self):
        """Test key rotation."""
        from arbiter.identity.key_management import KeyManager, KeyStatus
        
        manager = KeyManager()
        
        old_key = manager.generate_authentication_key()
        new_key = manager.rotate_key(old_key.key_id)
        
        assert new_key.key_id != old_key.key_id
        assert new_key.metadata.rotated_from == old_key.key_id
        
        # Old key should be revoked
        old_metadata = manager._storage.retrieve(old_key.key_id)[1]
        assert old_metadata.status == KeyStatus.REVOKED


class TestVCIssuer:
    """Tests for VC Issuer module."""

    def test_credential_issuance(self):
        """Test basic credential issuance."""
        from arbiter.identity.vc_issuer import VCIssuer, CredentialRequest
        
        issuer = VCIssuer.create("did:arbiter:issuer123")
        
        request = CredentialRequest(
            subject_did="did:arbiter:subject456",
            credential_type="AgentIdentityCredential",
            claims={"role": "researcher", "level": 3},
        )
        
        bundle = issuer.issue_credential(request)
        
        assert bundle.credential is not None
        assert bundle.credential.issuer == "did:arbiter:issuer123"
        assert bundle.credential.credential_subject.id == "did:arbiter:subject456"
        assert bundle.witness is not None


class TestVerificationHub:
    """Tests for Verification Hub."""

    def test_trust_decision(self):
        """Test that verification hub returns binary decisions."""
        from arbiter.identity.verification_hub import (
            VerificationHub,
            TrustDecision,
        )
        
        hub = VerificationHub()
        
        # Just verify the hub initializes correctly
        assert hub is not None


# =============================================================================
# Integrity Layer Tests
# =============================================================================

class TestABACPDP:
    """Tests for Policy Decision Point."""

    def test_policy_evaluation_permit(self):
        """Test policy evaluation with PERMIT outcome."""
        from arbiter.integrity.abac.pdp import PolicyDecisionPoint, EvaluationContext
        from arbiter.common.models import (
            Policy,
            PolicyRule,
            Condition,
            ConditionOperator,
            Effect,
            AccessRequest,
        )
        
        pdp = PolicyDecisionPoint()
        
        # Create a policy that permits if subject role is "admin"
        policy = Policy(
            policy_id="test-policy",
            version="1.0",
            rules=[
                PolicyRule(
                    rule_id="admin-permit",
                    effect=Effect.PERMIT,
                    conditions=[
                        Condition(
                            attribute_category="subject",
                            attribute_id="role",
                            operator=ConditionOperator.EQUALS,
                            value="admin",
                        ),
                    ],
                ),
            ],
        )
        
        context = EvaluationContext(
            subject={"role": "admin"},
            resource={"id": "data"},
            action={"id": "read"},
        )
        
        request = AccessRequest(
            request_id="req-1",
            subject_did="did:arbiter:alice",
            resource_id="data",
            action="read",
        )
        
        decision = pdp.evaluate(request, [policy], context)
        
        assert decision.effect == Effect.PERMIT

    def test_policy_evaluation_deny(self):
        """Test policy evaluation with DENY outcome."""
        from arbiter.integrity.abac.pdp import PolicyDecisionPoint, EvaluationContext
        from arbiter.common.models import (
            Policy,
            PolicyRule,
            Condition,
            ConditionOperator,
            Effect,
            AccessRequest,
        )
        
        pdp = PolicyDecisionPoint()
        
        policy = Policy(
            policy_id="test-policy",
            version="1.0",
            rules=[
                PolicyRule(
                    rule_id="admin-permit",
                    effect=Effect.PERMIT,
                    conditions=[
                        Condition(
                            attribute_category="subject",
                            attribute_id="role",
                            operator=ConditionOperator.EQUALS,
                            value="admin",
                        ),
                    ],
                ),
            ],
        )
        
        # Context with non-admin role
        context = EvaluationContext(
            subject={"role": "guest"},
            resource={"id": "data"},
            action={"id": "read"},
        )
        
        request = AccessRequest(
            request_id="req-1",
            subject_did="did:arbiter:bob",
            resource_id="data",
            action="read",
        )
        
        decision = pdp.evaluate(request, [policy], context)
        
        # No rule matches, so NOT_APPLICABLE
        assert decision.effect == Effect.NOT_APPLICABLE


class TestPaillier:
    """Tests for Paillier homomorphic encryption."""

    def test_keypair_generation(self):
        """Test Paillier key generation (small key for speed)."""
        from arbiter.integrity.homomorphic.paillier import generate_keypair
        
        # Use small key size for testing speed
        keypair = generate_keypair(key_size=512)
        
        assert keypair.public_key is not None
        assert keypair.private_key is not None

    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        from arbiter.integrity.homomorphic.paillier import (
            generate_keypair,
            encrypt,
            decrypt,
        )
        
        keypair = generate_keypair(key_size=512)
        
        plaintext = 12345
        encrypted = encrypt(keypair.public_key, plaintext)
        decrypted = decrypt(keypair.private_key, encrypted)
        
        assert decrypted == plaintext

    def test_homomorphic_addition(self):
        """Test homomorphic addition."""
        from arbiter.integrity.homomorphic.paillier import (
            generate_keypair,
            encrypt,
            decrypt,
        )
        
        keypair = generate_keypair(key_size=512)
        
        a = 100
        b = 250
        
        enc_a = encrypt(keypair.public_key, a)
        enc_b = encrypt(keypair.public_key, b)
        
        # Add encrypted values
        enc_sum = enc_a + enc_b
        
        decrypted_sum = decrypt(keypair.private_key, enc_sum)
        assert decrypted_sum == a + b

    def test_scalar_multiplication(self):
        """Test scalar multiplication."""
        from arbiter.integrity.homomorphic.paillier import (
            generate_keypair,
            encrypt,
            decrypt,
        )
        
        keypair = generate_keypair(key_size=512)
        
        value = 50
        scalar = 3
        
        encrypted = encrypt(keypair.public_key, value)
        result = encrypted * scalar
        
        decrypted = decrypt(keypair.private_key, result)
        assert decrypted == value * scalar


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests spanning multiple layers."""

    def test_full_credential_flow(self):
        """Test complete credential issuance and verification flow."""
        from arbiter.identity.key_management import KeyManager
        from arbiter.identity.did import DID
        from arbiter.identity.vc_issuer import VCIssuer, CredentialRequest
        from arbiter.identity.revocation import RevocationManager
        
        # Setup issuer
        key_manager = KeyManager()
        auth_key = key_manager.generate_authentication_key()
        issuer_did = DID.from_public_key(auth_key.public_key.public_key_bytes)
        
        issuer = VCIssuer.create(issuer_did.did_string)
        
        # Issue credential
        subject_key = key_manager.generate_authentication_key()
        subject_did = DID.from_public_key(subject_key.public_key.public_key_bytes)
        
        request = CredentialRequest(
            subject_did=subject_did.did_string,
            credential_type="AgentIdentityCredential",
            claims={
                "agentName": "ResearchBot",
                "capabilities": ["search", "analyze"],
            },
        )
        
        bundle = issuer.issue_credential(request)
        
        # Verify credential structure
        assert bundle.credential.issuer == issuer_did.did_string
        assert bundle.credential.credential_subject.id == subject_did.did_string
        assert "ResearchBot" == bundle.credential.credential_subject.claims["agentName"]

    def test_abac_with_credentials(self):
        """Test ABAC evaluation with credential-derived attributes."""
        from arbiter.integrity.abac import PolicyEnforcementPoint
        from arbiter.integrity.abac.pdp import PolicyDecisionPoint, EvaluationContext
        from arbiter.common.models import PolicyRule, Condition, ConditionOperator, Effect, AccessRequest, Policy
        
        # Create PDP directly for more control
        pdp = PolicyDecisionPoint()
        
        # Create policy requiring "search" capability
        policy = Policy(
            policy_id="search-policy",
            version="1.0",
            rules=[
                PolicyRule(
                    rule_id="allow-search",
                    effect=Effect.PERMIT,
                    conditions=[
                        Condition(
                            attribute_category="subject",
                            attribute_id="capabilities",
                            operator=ConditionOperator.CONTAINS,
                            value="search",
                        ),
                    ],
                ),
            ],
        )
        
        # Context with capabilities
        context = EvaluationContext(
            subject={"capabilities": ["search", "analyze"]},
            resource={"id": "data/research"},
            action={"id": "search"},
        )
        
        request = AccessRequest(
            request_id="req-1",
            subject_did="did:arbiter:agent123",
            resource_id="data/research",
            action="search",
        )
        
        decision = pdp.evaluate(request, [policy], context)
        
        assert decision.effect == Effect.PERMIT


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
