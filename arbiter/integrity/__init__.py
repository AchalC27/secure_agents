"""
Arbiter - Integrity Layer Package

Provides integrity guarantees through:
- ABAC: Fine-grained access control
- Homomorphic Encryption: Privacy-preserving computation

The Integrity Layer enforces:
- Authorization policies based on verified credentials
- Privacy-preserving data aggregation
- Secure computation on encrypted data
"""

from arbiter.integrity.policy_models import (
    AttributeCategory,
    AttributeDefinition,
    PolicySet,
    CombiningAlgorithm,
    PolicyTemplate,
    validate_policy,
    validate_policy_strict,
)

# Re-export ABAC components
from arbiter.integrity.abac import (
    PolicyAdministrationPoint,
    PolicyInformationPoint,
    PolicyDecisionPoint,
    PolicyEnforcementPoint,
    EvaluationContext,
    AttributeContext,
    EnforcementResult,
    create_pep_with_identity_integration,
)

# Re-export homomorphic components
from arbiter.integrity.homomorphic import (
    PaillierPublicKey,
    PaillierPrivateKey,
    PaillierKeyPair,
    EncryptedNumber,
    generate_keypair as generate_paillier_keypair,
    encrypt as paillier_encrypt,
    decrypt as paillier_decrypt,
    encrypted_sum,
)

__all__ = [
    # Policy Models
    "AttributeCategory",
    "AttributeDefinition",
    "PolicySet",
    "CombiningAlgorithm",
    "PolicyTemplate",
    "validate_policy",
    "validate_policy_strict",
    # ABAC
    "PolicyAdministrationPoint",
    "PolicyInformationPoint",
    "PolicyDecisionPoint",
    "PolicyEnforcementPoint",
    "EvaluationContext",
    "AttributeContext",
    "EnforcementResult",
    "create_pep_with_identity_integration",
    # Homomorphic
    "PaillierPublicKey",
    "PaillierPrivateKey",
    "PaillierKeyPair",
    "EncryptedNumber",
    "generate_paillier_keypair",
    "paillier_encrypt",
    "paillier_decrypt",
    "encrypted_sum",
]
