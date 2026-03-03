"""
Arbiter - Cryptographic Primitives Package

Provides cryptographic building blocks:
- PQC: Post-quantum cryptography (Dilithium, Kyber)
- BBS+: Signatures with selective disclosure
- Accumulators: Cryptographic accumulators for revocation
- Commitments: Pedersen and hash commitments
"""

from arbiter.crypto.pqc import (
    DilithiumPublicKey,
    DilithiumPrivateKey,
    DilithiumKeyPair,
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
    KyberPublicKey,
    KyberPrivateKey,
    KyberKeyPair,
    EncapsulationResult,
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    HybridKeyPair,
    generate_hybrid_keypair,
    DEFAULT_SECURITY_LEVEL,
)

from arbiter.crypto.bbs_plus import (
    BBSPublicKey,
    BBSPrivateKey,
    BBSKeyPair,
    BBSSignature,
    BBSProof,
    generate_bbs_keypair,
    bbs_sign,
    bbs_verify,
    bbs_create_proof,
    bbs_verify_proof,
)

from arbiter.crypto.accumulators import (
    AccumulatorPublicParams,
    AccumulatorState,
    Witness,
    NonMembershipWitness,
    AccumulatorManager,
    update_witness,
    create_non_membership_proof,
)

from arbiter.crypto.commitments import (
    HashCommitment,
    hash_commit,
    hash_open,
    PedersenParams,
    PedersenCommitment,
    pedersen_commit,
    pedersen_open,
    pedersen_add,
    pedersen_scalar_multiply,
    VectorCommitment,
    VectorOpening,
    VectorCommitter,
    generate_pedersen_params,
)

__all__ = [
    # PQC - Dilithium
    "DilithiumPublicKey",
    "DilithiumPrivateKey",
    "DilithiumKeyPair",
    "generate_dilithium_keypair",
    "dilithium_sign",
    "dilithium_verify",
    # PQC - Kyber
    "KyberPublicKey",
    "KyberPrivateKey",
    "KyberKeyPair",
    "EncapsulationResult",
    "generate_kyber_keypair",
    "kyber_encapsulate",
    "kyber_decapsulate",
    # PQC - Hybrid
    "HybridKeyPair",
    "generate_hybrid_keypair",
    "DEFAULT_SECURITY_LEVEL",
    # BBS+
    "BBSPublicKey",
    "BBSPrivateKey",
    "BBSKeyPair",
    "BBSSignature",
    "BBSProof",
    "generate_bbs_keypair",
    "bbs_sign",
    "bbs_verify",
    "bbs_create_proof",
    "bbs_verify_proof",
    # Accumulators
    "AccumulatorPublicParams",
    "AccumulatorState",
    "Witness",
    "NonMembershipWitness",
    "AccumulatorManager",
    "update_witness",
    "create_non_membership_proof",
    # Commitments
    "HashCommitment",
    "hash_commit",
    "hash_open",
    "PedersenParams",
    "PedersenCommitment",
    "pedersen_commit",
    "pedersen_open",
    "pedersen_add",
    "pedersen_scalar_multiply",
    "VectorCommitment",
    "VectorOpening",
    "VectorCommitter",
    "generate_pedersen_params",
]
