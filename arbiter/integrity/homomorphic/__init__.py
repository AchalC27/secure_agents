"""
Arbiter - Homomorphic Encryption Package

Privacy-preserving computation using homomorphic encryption.

Currently implements:
- Paillier cryptosystem (additive homomorphism)

Future additions:
- Threshold Paillier (distributed decryption)
- BFV/CKKS (for more complex computations)
"""

from arbiter.integrity.homomorphic.paillier import (
    PaillierPublicKey,
    PaillierPrivateKey,
    PaillierKeyPair,
    EncryptedNumber,
    generate_keypair,
    encrypt,
    decrypt,
    encrypt_list,
    decrypt_list,
    encrypted_sum,
    encrypted_mean,
    encrypted_weighted_sum,
)

__all__ = [
    "PaillierPublicKey",
    "PaillierPrivateKey",
    "PaillierKeyPair",
    "EncryptedNumber",
    "generate_keypair",
    "encrypt",
    "decrypt",
    "encrypt_list",
    "decrypt_list",
    "encrypted_sum",
    "encrypted_mean",
    "encrypted_weighted_sum",
]
