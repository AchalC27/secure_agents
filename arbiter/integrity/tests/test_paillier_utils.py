import pytest

from arbiter.integrity.homomorphic.paillier import (
    generate_keypair,
    encrypt,
    decrypt,
    EncryptedNumber,
    encrypted_sum,
    encrypted_weighted_sum,
    encrypt_list,
    decrypt_list,
)
from arbiter.common.errors import EncryptionError, DecryptionError


@pytest.fixture(scope="module")
def small_keypair():
    # Use small key for test speed
    return generate_keypair(key_size=512)


# encrypt() correctly encodes plaintext
# decrypt() correctly decodes ciphertext
def test_encrypt_decrypt_roundtrip(small_keypair):
    pk = small_keypair.public_key
    sk = small_keypair.private_key
    plaintext = 42
    enc = encrypt(pk, plaintext)
    dec = decrypt(sk, enc)
    assert dec == plaintext


# Paillier works in modulo n arithmetic, so:
# Negative values must be wrapped into the valid modulus range
# -1 becomes n - 1
# Your implementation correctly applies modular normalization
def test_encrypt_negative_mod_wrap(small_keypair):
    pk = small_keypair.public_key
    sk = small_keypair.private_key
    enc = encrypt(pk, -1)
    dec = decrypt(sk, enc)
    assert isinstance(dec, int)
    assert dec == (-1) % pk.n


# Trying to encrypt a value outside the valid plaintext space.
# Input validation inside encrypt()
# Proper error signaling instead of silent failure
def test_encrypt_plaintext_too_large_raises(small_keypair):
    pk = small_keypair.public_key
    with pytest.raises(EncryptionError):
        encrypt(pk, pk.n)


# Decrypting ciphertext using the wrong private key.
# Ciphertexts are key-bound
# Decryption does not “accidentally succeed
def test_decrypt_wrong_key_raises(small_keypair):
    pk = small_keypair.public_key
    sk = small_keypair.private_key
    enc = encrypt(pk, 5)
    other = generate_keypair(key_size=512)
    with pytest.raises(DecryptionError):
        decrypt(other.private_key, enc)


# encrypted_sum() combines ciphertexts correctly
# No decryption required during aggregation
# Ciphertext exponentiation works as scalar multiplication
# Order and pairing of values and weights is preserved
def test_encrypted_sum_and_weighted_sum(small_keypair):
    pk = small_keypair.public_key
    sk = small_keypair.private_key
    values = [10, 20, 30]
    encs = [encrypt(pk, v) for v in values]
    total_enc = encrypted_sum(encs)
    assert decrypt(sk, total_enc) == sum(values)
    weighted = encrypted_weighted_sum(encs, [1, 2, 3])
    assert decrypt(sk, weighted) == sum(v * w for v, w in zip(values, [1, 2, 3]))


# Attempting to sum no ciphertexts
def test_encrypted_sum_empty_raises():
    with pytest.raises(EncryptionError):
        encrypted_sum([])


# Ciphertexts and weights lists have different lengths.
# Structural validation of inputs
# One-to-one mapping enforcement
def test_weighted_sum_mismatch_length_raises(small_keypair):
    pk = small_keypair.public_key
    encs = [encrypt(pk, 1), encrypt(pk, 2)]
    with pytest.raises(EncryptionError):
        encrypted_weighted_sum(encs, [1])

# Batch encryption and decryption.
def test_encrypt_list_and_decrypt_list_roundtrip(small_keypair):
    pk = small_keypair.public_key
    sk = small_keypair.private_key
    vals = [2, 3, 5]
    encs = encrypt_list(pk, vals)
    outs = decrypt_list(sk, encs)
    assert outs == vals
