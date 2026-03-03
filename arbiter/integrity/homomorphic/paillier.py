"""
Arbiter - Paillier Homomorphic Encryption Module

Implements Paillier cryptosystem for privacy-preserving computation.

Paillier enables:
- Encrypted addition: E(a) * E(b) = E(a + b)
- Scalar multiplication: E(a)^k = E(k * a)
- Secure aggregation without revealing individual values

Reference: Pascal Paillier (1999) - Public-Key Cryptosystems Based on
Composite Degree Residuosity Classes

Use Cases in Arbiter:
- Aggregate trust scores without revealing individual scores
- Compute statistics on encrypted capability data
- Privacy-preserving voting and consensus

Security: Semantic security under the Decisional Composite Residuosity
Assumption (DCRA).
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

from arbiter.common.errors import EncryptionError, DecryptionError
from arbiter.common.utils import sha256_hash, bytes_to_base58


# =============================================================================
# Key Structures
# =============================================================================

@dataclass
class PaillierPublicKey:
    """Paillier public key.
    
    The public key is (n, g) where:
    - n = p * q (product of two large primes)
    - g = n + 1 (simplified generator)
    
    Attributes:
        n: RSA modulus n = p * q
        g: Generator (typically n + 1)
        n_squared: Precomputed n^2 for efficiency
        key_id: Optional key identifier
    """
    n: int
    g: int
    n_squared: int = 0
    key_id: str = ""

    def __post_init__(self) -> None:
        if self.n_squared == 0:
            object.__setattr__(self, "n_squared", self.n * self.n)
        if not self.key_id:
            key_hash = sha256_hash(self.n.to_bytes(256, "big"))
            object.__setattr__(self, "key_id", f"paillier-{bytes_to_base58(key_hash[:8])}")


@dataclass
class PaillierPrivateKey:
    """Paillier private key.
    
    The private key contains lambda and mu where:
    - lambda = lcm(p-1, q-1)
    - mu = (L(g^lambda mod n^2))^-1 mod n
    - L(x) = (x - 1) / n
    
    Attributes:
        lambda_val: Lambda value from key generation
        mu: Mu value for decryption
        public_key: Corresponding public key
    """
    lambda_val: int
    mu: int
    public_key: PaillierPublicKey


@dataclass
class PaillierKeyPair:
    """Complete Paillier key pair."""
    public_key: PaillierPublicKey
    private_key: PaillierPrivateKey


# =============================================================================
# Encrypted Value
# =============================================================================

@dataclass
class EncryptedNumber:
    """An encrypted number under Paillier.
    
    Supports homomorphic operations:
    - __add__: Encrypted addition
    - __mul__: Scalar multiplication
    
    Attributes:
        ciphertext: The encrypted value (mod n^2)
        public_key: Public key used for encryption
        _is_obfuscated: Whether randomness has been applied
    """
    ciphertext: int
    public_key: PaillierPublicKey
    _is_obfuscated: bool = True

    def __add__(
        self,
        other: Union["EncryptedNumber", int],
    ) -> "EncryptedNumber":
        """Add encrypted numbers or add plaintext to encrypted.
        
        E(a) + E(b) = E(a + b)
        E(a) + b = E(a + b)
        """
        if isinstance(other, EncryptedNumber):
            if other.public_key.n != self.public_key.n:
                raise EncryptionError("Cannot add values encrypted with different keys")
            # E(a) * E(b) mod n^2 = E(a + b)
            result = (self.ciphertext * other.ciphertext) % self.public_key.n_squared
        else:
            # Add plaintext: E(a) * g^b mod n^2 = E(a + b)
            plaintext_encoded = pow(self.public_key.g, other, self.public_key.n_squared)
            result = (self.ciphertext * plaintext_encoded) % self.public_key.n_squared
        
        return EncryptedNumber(result, self.public_key, False)

    def __radd__(self, other: int) -> "EncryptedNumber":
        """Right-side addition."""
        return self.__add__(other)

    def __mul__(self, scalar: int) -> "EncryptedNumber":
        """Multiply by a scalar.
        
        E(a) * k = E(a * k)
        """
        if scalar < 0:
            # Handle negative scalars
            scalar = scalar % self.public_key.n
        
        # E(a)^k mod n^2 = E(a * k)
        result = pow(self.ciphertext, scalar, self.public_key.n_squared)
        return EncryptedNumber(result, self.public_key, False)

    def __rmul__(self, scalar: int) -> "EncryptedNumber":
        """Right-side scalar multiplication."""
        return self.__mul__(scalar)

    def __sub__(
        self,
        other: Union["EncryptedNumber", int],
    ) -> "EncryptedNumber":
        """Subtract encrypted numbers.
        
        E(a) - E(b) = E(a - b)
        """
        if isinstance(other, EncryptedNumber):
            # Subtract by adding the negation
            neg_other = other * (-1)
            return self + neg_other
        else:
            # Subtract plaintext
            return self + (-other)

    def obfuscate(self) -> "EncryptedNumber":
        """Apply fresh randomness.
        
        Returns encrypted value with fresh randomness,
        making it indistinguishable from a fresh encryption.
        """
        if self._is_obfuscated:
            return self
        
        # Multiply by E(0) with fresh randomness
        r = _random_below(self.public_key.n)
        r_n = pow(r, self.public_key.n, self.public_key.n_squared)
        obfuscated = (self.ciphertext * r_n) % self.public_key.n_squared
        
        return EncryptedNumber(obfuscated, self.public_key, True)


# =============================================================================
# Key Generation
# =============================================================================

def _random_below(n: int) -> int:
    """Generate random number in [1, n)."""
    return secrets.randbelow(n - 1) + 1


def _gcd(a: int, b: int) -> int:
    """Compute GCD."""
    while b:
        a, b = b, a % b
    return a


def _lcm(a: int, b: int) -> int:
    """Compute LCM."""
    return (a * b) // _gcd(a, b)


def _mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""
    if _gcd(a, m) != 1:
        raise ValueError("Modular inverse doesn't exist")
    
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1,
            u2 - q * v2,
            u3 - q * v3,
            v1,
            v2,
            v3,
        )
    
    return u1 % m


def _is_prime(n: int, k: int = 25) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random prime of specified bit length."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(candidate):
            return candidate


def generate_keypair(key_size: int = 2048) -> PaillierKeyPair:
    """Generate a Paillier key pair.
    
    Args:
        key_size: Bit length of the modulus n (default 2048)
        
    Returns:
        PaillierKeyPair with public and private keys
    """
    # Generate two primes of half the key size
    prime_bits = key_size // 2
    
    p = _generate_prime(prime_bits)
    q = _generate_prime(prime_bits)
    
    # Ensure p != q
    while p == q:
        q = _generate_prime(prime_bits)
    
    n = p * q
    n_squared = n * n
    
    # g = n + 1 (simplified, always works)
    g = n + 1
    
    # Lambda = lcm(p-1, q-1)
    lambda_val = _lcm(p - 1, q - 1)
    
    # Compute mu = (L(g^lambda mod n^2))^-1 mod n
    # L(x) = (x - 1) / n
    g_lambda = pow(g, lambda_val, n_squared)
    l_value = (g_lambda - 1) // n
    mu = _mod_inverse(l_value, n)
    
    public_key = PaillierPublicKey(n=n, g=g, n_squared=n_squared)
    private_key = PaillierPrivateKey(
        lambda_val=lambda_val,
        mu=mu,
        public_key=public_key,
    )
    
    return PaillierKeyPair(public_key=public_key, private_key=private_key)


# =============================================================================
# Encryption and Decryption
# =============================================================================

def encrypt(
    public_key: PaillierPublicKey,
    plaintext: int,
    randomness: Optional[int] = None,
) -> EncryptedNumber:
    """Encrypt a plaintext value.
    
    E(m, r) = g^m * r^n mod n^2
    
    With g = n + 1:
    E(m, r) = (1 + n*m) * r^n mod n^2
    
    Args:
        public_key: Public key for encryption
        plaintext: Integer to encrypt (must be in [0, n))
        randomness: Optional randomness (generated if not provided)
        
    Returns:
        EncryptedNumber
    """
    n = public_key.n
    n_squared = public_key.n_squared
    
    # Handle negative plaintexts (mod n)
    if plaintext < 0:
        plaintext = plaintext % n
    
    if plaintext >= n:
        raise EncryptionError(f"Plaintext must be less than n ({n})")
    
    # Generate randomness if not provided
    if randomness is None:
        randomness = _random_below(n)
    
    # Ensure randomness is coprime to n
    while _gcd(randomness, n) != 1:
        randomness = _random_below(n)
    
    # Compute ciphertext
    # With g = n + 1: g^m = (1 + n)^m = 1 + n*m mod n^2
    g_m = (1 + n * plaintext) % n_squared
    r_n = pow(randomness, n, n_squared)
    ciphertext = (g_m * r_n) % n_squared
    
    return EncryptedNumber(ciphertext, public_key, True)


def decrypt(
    private_key: PaillierPrivateKey,
    encrypted: EncryptedNumber,
) -> int:
    """Decrypt an encrypted value.
    
    D(c) = L(c^lambda mod n^2) * mu mod n
    
    Args:
        private_key: Private key for decryption
        encrypted: Encrypted value
        
    Returns:
        Decrypted plaintext integer
    """
    if encrypted.public_key.n != private_key.public_key.n:
        raise DecryptionError("Key mismatch: encrypted value uses different key")
    
    n = private_key.public_key.n
    n_squared = private_key.public_key.n_squared
    
    # c^lambda mod n^2
    c_lambda = pow(encrypted.ciphertext, private_key.lambda_val, n_squared)
    
    # L(x) = (x - 1) / n
    l_value = (c_lambda - 1) // n
    
    # m = L(c^lambda) * mu mod n
    plaintext = (l_value * private_key.mu) % n
    
    return plaintext


# =============================================================================
# Utility Functions
# =============================================================================

def encrypt_list(
    public_key: PaillierPublicKey,
    values: List[int],
) -> List[EncryptedNumber]:
    """Encrypt a list of values.
    
    Args:
        public_key: Public key
        values: List of integers to encrypt
        
    Returns:
        List of encrypted values
    """
    return [encrypt(public_key, v) for v in values]


def decrypt_list(
    private_key: PaillierPrivateKey,
    encrypted_values: List[EncryptedNumber],
) -> List[int]:
    """Decrypt a list of encrypted values.
    
    Args:
        private_key: Private key
        encrypted_values: List of encrypted values
        
    Returns:
        List of decrypted integers
    """
    return [decrypt(private_key, e) for e in encrypted_values]


def encrypted_sum(
    encrypted_values: List[EncryptedNumber],
) -> EncryptedNumber:
    """Compute the encrypted sum of encrypted values.
    
    Args:
        encrypted_values: List of encrypted values
        
    Returns:
        Encrypted sum
    """
    if not encrypted_values:
        raise EncryptionError("Cannot sum empty list")
    
    result = encrypted_values[0]
    for ev in encrypted_values[1:]:
        result = result + ev
    
    return result


def encrypted_mean(
    encrypted_values: List[EncryptedNumber],
    count: int,
) -> Tuple[EncryptedNumber, int]:
    """Compute encrypted mean (returns sum and count).
    
    Since division isn't directly supported, returns the
    encrypted sum and count for the caller to divide after decryption.
    
    Args:
        encrypted_values: List of encrypted values
        count: Number of values
        
    Returns:
        Tuple of (encrypted_sum, count)
    """
    enc_sum = encrypted_sum(encrypted_values)
    return enc_sum, count


def encrypted_weighted_sum(
    encrypted_values: List[EncryptedNumber],
    weights: List[int],
) -> EncryptedNumber:
    """Compute encrypted weighted sum.
    
    Args:
        encrypted_values: Encrypted values
        weights: Integer weights
        
    Returns:
        Encrypted weighted sum
    """
    if len(encrypted_values) != len(weights):
        raise EncryptionError("Values and weights must have same length")
    
    if not encrypted_values:
        raise EncryptionError("Cannot compute weighted sum of empty list")
    
    result = encrypted_values[0] * weights[0]
    for ev, w in zip(encrypted_values[1:], weights[1:]):
        result = result + (ev * w)
    
    return result
