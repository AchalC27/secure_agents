"""
Arbiter - Utility Functions

Common utility functions used across all layers.
All functions are designed to be:
- Deterministic (no hidden randomness)
- Side-effect free where possible
- Fully type-hinted
"""

from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Optional
import json


# =============================================================================
# Encoding Utilities
# =============================================================================

# Base58 alphabet (Bitcoin style) - no 0, O, I, l to avoid confusion
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def bytes_to_base58(data: bytes) -> str:
    """Encode bytes to Base58 (Bitcoin style).
    
    Args:
        data: Raw bytes to encode
        
    Returns:
        Base58-encoded string
    """
    if not data:
        return ""
    
    num = int.from_bytes(data, "big")
    if num == 0:
        return BASE58_ALPHABET[0] * len(data)
    
    result = []
    while num:
        num, remainder = divmod(num, 58)
        result.append(BASE58_ALPHABET[remainder])
    
    # Handle leading zeros
    for byte in data:
        if byte == 0:
            result.append(BASE58_ALPHABET[0])
        else:
            break
    
    return "".join(reversed(result))


def base58_to_bytes(encoded: str) -> bytes:
    """Decode Base58 to bytes.
    
    Args:
        encoded: Base58-encoded string
        
    Returns:
        Decoded bytes
        
    Raises:
        ValueError: If string contains invalid Base58 characters
    """
    if not encoded:
        return b""
    
    num = 0
    for char in encoded:
        if char not in BASE58_ALPHABET:
            raise ValueError(f"Invalid Base58 character: {char}")
        num = num * 58 + BASE58_ALPHABET.index(char)
    
    # Count leading zeros (represented as '1' in Base58)
    leading_zeros = 0
    for char in encoded:
        if char == BASE58_ALPHABET[0]:
            leading_zeros += 1
        else:
            break
    
    # Convert to bytes
    if num == 0:
        return b"\x00" * leading_zeros
    
    byte_length = (num.bit_length() + 7) // 8
    result = num.to_bytes(byte_length, "big")
    
    return b"\x00" * leading_zeros + result


def bytes_to_multibase(data: bytes, encoding: str = "base58btc") -> str:
    """Encode bytes to Multibase format.
    
    Reference: https://github.com/multiformats/multibase
    
    Args:
        data: Raw bytes to encode
        encoding: Encoding type (currently only base58btc supported)
        
    Returns:
        Multibase-encoded string with prefix
    """
    if encoding != "base58btc":
        raise ValueError(f"Unsupported encoding: {encoding}")
    
    return "z" + bytes_to_base58(data)


def multibase_to_bytes(encoded: str) -> bytes:
    """Decode Multibase to bytes.
    
    Args:
        encoded: Multibase-encoded string with prefix
        
    Returns:
        Decoded bytes
        
    Raises:
        ValueError: If invalid multibase format or unsupported encoding
    """
    if not encoded:
        return b""
    
    prefix = encoded[0]
    if prefix != "z":
        raise ValueError(f"Unsupported multibase prefix: {prefix} (expected 'z' for base58btc)")
    
    return base58_to_bytes(encoded[1:])


# =============================================================================
# Hashing Utilities
# =============================================================================

def sha256_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash.
    
    Args:
        data: Data to hash
        
    Returns:
        32-byte hash digest
    """
    return hashlib.sha256(data).digest()


def sha256_hash_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string.
    
    Args:
        data: Data to hash
        
    Returns:
        64-character hex string
    """
    return hashlib.sha256(data).hexdigest()


def double_sha256(data: bytes) -> bytes:
    """Compute double SHA-256 hash (common in blockchain).
    
    Args:
        data: Data to hash
        
    Returns:
        32-byte hash digest
    """
    return sha256_hash(sha256_hash(data))


def sha3_256_hash(data: bytes) -> bytes:
    """Compute SHA3-256 hash.
    
    Args:
        data: Data to hash
        
    Returns:
        32-byte hash digest
    """
    return hashlib.sha3_256(data).digest()


def compute_fingerprint(public_key_bytes: bytes) -> str:
    """Compute key fingerprint for identification.
    
    Uses truncated SHA-256 for compact representation.
    
    Args:
        public_key_bytes: Public key material
        
    Returns:
        Base58-encoded fingerprint (first 16 bytes of SHA-256)
    """
    hash_bytes = sha256_hash(public_key_bytes)[:16]
    return bytes_to_base58(hash_bytes)


# =============================================================================
# ID Generation
# =============================================================================

def generate_id(prefix: str = "", length: int = 16) -> str:
    """Generate a cryptographically secure random ID.
    
    Args:
        prefix: Optional prefix for the ID
        length: Number of random bytes (default 16 = 128 bits)
        
    Returns:
        Unique identifier string
    """
    random_bytes = secrets.token_bytes(length)
    encoded = bytes_to_base58(random_bytes)
    return f"{prefix}{encoded}" if prefix else encoded


def generate_deterministic_id(seed_data: bytes, prefix: str = "") -> str:
    """Generate a deterministic ID from seed data.
    
    Same input always produces same output (for reproducibility).
    
    Args:
        seed_data: Data to derive ID from
        prefix: Optional prefix for the ID
        
    Returns:
        Deterministic identifier string
    """
    hash_bytes = sha256_hash(seed_data)[:16]
    encoded = bytes_to_base58(hash_bytes)
    return f"{prefix}{encoded}" if prefix else encoded


def generate_nonce(length: int = 32) -> bytes:
    """Generate a cryptographically secure nonce.
    
    Args:
        length: Number of random bytes
        
    Returns:
        Random nonce bytes
    """
    return secrets.token_bytes(length)


def generate_challenge() -> bytes:
    """Generate a challenge for ZK proofs or authentication.
    
    Includes timestamp component for freshness.
    
    Returns:
        32-byte challenge
    """
    timestamp = int(time.time() * 1000).to_bytes(8, "big")
    random_part = secrets.token_bytes(24)
    return timestamp + random_part


# =============================================================================
# Timestamp Utilities
# =============================================================================

def utc_now() -> datetime:
    """Get current UTC timestamp.
    
    Returns:
        Timezone-aware datetime in UTC
    """
    return datetime.now(timezone.utc)


def timestamp_to_iso(dt: datetime) -> str:
    """Convert datetime to ISO 8601 string.
    
    Args:
        dt: Datetime to convert
        
    Returns:
        ISO 8601 formatted string
    """
    return dt.isoformat()


def iso_to_timestamp(iso_str: str) -> datetime:
    """Parse ISO 8601 string to datetime.
    
    Args:
        iso_str: ISO 8601 formatted string
        
    Returns:
        Parsed datetime (timezone-aware)
    """
    return datetime.fromisoformat(iso_str)


def is_expired(expiration: Optional[datetime], now: Optional[datetime] = None) -> bool:
    """Check if a timestamp has expired.
    
    Args:
        expiration: Expiration timestamp (None means never expires)
        now: Current time (defaults to UTC now)
        
    Returns:
        True if expired, False otherwise
    """
    if expiration is None:
        return False
    
    current = now or utc_now()
    return current > expiration


# =============================================================================
# Canonical JSON Serialization
# =============================================================================

def canonical_json(data: dict[str, Any]) -> str:
    """Serialize dict to canonical JSON for hashing.
    
    Ensures deterministic output:
    - Sorted keys
    - No whitespace
    - Consistent separators
    
    Args:
        data: Dictionary to serialize
        
    Returns:
        Canonical JSON string
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serialize dict to canonical JSON bytes.
    
    Args:
        data: Dictionary to serialize
        
    Returns:
        UTF-8 encoded canonical JSON
    """
    return canonical_json(data).encode("utf-8")


def hash_json(data: dict[str, Any]) -> bytes:
    """Compute SHA-256 hash of canonical JSON.
    
    Args:
        data: Dictionary to hash
        
    Returns:
        32-byte hash digest
    """
    return sha256_hash(canonical_json_bytes(data))


# =============================================================================
# Validation Utilities
# =============================================================================

def validate_did_format(did: str) -> bool:
    """Validate DID format.
    
    Format: did:<method>:<method-specific-id>
    
    Args:
        did: DID string to validate
        
    Returns:
        True if valid format, False otherwise
    """
    if not did or not did.startswith("did:"):
        return False
    
    parts = did.split(":")
    if len(parts) < 3:
        return False
    
    method = parts[1]
    method_specific_id = ":".join(parts[2:])
    
    # Method must be lowercase alphanumeric
    if not method.isalnum() or not method.islower():
        return False
    
    # Method-specific ID must not be empty
    if not method_specific_id:
        return False
    
    return True


def validate_uri(uri: str) -> bool:
    """Basic URI validation.
    
    Args:
        uri: URI string to validate
        
    Returns:
        True if appears to be valid URI, False otherwise
    """
    if not uri:
        return False
    
    # Must have scheme
    if "://" not in uri and not uri.startswith("urn:"):
        return False
    
    return True


# =============================================================================
# Constant-Time Comparison
# =============================================================================

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.
    
    Prevents timing attacks by always comparing all bytes.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


# =============================================================================
# Error Message Sanitization
# =============================================================================

def sanitize_for_logging(value: str, max_length: int = 20) -> str:
    """Truncate sensitive values for safe logging.
    
    Args:
        value: Value to sanitize
        max_length: Maximum length before truncation
        
    Returns:
        Truncated value with ellipsis if needed
    """
    if len(value) <= max_length:
        return value
    return value[:max_length] + "..."


def mask_key_material(key_bytes: bytes) -> str:
    """Mask key material for logging (shows only fingerprint).
    
    Args:
        key_bytes: Key material to mask
        
    Returns:
        Safe string representation
    """
    if not key_bytes:
        return "<empty>"
    fingerprint = compute_fingerprint(key_bytes)
    return f"<key:{fingerprint[:8]}...>"
