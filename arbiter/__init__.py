"""
Arbiter - Production-Grade Identity + Integrity + Behavior for AI Agents

Arbiter provides a complete security layer for autonomous AI agents:

Identity Layer:
- Decentralized Identifiers (DIDs) for agent identity
- Verifiable Credentials with BBS+ for selective disclosure
- Zero-Knowledge Proofs for privacy-preserving verification
- Post-Quantum Cryptography for future-proof security
- Instant revocation via cryptographic accumulators

Integrity Layer:
- Attribute-Based Access Control (ABAC) for fine-grained authorization
- Paillier homomorphic encryption for privacy-preserving computation
- Deterministic policy evaluation

Behavior Layer:
- Real-time behavioral monitoring as a daemon process
- Semantic drift detection using ML embeddings
- Fast on-host anomaly detectors
- Policy-driven enforcement with automatic credential revocation
- Honeypot routing for deception of malicious agents

Quick Start:
    from arbiter import Identity, Integrity, Behavior
    
    # Create agent identity with revocation
    revocation = Identity.create_revocation_manager()
    
    # Start behavior monitoring daemon
    daemon = Behavior.create_daemon(revocation_manager=revocation)
    daemon.start()
    
    # Create agent identity
    identity = Identity.create_agent("my-agent")
    
    # Issue credential
    credential = identity.issue_credential(
        subject_did=identity.did,
        claims={"role": "researcher", "capabilities": ["search", "analyze"]}
    )
    
    # Check access
    pep = Integrity.create_enforcement_point()
    result = pep.enforce(
        subject_did=identity.did,
        resource_id="data/research",
        action="read",
        presentation=identity.create_presentation(credential)
    )
    
    # Submit events for behavior monitoring
    daemon.submit_telemetry(
        agent_id="my-agent",
        agent_role="researcher",
        session_id="session-1",
        user_id="user-1",
        event_type="USER_PROMPT",
        tool_name="SearchTool",
        payload="Search for research papers",
        token_count=50,
    )

For detailed documentation, see:
- ARCHITECTURE.md - System design overview
- CRYPTO.md - Cryptographic specifications
- FLOWS.md - Protocol sequences
- BEHAVIOR.md - Behavior monitoring integration
"""

__version__ = "0.1.0"
__author__ = "Arbiter Team"

# High-level API imports
from arbiter.identity import (
    # Core identity
    DID,
    DIDDocumentBuilder,
    KeyManager,
    VCIssuer,
    # Verification
    VerificationHub,
    TrustDecision,
    # Revocation
    RevocationManager,
    # Registry
    InMemoryRegistry,
    DIDResolver,
)

from arbiter.integrity import (
    # ABAC
    PolicyEnforcementPoint,
    PolicyDecisionPoint,
    PolicyAdministrationPoint,
    PolicyInformationPoint,
    # Homomorphic
    EncryptedNumber,
    generate_paillier_keypair,
    paillier_encrypt,
    paillier_decrypt,
)

from arbiter.crypto import (
    # PQC
    generate_dilithium_keypair,
    generate_kyber_keypair,
    # BBS+
    generate_bbs_keypair,
)

from arbiter.common import (
    # Models
    DIDDocument,
    VerifiableCredential,
    Policy,
    AccessDecision,
    # Errors
    ArbiterError,
)

from arbiter.behavior import (
    # Core components
    BehaviorDaemon,
    BehaviorEvent,
    EventBus,
    ProfileStore,
    OnHostDetectors,
    CentralDetector,
    Watchdog,
    PolicyEngine,
    PolicyDecision,
    # Telemetry
    make_event as make_behavior_event,
)


# =============================================================================
# Convenience Classes for High-Level API
# =============================================================================

class Identity:
    """High-level identity management API."""
    
    @staticmethod
    def create_key_manager():
        """Create a new key manager."""
        return KeyManager()
    
    @staticmethod
    def create_issuer(issuer_did: str):
        """Create a credential issuer."""
        return VCIssuer.create(issuer_did)
    
    @staticmethod
    def create_verification_hub():
        """Create a verification hub."""
        return VerificationHub()
    
    @staticmethod
    def create_revocation_manager():
        """Create a revocation manager."""
        return RevocationManager.initialize_system()


class Integrity:
    """High-level integrity management API."""
    
    @staticmethod
    def create_enforcement_point():
        """Create a policy enforcement point."""
        from arbiter.integrity.abac import create_pep_with_identity_integration
        return create_pep_with_identity_integration()
    
    @staticmethod
    def create_policy_admin():
        """Create a policy administration point."""
        return PolicyAdministrationPoint()


class Behavior:
    """High-level behavior monitoring API."""
    
    @staticmethod
    def create_daemon(
        revocation_manager=None,
        revocation_callback=None,
        watchdog_threshold: float = 0.8,
        enable_async: bool = True,
    ):
        """
        Create a behavior monitoring daemon.
        
        Args:
            revocation_manager: Optional RevocationManager for auto-revocation
            revocation_callback: Optional callback(handler_id, reason)
            watchdog_threshold: Risk score threshold for ML watchdog
            enable_async: Whether to run in background thread
            
        Returns:
            Configured BehaviorDaemon instance
        """
        return BehaviorDaemon(
            revocation_manager=revocation_manager,
            revocation_callback=revocation_callback,
            watchdog_threshold=watchdog_threshold,
            enable_async=enable_async,
        )
    
    @staticmethod
    def create_event_bus():
        """Create an event bus for event normalization."""
        return EventBus()
    
    @staticmethod
    def create_profile_store(alpha: float = 0.2, history_size: int = 20):
        """Create a profile store for behavioral baselines."""
        return ProfileStore(alpha=alpha, history_size=history_size)
    
    @staticmethod
    def create_policy_engine(
        throttle_threshold: float = 0.60,
        quarantine_threshold: float = 0.75,
        honeypot_threshold: float = 0.90,
        revocation_threshold: float = 0.95,
    ):
        """Create a policy engine with custom thresholds."""
        return PolicyEngine(
            throttle_threshold=throttle_threshold,
            quarantine_threshold=quarantine_threshold,
            honeypot_threshold=honeypot_threshold,
            revocation_threshold=revocation_threshold,
        )


__all__ = [
    # Version
    "__version__",
    # High-level API
    "Identity",
    "Integrity",
    "Behavior",
    # Identity Layer
    "DID",
    "DIDDocumentBuilder",
    "KeyManager",
    "VCIssuer",
    "VerificationHub",
    "TrustDecision",
    "RevocationManager",
    "InMemoryRegistry",
    "DIDResolver",
    # Integrity Layer
    "PolicyEnforcementPoint",
    "PolicyDecisionPoint",
    "PolicyAdministrationPoint",
    "PolicyInformationPoint",
    "EncryptedNumber",
    "generate_paillier_keypair",
    "paillier_encrypt",
    "paillier_decrypt",
    # Behavior Layer
    "BehaviorDaemon",
    "BehaviorEvent",
    "EventBus",
    "ProfileStore",
    "OnHostDetectors",
    "CentralDetector",
    "Watchdog",
    "PolicyEngine",
    "PolicyDecision",
    "make_behavior_event",
    # Crypto
    "generate_dilithium_keypair",
    "generate_kyber_keypair",
    "generate_bbs_keypair",
    # Common
    "DIDDocument",
    "VerifiableCredential",
    "Policy",
    "AccessDecision",
    "ArbiterError",
]
