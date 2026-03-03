"""
Arbiter Simulator - Custom Tools

CrewAI-compatible tools wrapping Arbiter protocol operations.

These tools allow agents to:
- Issue and verify credentials
- Create and verify presentations
- Request access to resources
- Revoke credentials
- Monitor agent behavior (via behavior daemon)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

from arbiter.common.utils import generate_id, utc_now
from arbiter.common.models import (
    VerifiableCredential,
    VerifiablePresentation,
    ZKProof,
    ProofType,
    Effect,
)
from arbiter.identity.did import DID, DIDDocumentBuilder
from arbiter.identity.key_management import KeyManager, KeyPurpose
from arbiter.identity.vc_issuer import VCIssuer, CredentialRequest, IssuedCredentialBundle
from arbiter.identity.verification_hub import VerificationHub, TrustDecision
from arbiter.identity.revocation import RevocationManager
from arbiter.integrity.abac import PolicyEnforcementPoint, EvaluationContext
from arbiter.integrity.abac.pdp import PolicyDecisionPoint

# Import behavior monitoring
from arbiter.behavior import BehaviorDaemon, make_event


# =============================================================================
# Tool Result Types
# =============================================================================

@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        status = "[OK]" if self.success else "[X]"
        return f"[{status}] {self.message}"


# =============================================================================
# Identity Management Context
# =============================================================================

class SimulationContext:
    """Shared context for simulation tools.
    
    Maintains state across tool invocations:
    - Registered agents and their credentials
    - Issued credentials
    - Revocation status
    - Access policies
    - Behavior monitoring daemon
    """
    
    def __init__(self) -> None:
        """Initialize simulation context."""
        self.key_manager = KeyManager()
        self.issuer: Optional[VCIssuer] = None
        self.issuer_did: Optional[str] = None
        self.verification_hub = VerificationHub()
        self.revocation_manager: Optional[RevocationManager] = None
        self.pep = PolicyEnforcementPoint()
        
        # Agent registry
        self.agents: Dict[str, Dict[str, Any]] = {}
        # Credential registry
        self.credentials: Dict[str, IssuedCredentialBundle] = {}
        # Revoked handlers
        self.revoked: set[str] = set()
        
        # Behavior monitoring daemon
        self.behavior_daemon: Optional[BehaviorDaemon] = None
        
        # Event log
        self.events: List[Dict[str, Any]] = []
        
        # Session counter for behavior events
        self._session_counter = 0
    
    def log_event(self, event_type: str, agent_did: str, details: Dict[str, Any]) -> None:
        """Log a simulation event."""
        self.events.append({
            "timestamp": utc_now().isoformat(),
            "type": event_type,
            "agent": agent_did,
            **details,
        })
    
    def setup_issuer(self, issuer_name: str = "TrustAuthority") -> str:
        """Setup the credential issuer with behavior monitoring."""
        auth_key = self.key_manager.generate_authentication_key()
        issuer_did = DID.from_public_key(auth_key.public_key.public_key_bytes)
        
        self.issuer_did = issuer_did.did_string
        self.issuer = VCIssuer.create(self.issuer_did)
        self.revocation_manager = RevocationManager.initialize_system()
        
        # Setup behavior daemon with revocation integration
        self.behavior_daemon = BehaviorDaemon(
            revocation_manager=self.revocation_manager,
            revocation_callback=self._on_behavior_revocation,
            enable_async=False,  # Sync mode for testing
        )
        
        self.log_event("ISSUER_SETUP", self.issuer_did, {"name": issuer_name})
        
        return self.issuer_did
    
    def _on_behavior_revocation(self, handler_id: str, reason: str) -> None:
        """Callback when behavior daemon triggers revocation."""
        self.revoked.add(handler_id)
        self.log_event("BEHAVIOR_REVOCATION", "system", {
            "handler_id": handler_id,
            "reason": reason,
        })
    
    def submit_behavior_event(
        self,
        agent_did: str,
        agent_role: str,
        tool_name: str,
        payload: str,
        token_count: int = 50,
        event_type: str = "USER_PROMPT",
    ) -> Dict[str, Any]:
        """
        Submit an agent action for behavior monitoring.
        
        This tracks agent behavior and can trigger credential revocation.
        
        Returns processing result with risk score and decisions.
        """
        if not self.behavior_daemon:
            return {"error": "Behavior daemon not initialized"}
        
        agent_info = self.agents.get(agent_did, {})
        agent_name = agent_info.get("name", "unknown")
        
        # Generate session ID
        session_id = f"sim-session-{self._session_counter}"
        
        # Create telemetry event
        event = make_event(
            agent_id=agent_name,
            agent_role=agent_role,
            session_id=session_id,
            user_id="simulation",
            event_type=event_type,
            tool_name=tool_name,
            payload=payload,
            token_count=token_count,
        )
        
        # Submit to behavior daemon
        self.behavior_daemon.submit_event(
            event,
            agent_did=agent_did,
        )
        
        # Get result
        risk_score = self.behavior_daemon.get_risk_score(agent_name)
        audit_log = self.behavior_daemon.get_audit_log(limit=1)
        
        result = {
            "agent": agent_name,
            "risk_score": risk_score,
            "processed": True,
        }
        
        if audit_log:
            last_entry = audit_log[-1]
            result["alerts"] = last_entry.get("alerts", [])
            result["decision"] = last_entry.get("decision", {})
        
        return result


# Global simulation context
_context: Optional[SimulationContext] = None


def get_context() -> SimulationContext:
    """Get or create the simulation context."""
    global _context
    if _context is None:
        _context = SimulationContext()
    return _context


def reset_context() -> None:
    """Reset simulation context (for testing)."""
    global _context
    _context = None


# =============================================================================
# Identity Tools
# =============================================================================

def create_agent_identity(
    agent_name: str,
    agent_type: str = "general",
) -> ToolResult:
    """Create a new agent with DID and keys.
    
    Args:
        agent_name: Human-readable agent name
        agent_type: Type of agent (researcher, guardian, etc.)
        
    Returns:
        ToolResult with agent DID
    """
    ctx = get_context()
    
    # Generate keys
    auth_key = ctx.key_manager.generate_authentication_key()
    did = DID.from_public_key(auth_key.public_key.public_key_bytes)
    
    # Build DID Document
    builder = DIDDocumentBuilder(did)
    builder.add_authentication_key(auth_key.public_key.public_key_bytes)
    builder.set_timestamps()
    document = builder.build()
    
    # Register agent
    ctx.agents[did.did_string] = {
        "name": agent_name,
        "type": agent_type,
        "did": did.did_string,
        "document": document,
        "auth_key_id": auth_key.key_id,
        "created": utc_now().isoformat(),
        "credentials": [],
    }
    
    ctx.log_event("AGENT_CREATED", did.did_string, {
        "name": agent_name,
        "type": agent_type,
    })
    
    return ToolResult(
        success=True,
        message=f"Created agent '{agent_name}' with DID: {did.did_string}",
        data={"did": did.did_string, "name": agent_name},
    )


def issue_credential(
    subject_did: str,
    credential_type: str,
    claims: Dict[str, Any],
) -> ToolResult:
    """Issue a credential to an agent.
    
    Args:
        subject_did: DID of the agent receiving credential
        credential_type: Type of credential
        claims: Credential claims/attributes
        
    Returns:
        ToolResult with credential ID
    """
    ctx = get_context()
    
    # Ensure issuer is setup
    if ctx.issuer is None:
        ctx.setup_issuer()
    
    # Verify subject exists
    if subject_did not in ctx.agents:
        return ToolResult(
            success=False,
            message=f"Unknown agent: {subject_did}",
        )
    
    # Issue credential
    request = CredentialRequest(
        subject_did=subject_did,
        credential_type=credential_type,
        claims=claims,
    )
    
    bundle = ctx.issuer.issue_credential(request)
    
    # Store credential
    cred_id = bundle.credential.id
    ctx.credentials[cred_id] = bundle
    ctx.agents[subject_did]["credentials"].append(cred_id)
    
    ctx.log_event("CREDENTIAL_ISSUED", subject_did, {
        "credential_id": cred_id,
        "type": credential_type,
        "claims": list(claims.keys()),
    })
    
    return ToolResult(
        success=True,
        message=f"Issued {credential_type} to {ctx.agents[subject_did]['name']}",
        data={
            "credential_id": cred_id,
            "subject": subject_did,
            "type": credential_type,
        },
    )


def create_presentation(
    holder_did: str,
    credential_id: str,
    disclosed_claims: Optional[List[str]] = None,
    verifier_domain: str = "verifier.example.com",
) -> ToolResult:
    """Create a verifiable presentation from a credential.
    
    Args:
        holder_did: DID of the credential holder
        credential_id: ID of credential to present
        disclosed_claims: Claims to disclose (None = all)
        verifier_domain: Domain of the verifier
        
    Returns:
        ToolResult with presentation
    """
    ctx = get_context()
    
    # Verify holder
    if holder_did not in ctx.agents:
        return ToolResult(success=False, message=f"Unknown agent: {holder_did}")
    
    # Get credential
    if credential_id not in ctx.credentials:
        return ToolResult(success=False, message=f"Unknown credential: {credential_id}")
    
    bundle = ctx.credentials[credential_id]
    
    # Check ownership
    if bundle.credential.credential_subject.id != holder_did:
        return ToolResult(success=False, message="Credential does not belong to holder")
    
    # Check revocation
    handler_id = bundle.credential.revocation.handler_id
    if handler_id in ctx.revoked:
        return ToolResult(success=False, message="Credential has been revoked")
    
    # Create presentation
    challenge = generate_id(prefix="challenge-").encode()
    
    # Build ZK proofs
    proofs = []
    
    # Validity proof
    proofs.append(ZKProof(
        proof_type=ProofType.CREDENTIAL_VALIDITY,
        challenge=challenge,
        proof_data=b"simulated-validity-proof",
        disclosed_attributes=disclosed_claims or [],
        disclosed_values={
            k: v for k, v in bundle.credential.credential_subject.claims.items()
            if disclosed_claims is None or k in disclosed_claims
        },
    ))
    
    # Non-revocation proof
    proofs.append(ZKProof(
        proof_type=ProofType.NON_REVOCATION,
        challenge=challenge,
        proof_data=b"simulated-non-revocation-proof",
        accumulator_value=b"current-accumulator-value",
    ))
    
    presentation = VerifiablePresentation(
        holder=holder_did,
        challenge=challenge,
        domain=verifier_domain,
        zkp_proofs=proofs,
        credential_id=credential_id,
    )
    
    ctx.log_event("PRESENTATION_CREATED", holder_did, {
        "credential_id": credential_id,
        "disclosed_claims": disclosed_claims,
        "verifier": verifier_domain,
    })
    
    return ToolResult(
        success=True,
        message=f"Created presentation for credential {credential_id}",
        data={
            "holder": holder_did,
            "credential_id": credential_id,
            "disclosed_values": proofs[0].disclosed_values,
        },
    )


def verify_presentation(
    presentation_holder: str,
    credential_id: str,
    required_claims: Optional[List[str]] = None,
) -> ToolResult:
    """Verify a presentation and return trust decision.
    
    Args:
        presentation_holder: DID of the presenter
        credential_id: Credential being presented
        required_claims: Claims that must be present
        
    Returns:
        ToolResult with trust decision
    """
    ctx = get_context()
    
    # Get credential
    if credential_id not in ctx.credentials:
        return ToolResult(
            success=False,
            message=f"Unknown credential: {credential_id}",
            data={"decision": "UNTRUSTED", "reason": "Unknown credential"},
        )
    
    bundle = ctx.credentials[credential_id]
    
    # Check ownership
    if bundle.credential.credential_subject.id != presentation_holder:
        return ToolResult(
            success=False,
            message="Credential holder mismatch",
            data={"decision": "UNTRUSTED", "reason": "Holder mismatch"},
        )
    
    # Check revocation
    handler_id = bundle.credential.revocation.handler_id
    if handler_id in ctx.revoked:
        ctx.log_event("VERIFICATION_FAILED", presentation_holder, {
            "credential_id": credential_id,
            "reason": "Credential revoked",
        })
        return ToolResult(
            success=False,
            message="Credential has been revoked",
            data={"decision": "UNTRUSTED", "reason": "Revoked"},
        )
    
    # Check required claims
    claims = bundle.credential.credential_subject.claims
    if required_claims:
        missing = [c for c in required_claims if c not in claims]
        if missing:
            return ToolResult(
                success=False,
                message=f"Missing required claims: {missing}",
                data={"decision": "UNTRUSTED", "reason": "Missing claims"},
            )
    
    # Verify issuer (in simulation, we trust our issuer)
    if bundle.credential.issuer != ctx.issuer_did:
        return ToolResult(
            success=False,
            message="Untrusted issuer",
            data={"decision": "UNTRUSTED", "reason": "Unknown issuer"},
        )
    
    ctx.log_event("VERIFICATION_SUCCESS", presentation_holder, {
        "credential_id": credential_id,
        "claims_verified": list(claims.keys()),
    })
    
    return ToolResult(
        success=True,
        message=f"Verified: {ctx.agents[presentation_holder]['name']} has valid credential",
        data={
            "decision": "TRUSTED",
            "holder": presentation_holder,
            "issuer": bundle.credential.issuer,
            "claims": claims,
        },
    )


def revoke_credential(
    credential_id: str,
    reason: str = "Unspecified",
) -> ToolResult:
    """Revoke a credential.
    
    Args:
        credential_id: ID of credential to revoke
        reason: Reason for revocation
        
    Returns:
        ToolResult
    """
    ctx = get_context()
    
    if credential_id not in ctx.credentials:
        return ToolResult(success=False, message=f"Unknown credential: {credential_id}")
    
    bundle = ctx.credentials[credential_id]
    handler_id = bundle.credential.revocation.handler_id
    
    # Check if already revoked
    if handler_id in ctx.revoked:
        return ToolResult(success=False, message="Credential already revoked")
    
    # Revoke
    ctx.revoked.add(handler_id)
    
    subject_did = bundle.credential.credential_subject.id
    agent_name = ctx.agents.get(subject_did, {}).get("name", "Unknown")
    
    ctx.log_event("CREDENTIAL_REVOKED", subject_did, {
        "credential_id": credential_id,
        "handler_id": handler_id,
        "reason": reason,
    })
    
    return ToolResult(
        success=True,
        message=f"Revoked credential for {agent_name}: {reason}",
        data={"credential_id": credential_id, "handler_id": handler_id},
    )


# =============================================================================
# Access Control Tools
# =============================================================================

def request_access(
    requester_did: str,
    resource_id: str,
    action: str,
    credential_id: Optional[str] = None,
) -> ToolResult:
    """Request access to a resource.
    
    Args:
        requester_did: DID of requesting agent
        resource_id: Resource being accessed
        action: Action to perform
        credential_id: Optional credential to present
        
    Returns:
        ToolResult with access decision
    """
    ctx = get_context()
    
    # Verify requester
    if requester_did not in ctx.agents:
        return ToolResult(
            success=False,
            message=f"Unknown agent: {requester_did}",
            data={"effect": "DENY"},
        )
    
    agent = ctx.agents[requester_did]
    
    # Get capabilities from credential if provided
    capabilities = []
    if credential_id and credential_id in ctx.credentials:
        bundle = ctx.credentials[credential_id]
        
        # Check revocation
        if bundle.credential.revocation.handler_id in ctx.revoked:
            ctx.log_event("ACCESS_DENIED", requester_did, {
                "resource": resource_id,
                "action": action,
                "reason": "Revoked credential",
            })
            return ToolResult(
                success=False,
                message="Credential revoked - access denied",
                data={"effect": "DENY", "reason": "Revoked credential"},
            )
        
        capabilities = bundle.credential.credential_subject.claims.get("capabilities", [])
    
    # Build evaluation context
    eval_context = EvaluationContext(
        subject={
            "did": requester_did,
            "name": agent["name"],
            "type": agent["type"],
            "capabilities": capabilities,
        },
        resource={"id": resource_id},
        action={"id": action},
        environment={"timestamp": utc_now().isoformat()},
    )
    
    # Check if action matches any capability
    # Simple rule: action must be in capabilities
    permitted = action in capabilities or "admin" in capabilities
    
    effect = "PERMIT" if permitted else "DENY"
    
    ctx.log_event("ACCESS_" + effect, requester_did, {
        "resource": resource_id,
        "action": action,
        "capabilities": capabilities,
    })
    
    if permitted:
        return ToolResult(
            success=True,
            message=f"Access granted: {agent['name']} can {action} {resource_id}",
            data={"effect": "PERMIT", "capabilities": capabilities},
        )
    else:
        return ToolResult(
            success=False,
            message=f"Access denied: {agent['name']} lacks '{action}' capability",
            data={"effect": "DENY", "required": action, "has": capabilities},
        )


# =============================================================================
# Utility Tools
# =============================================================================

def get_agent_info(agent_did: str) -> ToolResult:
    """Get information about an agent.
    
    Args:
        agent_did: DID of the agent
        
    Returns:
        ToolResult with agent information
    """
    ctx = get_context()
    
    if agent_did not in ctx.agents:
        return ToolResult(success=False, message=f"Unknown agent: {agent_did}")
    
    agent = ctx.agents[agent_did]
    
    return ToolResult(
        success=True,
        message=f"Agent: {agent['name']}",
        data={
            "did": agent_did,
            "name": agent["name"],
            "type": agent["type"],
            "credentials": agent["credentials"],
            "created": agent["created"],
        },
    )


def list_agents() -> ToolResult:
    """List all registered agents.
    
    Returns:
        ToolResult with agent list
    """
    ctx = get_context()
    
    agents = [
        {"did": did, "name": info["name"], "type": info["type"]}
        for did, info in ctx.agents.items()
    ]
    
    return ToolResult(
        success=True,
        message=f"Found {len(agents)} agents",
        data={"agents": agents},
    )


def get_event_log(limit: int = 20) -> ToolResult:
    """Get recent events from the simulation.
    
    Args:
        limit: Maximum events to return
        
    Returns:
        ToolResult with event log
    """
    ctx = get_context()
    
    events = ctx.events[-limit:]
    
    return ToolResult(
        success=True,
        message=f"Returning {len(events)} events",
        data={"events": events},
    )
