"""
Arbiter Simulator - Agent Definitions

Defines agent types that participate in simulations.

Each agent has:
- Identity (DID, credentials)
- Capabilities (what they can do)
- Behavior (how they interact)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Callable

from arbiter.simulator.tools import (
    ToolResult,
    get_context,
    create_agent_identity,
    issue_credential,
    create_presentation,
    verify_presentation,
    request_access,
    revoke_credential,
)


# =============================================================================
# Agent Types
# =============================================================================

class AgentRole(Enum):
    """Predefined agent roles."""
    IDENTITY_AUTHORITY = "identity_authority"
    RESEARCHER = "researcher"
    GUARDIAN = "guardian"
    COORDINATOR = "coordinator"
    DATA_PROVIDER = "data_provider"


# =============================================================================
# Simulated Agent
# =============================================================================

@dataclass
class SimulatedAgent:
    """An agent participating in the simulation.
    
    Attributes:
        name: Human-readable name
        role: Agent's role
        did: Assigned DID (set after creation)
        credentials: List of credential IDs
        capabilities: Agent's capabilities
    """
    name: str
    role: AgentRole
    did: str = ""
    credentials: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    
    # Action history
    actions: List[Dict[str, Any]] = field(default_factory=list)
    
    def log_action(self, action: str, result: ToolResult) -> None:
        """Log an action taken by this agent."""
        self.actions.append({
            "action": action,
            "success": result.success,
            "message": result.message,
        })
    
    def initialize(self) -> ToolResult:
        """Create this agent's identity."""
        result = create_agent_identity(self.name, self.role.value)
        if result.success:
            self.did = result.data["did"]
        self.log_action("initialize", result)
        return result
    
    def present_credential(
        self,
        credential_id: str,
        disclosed_claims: Optional[List[str]] = None,
        verifier: str = "verifier.example.com",
    ) -> ToolResult:
        """Create a presentation of a credential."""
        result = create_presentation(
            self.did,
            credential_id,
            disclosed_claims,
            verifier,
        )
        self.log_action("present_credential", result)
        return result
    
    def request_resource_access(
        self,
        resource_id: str,
        action: str,
        credential_id: Optional[str] = None,
    ) -> ToolResult:
        """Request access to a resource."""
        cred = credential_id or (self.credentials[0] if self.credentials else None)
        result = request_access(self.did, resource_id, action, cred)
        self.log_action(f"request_access:{action}", result)
        return result


# =============================================================================
# Identity Authority Agent
# =============================================================================

@dataclass
class IdentityAuthorityAgent(SimulatedAgent):
    """Agent that issues and manages credentials.
    
    The identity authority:
    - Issues credentials to other agents
    - Revokes compromised credentials
    - Maintains trust registry
    """
    role: AgentRole = field(default=AgentRole.IDENTITY_AUTHORITY)
    
    def __post_init__(self) -> None:
        self.capabilities = ["issue_credential", "revoke_credential", "verify"]
    
    def issue_credential_to(
        self,
        subject: SimulatedAgent,
        credential_type: str,
        claims: Dict[str, Any],
    ) -> ToolResult:
        """Issue a credential to another agent."""
        result = issue_credential(subject.did, credential_type, claims)
        if result.success:
            cred_id = result.data["credential_id"]
            subject.credentials.append(cred_id)
            # Update capabilities from claims
            if "capabilities" in claims:
                subject.capabilities.extend(claims["capabilities"])
        self.log_action(f"issue_credential:{credential_type}", result)
        return result
    
    def revoke_credential_of(
        self,
        subject: SimulatedAgent,
        credential_id: str,
        reason: str = "Compromised",
    ) -> ToolResult:
        """Revoke an agent's credential."""
        result = revoke_credential(credential_id, reason)
        if result.success and credential_id in subject.credentials:
            subject.credentials.remove(credential_id)
        self.log_action("revoke_credential", result)
        return result
    
    def verify_agent(
        self,
        subject: SimulatedAgent,
        credential_id: str,
        required_claims: Optional[List[str]] = None,
    ) -> ToolResult:
        """Verify an agent's credential."""
        result = verify_presentation(subject.did, credential_id, required_claims)
        self.log_action("verify_agent", result)
        return result


# =============================================================================
# Researcher Agent
# =============================================================================

@dataclass
class ResearcherAgent(SimulatedAgent):
    """Agent that performs research tasks.
    
    The researcher:
    - Requests access to data resources
    - Analyzes information
    - Presents credentials when challenged
    """
    role: AgentRole = field(default=AgentRole.RESEARCHER)
    
    def __post_init__(self) -> None:
        self.capabilities = []  # Set by credential
    
    def search_data(self, resource_id: str) -> ToolResult:
        """Search a data resource."""
        return self.request_resource_access(resource_id, "search")
    
    def analyze_data(self, resource_id: str) -> ToolResult:
        """Analyze a data resource."""
        return self.request_resource_access(resource_id, "analyze")
    
    def read_data(self, resource_id: str) -> ToolResult:
        """Read a data resource."""
        return self.request_resource_access(resource_id, "read")


# =============================================================================
# Guardian Agent
# =============================================================================

@dataclass
class GuardianAgent(SimulatedAgent):
    """Agent that enforces access control.
    
    The guardian:
    - Verifies credentials before granting access
    - Monitors for suspicious activity
    - Reports security incidents
    """
    role: AgentRole = field(default=AgentRole.GUARDIAN)
    
    # Access attempts
    access_log: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        self.capabilities = ["verify", "monitor", "report"]
    
    def check_access(
        self,
        requester: SimulatedAgent,
        resource_id: str,
        action: str,
    ) -> ToolResult:
        """Check if an agent can access a resource."""
        # First verify their credential
        if not requester.credentials:
            result = ToolResult(
                success=False,
                message=f"Agent {requester.name} has no credentials",
                data={"effect": "DENY"},
            )
        else:
            result = request_access(
                requester.did,
                resource_id,
                action,
                requester.credentials[0],
            )
        
        # Log access attempt
        self.access_log.append({
            "requester": requester.did,
            "resource": resource_id,
            "action": action,
            "permitted": result.success,
        })
        
        self.log_action("check_access", result)
        return result
    
    def verify_and_grant(
        self,
        requester: SimulatedAgent,
        resource_id: str,
        action: str,
        required_claims: Optional[List[str]] = None,
    ) -> ToolResult:
        """Verify credential and grant access in one step."""
        if not requester.credentials:
            return ToolResult(
                success=False,
                message=f"{requester.name} has no credentials to verify",
                data={"step": "verification", "effect": "DENY"},
            )
        
        # Step 1: Verify credential
        verify_result = verify_presentation(
            requester.did,
            requester.credentials[0],
            required_claims,
        )
        
        if not verify_result.success:
            self.log_action("verify_and_grant:verify_failed", verify_result)
            return verify_result
        
        # Step 2: Check access
        access_result = request_access(
            requester.did,
            resource_id,
            action,
            requester.credentials[0],
        )
        
        self.log_action("verify_and_grant", access_result)
        return access_result


# =============================================================================
# Coordinator Agent
# =============================================================================

@dataclass
class CoordinatorAgent(SimulatedAgent):
    """Agent that coordinates multi-agent workflows.
    
    The coordinator:
    - Orchestrates tasks between agents
    - Handles mutual authentication
    - Manages collaborative workflows
    """
    role: AgentRole = field(default=AgentRole.COORDINATOR)
    
    # Managed agents
    managed_agents: List[SimulatedAgent] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        self.capabilities = ["coordinate", "delegate", "authenticate"]
    
    def add_agent(self, agent: SimulatedAgent) -> None:
        """Add an agent to coordinate."""
        self.managed_agents.append(agent)
    
    def authenticate_agent(
        self,
        agent: SimulatedAgent,
        authority: IdentityAuthorityAgent,
    ) -> ToolResult:
        """Authenticate an agent via the identity authority."""
        if not agent.credentials:
            return ToolResult(
                success=False,
                message=f"{agent.name} has no credentials",
            )
        
        return authority.verify_agent(agent, agent.credentials[0])
    
    def delegate_task(
        self,
        agent: SimulatedAgent,
        resource_id: str,
        action: str,
    ) -> ToolResult:
        """Delegate a task to an agent."""
        if agent not in self.managed_agents:
            return ToolResult(
                success=False,
                message=f"{agent.name} is not a managed agent",
            )
        
        result = agent.request_resource_access(resource_id, action)
        self.log_action(f"delegate:{action}", result)
        return result


# =============================================================================
# Data Provider Agent
# =============================================================================

@dataclass
class DataProviderAgent(SimulatedAgent):
    """Agent that provides data resources.
    
    The data provider:
    - Hosts data resources
    - Enforces access policies
    - Logs access attempts
    """
    role: AgentRole = field(default=AgentRole.DATA_PROVIDER)
    
    # Available resources
    resources: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        self.capabilities = ["host", "provide", "log"]
    
    def add_resource(
        self,
        resource_id: str,
        data: Any,
        required_capabilities: Optional[List[str]] = None,
    ) -> None:
        """Add a resource."""
        self.resources[resource_id] = {
            "data": data,
            "required_capabilities": required_capabilities or [],
            "access_log": [],
        }
    
    def serve_resource(
        self,
        resource_id: str,
        requester: SimulatedAgent,
        action: str,
    ) -> ToolResult:
        """Serve a resource to a requester (after access check)."""
        if resource_id not in self.resources:
            return ToolResult(
                success=False,
                message=f"Resource not found: {resource_id}",
            )
        
        resource = self.resources[resource_id]
        
        # Check access
        access_result = requester.request_resource_access(
            resource_id, action
        )
        
        if not access_result.success:
            return access_result
        
        # Log and return
        resource["access_log"].append({
            "agent": requester.did,
            "action": action,
        })
        
        return ToolResult(
            success=True,
            message=f"Served {resource_id} to {requester.name}",
            data={"resource_id": resource_id},
        )


# =============================================================================
# Agent Factory
# =============================================================================

def create_identity_authority(name: str = "TrustAuthority") -> IdentityAuthorityAgent:
    """Create and initialize an identity authority agent."""
    agent = IdentityAuthorityAgent(name=name)
    agent.initialize()
    
    # Setup as issuer
    ctx = get_context()
    ctx.setup_issuer(name)
    
    return agent


def create_researcher(name: str, authority: Optional[IdentityAuthorityAgent] = None) -> ResearcherAgent:
    """Create and initialize a researcher agent."""
    agent = ResearcherAgent(name=name)
    agent.initialize()
    return agent


def create_guardian(name: str) -> GuardianAgent:
    """Create and initialize a guardian agent."""
    agent = GuardianAgent(name=name)
    agent.initialize()
    return agent


def create_coordinator(name: str) -> CoordinatorAgent:
    """Create and initialize a coordinator agent."""
    agent = CoordinatorAgent(name=name)
    agent.initialize()
    return agent


def create_data_provider(name: str) -> DataProviderAgent:
    """Create and initialize a data provider agent."""
    agent = DataProviderAgent(name=name)
    agent.initialize()
    return agent
