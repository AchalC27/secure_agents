"""
Arbiter - Policy Enforcement Point (PEP)

The PEP intercepts access requests, queries the PDP, and enforces decisions.

Reference: NIST SP 800-162 - ABAC Architecture

The PEP:
- Intercepts all access requests
- Builds evaluation context from available data
- Queries PDP for decision
- Enforces the decision (permit/deny)
- Handles obligations

Integration with Identity Layer:
- Validates credentials before evaluation
- Extracts attributes from ZK proofs
- Verifies non-revocation status
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from arbiter.common.models import (
    AccessRequest,
    AccessDecision,
    Policy,
    Effect,
    VerifiablePresentation,
)
from arbiter.common.errors import (
    AccessDeniedError,
    AuthorizationError,
)
from arbiter.common.utils import utc_now, generate_id
from arbiter.integrity.abac.pdp import PolicyDecisionPoint, EvaluationContext
from arbiter.integrity.abac.pip import PolicyInformationPoint, AttributeContext
from arbiter.integrity.abac.pap import PolicyAdministrationPoint
from arbiter.integrity.policy_models import PolicySet, CombiningAlgorithm


# =============================================================================
# Enforcement Result
# =============================================================================

@dataclass
class EnforcementResult:
    """Result of policy enforcement.
    
    Attributes:
        permitted: Whether access is permitted
        decision: The underlying access decision
        obligations: Actions to be performed
        advice: Advisory information
    """
    permitted: bool
    decision: AccessDecision
    obligations: List[Dict[str, Any]] = field(default_factory=list)
    advice: List[str] = field(default_factory=list)


# =============================================================================
# Obligation Handler
# =============================================================================

class ObligationHandler:
    """Handles obligations from policy decisions.
    
    Obligations are actions that must be performed when
    access is granted or denied.
    """

    def __init__(self) -> None:
        """Initialize handler."""
        self._handlers: Dict[
            str,
            Callable[[Dict[str, Any]], bool]
        ] = {}

    def register_handler(
        self,
        obligation_type: str,
        handler: Callable[[Dict[str, Any]], bool],
    ) -> None:
        """Register an obligation handler.
        
        Args:
            obligation_type: Type of obligation
            handler: Function to handle the obligation
        """
        self._handlers[obligation_type] = handler

    def fulfill(
        self,
        obligations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Fulfill obligations.
        
        Args:
            obligations: Obligations to fulfill
            
        Returns:
            List of failed obligations
        """
        failed = []
        
        for obligation in obligations:
            ob_type = obligation.get("type", "")
            handler = self._handlers.get(ob_type)
            
            if handler:
                try:
                    if not handler(obligation):
                        failed.append(obligation)
                except Exception:
                    failed.append(obligation)
            else:
                # No handler - obligation fails
                failed.append(obligation)
        
        return failed


# =============================================================================
# Policy Enforcement Point
# =============================================================================

class PolicyEnforcementPoint:
    """Enforces access control decisions.
    
    The PEP is the primary interface for access control:
    1. Receives access requests
    2. Builds evaluation context (via PIP)
    3. Queries PDP for decision
    4. Enforces the decision
    5. Handles obligations
    
    Integration with Identity:
    - Accepts verifiable presentations for subject attributes
    - Validates credentials before extracting attributes
    - Ensures non-revocation before granting access
    """

    def __init__(
        self,
        pdp: Optional[PolicyDecisionPoint] = None,
        pip: Optional[PolicyInformationPoint] = None,
        pap: Optional[PolicyAdministrationPoint] = None,
    ) -> None:
        """Initialize the PEP.
        
        Args:
            pdp: Policy Decision Point
            pip: Policy Information Point
            pap: Policy Administration Point
        """
        self.pdp = pdp or PolicyDecisionPoint()
        self.pip = pip or PolicyInformationPoint()
        self.pap = pap or PolicyAdministrationPoint()
        self.obligation_handler = ObligationHandler()
        
        # Audit log
        self._audit_log: List[Dict[str, Any]] = []
        self._audit_enabled = True

    def enforce(
        self,
        subject_did: str,
        resource_id: str,
        action: str,
        presentation: Optional[VerifiablePresentation] = None,
        resource_metadata: Optional[Dict[str, Any]] = None,
        environment: Optional[Dict[str, Any]] = None,
        policy_ids: Optional[List[str]] = None,
    ) -> EnforcementResult:
        """Enforce access control for a request.
        
        Main entry point for access control.
        
        Args:
            subject_did: DID of the requesting agent
            resource_id: Resource being accessed
            action: Action being performed
            presentation: Optional verifiable presentation
            resource_metadata: Resource attributes
            environment: Environment attributes
            policy_ids: Specific policies to evaluate (or all active)
            
        Returns:
            EnforcementResult with decision
        """
        # Create request
        request = AccessRequest(
            request_id=generate_id(prefix="req-"),
            subject_did=subject_did,
            resource_id=resource_id,
            action=action,
            environment=environment or {},
            presentation=presentation,
        )
        
        # Build attribute context
        attr_context = AttributeContext(
            subject_did=subject_did,
            resource_id=resource_id,
            action=action,
            subject_presentation=presentation,
            resource_metadata=resource_metadata or {},
            environment=environment or {},
        )
        
        # Get all attributes via PIP
        all_attrs = self.pip.get_all_attributes(attr_context)
        
        # Build evaluation context
        eval_context = EvaluationContext(
            subject=all_attrs.get("subject", {}),
            resource=all_attrs.get("resource", {}),
            action=all_attrs.get("action", {}),
            environment=all_attrs.get("environment", {}),
        )
        
        # Get policies to evaluate
        if policy_ids:
            policies = [self.pap.get_policy(pid) for pid in policy_ids]
        else:
            policies = self.pap.list_policies(active_only=True)
        
        # Evaluate via PDP
        decision = self.pdp.evaluate(
            request,
            policies,
            eval_context,
            CombiningAlgorithm.DENY_OVERRIDES,
        )
        
        # Determine if permitted
        permitted = decision.effect == Effect.PERMIT
        
        # Handle obligations
        failed_obligations = []
        if decision.obligations:
            failed_obligations = self.obligation_handler.fulfill(
                decision.obligations
            )
            # If mandatory obligations fail, deny access
            if failed_obligations:
                permitted = False
                decision.reason = "Mandatory obligation failed"
        
        # Audit
        if self._audit_enabled:
            self._log_decision(request, decision, permitted)
        
        return EnforcementResult(
            permitted=permitted,
            decision=decision,
            obligations=failed_obligations,
            advice=decision.advice,
        )

    def enforce_or_raise(
        self,
        subject_did: str,
        resource_id: str,
        action: str,
        **kwargs: Any,
    ) -> EnforcementResult:
        """Enforce and raise exception if denied.
        
        Args:
            subject_did: DID of the requesting agent
            resource_id: Resource being accessed
            action: Action being performed
            **kwargs: Additional arguments for enforce()
            
        Returns:
            EnforcementResult if permitted
            
        Raises:
            AccessDeniedError: If access is denied
        """
        result = self.enforce(subject_did, resource_id, action, **kwargs)
        
        if not result.permitted:
            raise AccessDeniedError(
                resource_id=resource_id,
                action=action,
                reason=result.decision.reason,
            )
        
        return result

    def check_permission(
        self,
        subject_did: str,
        resource_id: str,
        action: str,
        **kwargs: Any,
    ) -> bool:
        """Quick permission check.
        
        Args:
            subject_did: DID of the requesting agent
            resource_id: Resource being accessed
            action: Action being performed
            **kwargs: Additional arguments
            
        Returns:
            True if permitted
        """
        result = self.enforce(subject_did, resource_id, action, **kwargs)
        return result.permitted

    def enforce_with_policy_set(
        self,
        subject_did: str,
        resource_id: str,
        action: str,
        policy_set_id: str,
        **kwargs: Any,
    ) -> EnforcementResult:
        """Enforce using a specific policy set.
        
        Args:
            subject_did: DID of the requesting agent
            resource_id: Resource being accessed
            action: Action being performed
            policy_set_id: Policy set to use
            **kwargs: Additional arguments
            
        Returns:
            EnforcementResult
        """
        # Build context
        attr_context = AttributeContext(
            subject_did=subject_did,
            resource_id=resource_id,
            action=action,
            subject_presentation=kwargs.get("presentation"),
            resource_metadata=kwargs.get("resource_metadata", {}),
            environment=kwargs.get("environment", {}),
        )
        
        all_attrs = self.pip.get_all_attributes(attr_context)
        
        eval_context = EvaluationContext(
            subject=all_attrs.get("subject", {}),
            resource=all_attrs.get("resource", {}),
            action=all_attrs.get("action", {}),
            environment=all_attrs.get("environment", {}),
        )
        
        # Get policy set
        policy_set = self.pap.get_policy_set(policy_set_id)
        
        # Create request
        request = AccessRequest(
            request_id=generate_id(prefix="req-"),
            subject_did=subject_did,
            resource_id=resource_id,
            action=action,
        )
        
        # Evaluate
        decision = self.pdp.evaluate_policy_set(request, policy_set, eval_context)
        
        permitted = decision.effect == Effect.PERMIT
        
        if self._audit_enabled:
            self._log_decision(request, decision, permitted)
        
        return EnforcementResult(
            permitted=permitted,
            decision=decision,
        )

    def register_obligation_handler(
        self,
        obligation_type: str,
        handler: Callable[[Dict[str, Any]], bool],
    ) -> None:
        """Register an obligation handler.
        
        Args:
            obligation_type: Type of obligation
            handler: Handler function
        """
        self.obligation_handler.register_handler(obligation_type, handler)

    def get_audit_log(
        self,
        limit: int = 100,
        subject_did: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get audit log entries.
        
        Args:
            limit: Maximum entries to return
            subject_did: Filter by subject
            resource_id: Filter by resource
            
        Returns:
            Matching audit entries
        """
        entries = self._audit_log[-limit:]
        
        if subject_did:
            entries = [e for e in entries if e.get("subject_did") == subject_did]
        if resource_id:
            entries = [e for e in entries if e.get("resource_id") == resource_id]
        
        return entries

    def enable_audit(self, enabled: bool = True) -> None:
        """Enable or disable audit logging.
        
        Args:
            enabled: Whether to enable auditing
        """
        self._audit_enabled = enabled

    def _log_decision(
        self,
        request: AccessRequest,
        decision: AccessDecision,
        permitted: bool,
    ) -> None:
        """Log an access decision for audit.
        
        Args:
            request: The access request
            decision: The decision made
            permitted: Final permission status
        """
        entry = {
            "timestamp": utc_now().isoformat(),
            "request_id": request.request_id,
            "subject_did": request.subject_did,
            "resource_id": request.resource_id,
            "action": request.action,
            "permitted": permitted,
            "effect": decision.effect.value if decision.effect else None,
            "policy_id": decision.policy_id,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
        }
        self._audit_log.append(entry)
        
        # Keep log size bounded
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-5000:]


# =============================================================================
# Pre-configured PEP Factory
# =============================================================================

def create_pep_with_identity_integration() -> PolicyEnforcementPoint:
    """Create a PEP configured for identity integration.
    
    Returns:
        Configured PEP with identity-aware attribute extraction
    """
    pep = PolicyEnforcementPoint()
    
    # Register attribute resolvers for identity data
    def resolve_capabilities(context: AttributeContext) -> List[str]:
        """Extract capabilities from presentation."""
        if not context.subject_presentation:
            return []
        
        capabilities = []
        for proof in context.subject_presentation.zkp_proofs:
            caps = proof.disclosed_values.get("capabilities", [])
            if isinstance(caps, list):
                capabilities.extend(caps)
            proven = proof.disclosed_values.get("proven_capabilities", [])
            if isinstance(proven, list):
                capabilities.extend(proven)
        
        return list(set(capabilities))
    
    pep.pip.register_resolver("subject.capabilities", resolve_capabilities)
    
    return pep
