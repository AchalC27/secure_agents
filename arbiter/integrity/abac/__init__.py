"""
Arbiter - ABAC Package

Attribute-Based Access Control implementation.

Components:
- PAP: Policy Administration Point - policy management
- PIP: Policy Information Point - attribute retrieval
- PDP: Policy Decision Point - policy evaluation
- PEP: Policy Enforcement Point - decision enforcement

Reference: NIST SP 800-162
"""

from arbiter.integrity.abac.pap import (
    PolicyAdministrationPoint,
    PolicyRepository,
    PolicyMetadata,
)
from arbiter.integrity.abac.pip import (
    PolicyInformationPoint,
    AttributeContext,
    AttributeSource,
    CredentialAttributeSource,
    EnvironmentAttributeSource,
)
from arbiter.integrity.abac.pdp import (
    PolicyDecisionPoint,
    EvaluationContext,
    RuleEvaluationResult,
    PolicyEvaluationResult,
)
from arbiter.integrity.abac.pep import (
    PolicyEnforcementPoint,
    EnforcementResult,
    ObligationHandler,
    create_pep_with_identity_integration,
)

__all__ = [
    # PAP
    "PolicyAdministrationPoint",
    "PolicyRepository",
    "PolicyMetadata",
    # PIP
    "PolicyInformationPoint",
    "AttributeContext",
    "AttributeSource",
    "CredentialAttributeSource",
    "EnvironmentAttributeSource",
    # PDP
    "PolicyDecisionPoint",
    "EvaluationContext",
    "RuleEvaluationResult",
    "PolicyEvaluationResult",
    # PEP
    "PolicyEnforcementPoint",
    "EnforcementResult",
    "ObligationHandler",
    "create_pep_with_identity_integration",
]
