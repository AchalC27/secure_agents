"""
Arbiter - ABAC Policy Models

Data models for Attribute-Based Access Control policies.

Reference: NIST SP 800-162 - Guide to Attribute Based Access Control
https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-162.pdf

ABAC enables fine-grained access control based on:
- Subject attributes (who is requesting)
- Resource attributes (what is being accessed)
- Action attributes (what operation)
- Environment attributes (context: time, location, etc.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from arbiter.common.models import (
    Policy,
    PolicyRule,
    Condition,
    ConditionOperator,
    Effect,
)
from arbiter.common.errors import PolicyValidationError
from arbiter.common.utils import utc_now, generate_id, canonical_json


# =============================================================================
# Attribute Categories
# =============================================================================

class AttributeCategory(Enum):
    """Categories of attributes for ABAC evaluation."""
    SUBJECT = "subject"  # Attributes of the requester
    RESOURCE = "resource"  # Attributes of the resource
    ACTION = "action"  # Attributes of the action
    ENVIRONMENT = "environment"  # Contextual attributes


# =============================================================================
# Attribute Definitions
# =============================================================================

@dataclass
class AttributeDefinition:
    """Definition of an attribute for policy use.
    
    Attributes:
        attribute_id: Unique identifier (e.g., "subject.role")
        category: Attribute category
        data_type: Expected data type (string, int, list, etc.)
        required: Whether attribute must be present
        description: Human-readable description
    """
    attribute_id: str
    category: AttributeCategory
    data_type: str
    required: bool = False
    description: str = ""
    allowed_values: Optional[List[Any]] = None


# =============================================================================
# Standard Attributes
# =============================================================================

# Subject attributes (agent properties)
ATTR_SUBJECT_DID = AttributeDefinition(
    "subject.did", AttributeCategory.SUBJECT, "string", True,
    "DID of the requesting agent"
)
ATTR_SUBJECT_ROLE = AttributeDefinition(
    "subject.role", AttributeCategory.SUBJECT, "string", False,
    "Role of the agent"
)
ATTR_SUBJECT_CAPABILITIES = AttributeDefinition(
    "subject.capabilities", AttributeCategory.SUBJECT, "list", False,
    "Capabilities proven by credentials"
)
ATTR_SUBJECT_TRUST_SCORE = AttributeDefinition(
    "subject.trustScore", AttributeCategory.SUBJECT, "float", False,
    "Computed trust score"
)

# Resource attributes
ATTR_RESOURCE_ID = AttributeDefinition(
    "resource.id", AttributeCategory.RESOURCE, "string", True,
    "Unique resource identifier"
)
ATTR_RESOURCE_TYPE = AttributeDefinition(
    "resource.type", AttributeCategory.RESOURCE, "string", True,
    "Type of resource"
)
ATTR_RESOURCE_OWNER = AttributeDefinition(
    "resource.owner", AttributeCategory.RESOURCE, "string", False,
    "DID of resource owner"
)
ATTR_RESOURCE_SENSITIVITY = AttributeDefinition(
    "resource.sensitivity", AttributeCategory.RESOURCE, "string", False,
    "Sensitivity level (public, internal, confidential, restricted)"
)

# Action attributes
ATTR_ACTION_ID = AttributeDefinition(
    "action.id", AttributeCategory.ACTION, "string", True,
    "Action being performed"
)
ATTR_ACTION_TYPE = AttributeDefinition(
    "action.type", AttributeCategory.ACTION, "string", False,
    "Type of action (read, write, execute, delete)"
)

# Environment attributes
ATTR_ENV_TIME = AttributeDefinition(
    "environment.currentTime", AttributeCategory.ENVIRONMENT, "datetime", False,
    "Current timestamp"
)
ATTR_ENV_LOCATION = AttributeDefinition(
    "environment.location", AttributeCategory.ENVIRONMENT, "string", False,
    "Request origin location"
)
ATTR_ENV_NETWORK = AttributeDefinition(
    "environment.network", AttributeCategory.ENVIRONMENT, "string", False,
    "Network type (internal, external)"
)


# =============================================================================
# Policy Set
# =============================================================================

class CombiningAlgorithm(Enum):
    """Algorithms for combining multiple policy decisions."""
    DENY_OVERRIDES = "deny_overrides"  # Any DENY wins
    PERMIT_OVERRIDES = "permit_overrides"  # Any PERMIT wins
    FIRST_APPLICABLE = "first_applicable"  # First match wins
    ONLY_ONE_APPLICABLE = "only_one_applicable"  # Exactly one must match


@dataclass
class PolicySet:
    """Set of policies with combining algorithm.
    
    Policies are evaluated according to the combining algorithm
    to produce a final decision.
    
    Attributes:
        policy_set_id: Unique identifier
        policies: List of policies in evaluation order
        combining_algorithm: How to combine multiple decisions
        target: Optional pre-filter for applicability
        description: Human-readable description
    """
    policy_set_id: str
    policies: List[Policy]
    combining_algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES
    target: Optional[Dict[str, Any]] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize policy set."""
        return {
            "policySetId": self.policy_set_id,
            "combiningAlgorithm": self.combining_algorithm.value,
            "target": self.target,
            "policies": [p.to_dict() for p in self.policies],
            "description": self.description,
        }


# =============================================================================
# Policy Templates
# =============================================================================

class PolicyTemplate:
    """Factory for creating common policy patterns."""

    @staticmethod
    def allow_owner_full_access(
        resource_type: str,
        policy_id: Optional[str] = None,
    ) -> Policy:
        """Create policy allowing resource owner full access.
        
        Args:
            resource_type: Type of resource
            policy_id: Optional policy ID
            
        Returns:
            Policy granting owner full access
        """
        return Policy(
            policy_id=policy_id or f"owner-access-{generate_id(length=4)}",
            version="1.0",
            target={"resource.type": resource_type},
            rules=[
                PolicyRule(
                    rule_id="owner-permit",
                    effect=Effect.PERMIT,
                    conditions=[
                        # Subject DID matches resource owner
                        Condition(
                            attribute_category="subject",
                            attribute_id="did",
                            operator=ConditionOperator.EQUALS,
                            value="${resource.owner}",  # Reference to resource attr
                        ),
                    ],
                    description="Owner has full access to their resources",
                ),
            ],
        )

    @staticmethod
    def require_capability(
        capability: str,
        resource_type: str,
        action: str,
        policy_id: Optional[str] = None,
    ) -> Policy:
        """Create policy requiring specific capability.
        
        Args:
            capability: Required capability
            resource_type: Type of resource
            action: Action being performed
            policy_id: Optional policy ID
            
        Returns:
            Policy requiring the capability
        """
        return Policy(
            policy_id=policy_id or f"cap-{capability}-{generate_id(length=4)}",
            version="1.0",
            target={
                "resource.type": resource_type,
                "action.id": action,
            },
            rules=[
                PolicyRule(
                    rule_id="capability-check",
                    effect=Effect.PERMIT,
                    conditions=[
                        Condition(
                            attribute_category="subject",
                            attribute_id="capabilities",
                            operator=ConditionOperator.CONTAINS,
                            value=capability,
                        ),
                    ],
                    description=f"Requires {capability} capability",
                ),
            ],
        )

    @staticmethod
    def time_based_access(
        start_hour: int,
        end_hour: int,
        resource_type: str,
        policy_id: Optional[str] = None,
    ) -> Policy:
        """Create policy restricting access to time window.
        
        Args:
            start_hour: Start hour (0-23)
            end_hour: End hour (0-23)
            resource_type: Type of resource
            policy_id: Optional policy ID
            
        Returns:
            Policy with time restriction
        """
        return Policy(
            policy_id=policy_id or f"time-access-{generate_id(length=4)}",
            version="1.0",
            target={"resource.type": resource_type},
            rules=[
                PolicyRule(
                    rule_id="time-window-deny",
                    effect=Effect.DENY,
                    conditions=[
                        Condition(
                            attribute_category="environment",
                            attribute_id="currentHour",
                            operator=ConditionOperator.LESS_THAN,
                            value=start_hour,
                        ),
                    ],
                    description=f"Deny before {start_hour}:00",
                ),
                PolicyRule(
                    rule_id="time-window-deny-2",
                    effect=Effect.DENY,
                    conditions=[
                        Condition(
                            attribute_category="environment",
                            attribute_id="currentHour",
                            operator=ConditionOperator.GREATER_THAN_OR_EQUAL,
                            value=end_hour,
                        ),
                    ],
                    description=f"Deny after {end_hour}:00",
                ),
                PolicyRule(
                    rule_id="time-window-permit",
                    effect=Effect.PERMIT,
                    conditions=[],  # No additional conditions
                    description="Permit during allowed hours",
                ),
            ],
        )

    @staticmethod
    def sensitivity_based_access(
        allowed_sensitivities: List[str],
        policy_id: Optional[str] = None,
    ) -> Policy:
        """Create policy based on resource sensitivity.
        
        Args:
            allowed_sensitivities: List of allowed sensitivity levels
            policy_id: Optional policy ID
            
        Returns:
            Policy checking sensitivity
        """
        return Policy(
            policy_id=policy_id or f"sensitivity-{generate_id(length=4)}",
            version="1.0",
            rules=[
                PolicyRule(
                    rule_id="sensitivity-check",
                    effect=Effect.PERMIT,
                    conditions=[
                        Condition(
                            attribute_category="resource",
                            attribute_id="sensitivity",
                            operator=ConditionOperator.IN,
                            value=allowed_sensitivities,
                        ),
                    ],
                    description=f"Allow access to {allowed_sensitivities} resources",
                ),
                PolicyRule(
                    rule_id="sensitivity-deny",
                    effect=Effect.DENY,
                    conditions=[],  # Default deny
                    description="Deny access to other sensitivity levels",
                ),
            ],
        )


# =============================================================================
# Policy Validation
# =============================================================================

def validate_policy(policy: Policy) -> List[str]:
    """Validate a policy for correctness.
    
    Args:
        policy: Policy to validate
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors: List[str] = []

    # Check policy ID
    if not policy.policy_id:
        errors.append("Policy ID is required")

    # Check version
    if not policy.version:
        errors.append("Policy version is required")

    # Check rules
    if not policy.rules:
        errors.append("Policy must have at least one rule")

    for rule in policy.rules:
        # Check rule ID
        if not rule.rule_id:
            errors.append("Rule ID is required")

        # Check effect
        if rule.effect not in [Effect.PERMIT, Effect.DENY]:
            errors.append(f"Invalid effect in rule {rule.rule_id}: {rule.effect}")

        # Validate conditions
        for condition in rule.conditions:
            if not condition.attribute_category:
                errors.append(f"Condition in rule {rule.rule_id} missing category")
            if not condition.attribute_id:
                errors.append(f"Condition in rule {rule.rule_id} missing attribute_id")

    return errors


def validate_policy_strict(policy: Policy) -> None:
    """Validate policy and raise exception on errors.
    
    Args:
        policy: Policy to validate
        
    Raises:
        PolicyValidationError: If policy is invalid
    """
    errors = validate_policy(policy)
    if errors:
        raise PolicyValidationError(
            f"Policy validation failed: {'; '.join(errors)}",
            policy_id=policy.policy_id,
        )
