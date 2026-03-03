"""
Arbiter - Policy Administration Point (PAP)

The PAP manages policy lifecycle: creation, storage, update, deletion.

Reference: NIST SP 800-162 - ABAC Architecture

The PAP:
- Stores and manages policies
- Provides version control
- Validates policy syntax
- Supports policy import/export
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from arbiter.common.models import Policy, PolicyRule, Condition, Effect
from arbiter.common.errors import (
    PolicyError,
    PolicyNotFoundError,
    PolicyValidationError,
)
from arbiter.common.utils import utc_now, generate_id
from arbiter.integrity.policy_models import (
    PolicySet,
    CombiningAlgorithm,
    validate_policy,
    validate_policy_strict,
)


# =============================================================================
# Policy Metadata
# =============================================================================

@dataclass
class PolicyMetadata:
    """Metadata about a stored policy.
    
    Attributes:
        policy_id: Unique policy identifier
        version: Current version
        created_at: Creation timestamp
        updated_at: Last update timestamp
        created_by: DID of creator
        active: Whether policy is active
        tags: Optional tags for categorization
    """
    policy_id: str
    version: str
    created_at: datetime
    updated_at: datetime
    created_by: str = ""
    active: bool = True
    tags: Set[str] = field(default_factory=set)


# =============================================================================
# Policy Repository
# =============================================================================

class PolicyRepository:
    """Repository for policy storage and retrieval."""

    def __init__(self) -> None:
        """Initialize empty repository."""
        self._policies: Dict[str, Policy] = {}
        self._metadata: Dict[str, PolicyMetadata] = {}
        self._version_history: Dict[str, List[Policy]] = {}

    def store(
        self,
        policy: Policy,
        created_by: str = "",
        tags: Optional[Set[str]] = None,
    ) -> PolicyMetadata:
        """Store a policy.
        
        Args:
            policy: Policy to store
            created_by: DID of creator
            tags: Optional tags
            
        Returns:
            Policy metadata
            
        Raises:
            PolicyValidationError: If policy is invalid
        """
        # Validate
        validate_policy_strict(policy)
        
        now = utc_now()
        
        # Check if updating existing
        if policy.policy_id in self._policies:
            # Add to version history
            old_policy = self._policies[policy.policy_id]
            if policy.policy_id not in self._version_history:
                self._version_history[policy.policy_id] = []
            self._version_history[policy.policy_id].append(old_policy)
            
            # Update metadata
            metadata = self._metadata[policy.policy_id]
            metadata.version = policy.version
            metadata.updated_at = now
        else:
            # New policy
            metadata = PolicyMetadata(
                policy_id=policy.policy_id,
                version=policy.version,
                created_at=now,
                updated_at=now,
                created_by=created_by,
                tags=tags or set(),
            )
            self._metadata[policy.policy_id] = metadata
        
        self._policies[policy.policy_id] = policy
        policy.updated = now
        
        return metadata

    def get(self, policy_id: str) -> Policy:
        """Get a policy by ID.
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            The policy
            
        Raises:
            PolicyNotFoundError: If policy not found
        """
        if policy_id not in self._policies:
            raise PolicyNotFoundError(policy_id)
        return self._policies[policy_id]

    def get_metadata(self, policy_id: str) -> PolicyMetadata:
        """Get policy metadata.
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            Policy metadata
        """
        if policy_id not in self._metadata:
            raise PolicyNotFoundError(policy_id)
        return self._metadata[policy_id]

    def delete(self, policy_id: str) -> None:
        """Delete a policy.
        
        Args:
            policy_id: Policy identifier
        """
        if policy_id in self._policies:
            del self._policies[policy_id]
        if policy_id in self._metadata:
            del self._metadata[policy_id]
        if policy_id in self._version_history:
            del self._version_history[policy_id]

    def list_all(self, active_only: bool = True) -> List[PolicyMetadata]:
        """List all policies.
        
        Args:
            active_only: Only return active policies
            
        Returns:
            List of policy metadata
        """
        if active_only:
            return [m for m in self._metadata.values() if m.active]
        return list(self._metadata.values())

    def find_by_tags(self, tags: Set[str]) -> List[Policy]:
        """Find policies by tags.
        
        Args:
            tags: Tags to match (any match)
            
        Returns:
            Matching policies
        """
        matching = []
        for policy_id, metadata in self._metadata.items():
            if tags & metadata.tags:  # Intersection
                matching.append(self._policies[policy_id])
        return matching

    def get_version_history(self, policy_id: str) -> List[Policy]:
        """Get version history for a policy.
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            List of previous versions
        """
        return self._version_history.get(policy_id, [])

    def deactivate(self, policy_id: str) -> None:
        """Deactivate a policy (soft delete).
        
        Args:
            policy_id: Policy identifier
        """
        if policy_id in self._metadata:
            self._metadata[policy_id].active = False

    def activate(self, policy_id: str) -> None:
        """Activate a policy.
        
        Args:
            policy_id: Policy identifier
        """
        if policy_id in self._metadata:
            self._metadata[policy_id].active = True


# =============================================================================
# Policy Administration Point
# =============================================================================

class PolicyAdministrationPoint:
    """Manages policy lifecycle and provides policy authoring capabilities.
    
    The PAP is responsible for:
    - Policy CRUD operations
    - Policy validation
    - Version management
    - Policy set management
    """

    def __init__(
        self,
        repository: Optional[PolicyRepository] = None,
    ) -> None:
        """Initialize the PAP.
        
        Args:
            repository: Policy repository (created if not provided)
        """
        self.repository = repository or PolicyRepository()
        self._policy_sets: Dict[str, PolicySet] = {}

    def create_policy(
        self,
        policy_id: Optional[str] = None,
        version: str = "1.0",
        rules: Optional[List[PolicyRule]] = None,
        target: Optional[Dict[str, Any]] = None,
        created_by: str = "",
        tags: Optional[Set[str]] = None,
    ) -> Policy:
        """Create and store a new policy.
        
        Args:
            policy_id: Optional ID (generated if not provided)
            version: Policy version
            rules: Policy rules
            target: Policy target (pre-filter)
            created_by: Creator DID
            tags: Policy tags
            
        Returns:
            Created policy
        """
        if policy_id is None:
            policy_id = f"policy-{generate_id(length=8)}"
        
        policy = Policy(
            policy_id=policy_id,
            version=version,
            rules=rules or [],
            target=target,
            created=utc_now(),
        )
        
        self.repository.store(policy, created_by, tags)
        
        return policy

    def update_policy(
        self,
        policy_id: str,
        rules: Optional[List[PolicyRule]] = None,
        target: Optional[Dict[str, Any]] = None,
        version: Optional[str] = None,
    ) -> Policy:
        """Update an existing policy.
        
        Args:
            policy_id: Policy to update
            rules: New rules (or keep existing)
            target: New target (or keep existing)
            version: New version (auto-incremented if not provided)
            
        Returns:
            Updated policy
        """
        existing = self.repository.get(policy_id)
        
        # Auto-increment version if not provided
        if version is None:
            parts = existing.version.split(".")
            if len(parts) >= 2:
                major, minor = int(parts[0]), int(parts[1])
                version = f"{major}.{minor + 1}"
            else:
                version = f"{existing.version}.1"
        
        updated = Policy(
            policy_id=policy_id,
            version=version,
            rules=rules if rules is not None else existing.rules,
            target=target if target is not None else existing.target,
            created=existing.created,
        )
        
        self.repository.store(updated)
        
        return updated

    def delete_policy(self, policy_id: str, hard_delete: bool = False) -> None:
        """Delete a policy.
        
        Args:
            policy_id: Policy to delete
            hard_delete: If True, permanently delete; else deactivate
        """
        if hard_delete:
            self.repository.delete(policy_id)
        else:
            self.repository.deactivate(policy_id)

    def get_policy(self, policy_id: str) -> Policy:
        """Get a policy by ID.
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            The policy
        """
        return self.repository.get(policy_id)

    def list_policies(
        self,
        active_only: bool = True,
        tags: Optional[Set[str]] = None,
    ) -> List[Policy]:
        """List policies with optional filtering.
        
        Args:
            active_only: Only active policies
            tags: Filter by tags
            
        Returns:
            List of matching policies
        """
        if tags:
            return self.repository.find_by_tags(tags)
        
        metadata_list = self.repository.list_all(active_only)
        return [self.repository.get(m.policy_id) for m in metadata_list]

    def create_policy_set(
        self,
        policy_set_id: Optional[str] = None,
        policy_ids: Optional[List[str]] = None,
        combining_algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES,
        target: Optional[Dict[str, Any]] = None,
        description: str = "",
    ) -> PolicySet:
        """Create a policy set from existing policies.
        
        Args:
            policy_set_id: Optional ID
            policy_ids: IDs of policies to include
            combining_algorithm: How to combine decisions
            target: Policy set target
            description: Human-readable description
            
        Returns:
            Created policy set
        """
        if policy_set_id is None:
            policy_set_id = f"policy-set-{generate_id(length=8)}"
        
        policies = []
        for pid in (policy_ids or []):
            policies.append(self.repository.get(pid))
        
        policy_set = PolicySet(
            policy_set_id=policy_set_id,
            policies=policies,
            combining_algorithm=combining_algorithm,
            target=target,
            description=description,
        )
        
        self._policy_sets[policy_set_id] = policy_set
        
        return policy_set

    def get_policy_set(self, policy_set_id: str) -> PolicySet:
        """Get a policy set by ID.
        
        Args:
            policy_set_id: Policy set identifier
            
        Returns:
            The policy set
            
        Raises:
            PolicyNotFoundError: If not found
        """
        if policy_set_id not in self._policy_sets:
            raise PolicyNotFoundError(policy_set_id)
        return self._policy_sets[policy_set_id]

    def validate_policy(self, policy: Policy) -> List[str]:
        """Validate a policy without storing.
        
        Args:
            policy: Policy to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        return validate_policy(policy)

    def add_rule_to_policy(
        self,
        policy_id: str,
        rule: PolicyRule,
    ) -> Policy:
        """Add a rule to an existing policy.
        
        Args:
            policy_id: Policy to modify
            rule: Rule to add
            
        Returns:
            Updated policy
        """
        existing = self.repository.get(policy_id)
        new_rules = existing.rules + [rule]
        return self.update_policy(policy_id, rules=new_rules)

    def remove_rule_from_policy(
        self,
        policy_id: str,
        rule_id: str,
    ) -> Policy:
        """Remove a rule from a policy.
        
        Args:
            policy_id: Policy to modify
            rule_id: Rule to remove
            
        Returns:
            Updated policy
        """
        existing = self.repository.get(policy_id)
        new_rules = [r for r in existing.rules if r.rule_id != rule_id]
        return self.update_policy(policy_id, rules=new_rules)

    def export_policy(self, policy_id: str) -> Dict[str, Any]:
        """Export a policy to dictionary format.
        
        Args:
            policy_id: Policy to export
            
        Returns:
            Policy as dictionary
        """
        policy = self.repository.get(policy_id)
        return policy.to_dict()

    def import_policy(
        self,
        policy_dict: Dict[str, Any],
        created_by: str = "",
    ) -> Policy:
        """Import a policy from dictionary format.
        
        Args:
            policy_dict: Policy dictionary
            created_by: Importer DID
            
        Returns:
            Imported policy
        """
        # Parse rules
        rules = []
        for rule_dict in policy_dict.get("rules", []):
            conditions = []
            for cond_dict in rule_dict.get("conditions", []):
                from arbiter.common.models import ConditionOperator
                conditions.append(Condition(
                    attribute_category=cond_dict["category"],
                    attribute_id=cond_dict["attributeId"],
                    operator=ConditionOperator(cond_dict["operator"]),
                    value=cond_dict["value"],
                ))
            
            rules.append(PolicyRule(
                rule_id=rule_dict["ruleId"],
                effect=Effect(rule_dict["effect"]),
                conditions=conditions,
                description=rule_dict.get("description", ""),
            ))
        
        policy = Policy(
            policy_id=policy_dict["policyId"],
            version=policy_dict.get("version", "1.0"),
            rules=rules,
            target=policy_dict.get("target"),
        )
        
        self.repository.store(policy, created_by)
        
        return policy
