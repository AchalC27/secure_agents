"""
Arbiter - Policy Information Point (PIP)

The PIP retrieves and supplies attributes for policy evaluation.

Reference: NIST SP 800-162 - ABAC Architecture

The PIP:
- Fetches subject attributes (from credentials, DID documents)
- Fetches resource attributes (from resource metadata)
- Fetches environment attributes (time, location, etc.)
- Validates attributes via identity layer

Integration with Identity Layer:
- Verifies ZK proofs to extract proven attributes
- Validates credentials for attribute claims
- Resolves DIDs for subject information
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

from arbiter.common.models import (
    VerifiablePresentation,
    VerifiableCredential,
    DIDDocument,
    ZKProof,
    ProofType,
)
from arbiter.common.errors import ArbiterError
from arbiter.common.utils import utc_now
from arbiter.integrity.policy_models import AttributeCategory


# =============================================================================
# Attribute Source
# =============================================================================

class AttributeSource(ABC):
    """Abstract source for attribute retrieval."""

    @abstractmethod
    def get_attribute(
        self,
        category: AttributeCategory,
        attribute_id: str,
        context: Dict[str, Any],
    ) -> Optional[Any]:
        """Retrieve an attribute value.
        
        Args:
            category: Attribute category
            attribute_id: Specific attribute ID
            context: Request context
            
        Returns:
            Attribute value or None if not found
        """
        pass

    @abstractmethod
    def get_available_attributes(
        self,
        category: AttributeCategory,
    ) -> List[str]:
        """List available attributes for a category.
        
        Args:
            category: Attribute category
            
        Returns:
            List of attribute IDs
        """
        pass


# =============================================================================
# Attribute Context
# =============================================================================

@dataclass
class AttributeContext:
    """Context for attribute retrieval.
    
    Contains all information available for attribute extraction.
    
    Attributes:
        subject_did: DID of the requesting agent
        subject_presentation: Optional ZK presentation
        subject_did_document: Optional resolved DID document
        resource_id: Resource being accessed
        resource_metadata: Resource attributes
        action: Action being performed
        environment: Environment attributes
        timestamp: Request timestamp
    """
    subject_did: str
    resource_id: str
    action: str
    subject_presentation: Optional[VerifiablePresentation] = None
    subject_did_document: Optional[DIDDocument] = None
    resource_metadata: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utc_now)


# =============================================================================
# Policy Information Point
# =============================================================================

class PolicyInformationPoint:
    """Retrieves and supplies attributes for policy evaluation.
    
    The PIP is the central attribute repository that:
    1. Extracts attributes from ZK presentations
    2. Fetches resource metadata
    3. Provides environment attributes
    4. Caches attributes for performance
    """

    def __init__(self) -> None:
        """Initialize the PIP."""
        self._attribute_sources: Dict[AttributeCategory, List[AttributeSource]] = {
            AttributeCategory.SUBJECT: [],
            AttributeCategory.RESOURCE: [],
            AttributeCategory.ACTION: [],
            AttributeCategory.ENVIRONMENT: [],
        }
        self._attribute_cache: Dict[str, Any] = {}
        self._custom_resolvers: Dict[str, Callable[[AttributeContext], Any]] = {}

    def register_source(
        self,
        category: AttributeCategory,
        source: AttributeSource,
    ) -> None:
        """Register an attribute source.
        
        Args:
            category: Category this source provides
            source: The attribute source
        """
        self._attribute_sources[category].append(source)

    def register_resolver(
        self,
        attribute_path: str,
        resolver: Callable[[AttributeContext], Any],
    ) -> None:
        """Register a custom attribute resolver.
        
        Args:
            attribute_path: Full attribute path (e.g., "subject.role")
            resolver: Function to resolve the attribute
        """
        self._custom_resolvers[attribute_path] = resolver

    def get_attribute(
        self,
        category: str,
        attribute_id: str,
        context: AttributeContext,
    ) -> Optional[Any]:
        """Get an attribute value.
        
        Resolution order:
        1. Custom resolver
        2. Direct extraction from context
        3. Registered sources
        
        Args:
            category: Attribute category
            attribute_id: Specific attribute
            context: Attribute context
            
        Returns:
            Attribute value or None
        """
        # Build cache key
        cache_key = f"{category}.{attribute_id}"
        
        # Check cache
        if cache_key in self._attribute_cache:
            return self._attribute_cache[cache_key]
        
        # Try custom resolver
        if cache_key in self._custom_resolvers:
            value = self._custom_resolvers[cache_key](context)
            self._attribute_cache[cache_key] = value
            return value
        
        # Try direct extraction
        value = self._extract_from_context(category, attribute_id, context)
        if value is not None:
            self._attribute_cache[cache_key] = value
            return value
        
        # Try registered sources
        try:
            cat_enum = AttributeCategory(category)
        except ValueError:
            return None
        
        for source in self._attribute_sources.get(cat_enum, []):
            value = source.get_attribute(
                cat_enum,
                attribute_id,
                context.__dict__,
            )
            if value is not None:
                self._attribute_cache[cache_key] = value
                return value
        
        return None

    def get_all_attributes(
        self,
        context: AttributeContext,
    ) -> Dict[str, Dict[str, Any]]:
        """Get all available attributes for a context.
        
        Args:
            context: Attribute context
            
        Returns:
            Dict of category -> {attribute_id: value}
        """
        all_attrs: Dict[str, Dict[str, Any]] = {
            "subject": {},
            "resource": {},
            "action": {},
            "environment": {},
        }
        
        # Subject attributes
        all_attrs["subject"]["did"] = context.subject_did
        if context.subject_presentation:
            for proof in context.subject_presentation.zkp_proofs:
                all_attrs["subject"].update(proof.disclosed_values)
        
        if context.subject_did_document:
            # Extract from DID document
            all_attrs["subject"]["publicKeyCount"] = len(
                context.subject_did_document.verification_method
            )
        
        # Resource attributes
        all_attrs["resource"]["id"] = context.resource_id
        all_attrs["resource"].update(context.resource_metadata)
        
        # Action attributes
        all_attrs["action"]["id"] = context.action
        
        # Environment attributes
        all_attrs["environment"]["currentTime"] = context.timestamp
        all_attrs["environment"]["currentHour"] = context.timestamp.hour
        all_attrs["environment"].update(context.environment)
        
        return all_attrs

    def clear_cache(self) -> None:
        """Clear the attribute cache."""
        self._attribute_cache.clear()

    def _extract_from_context(
        self,
        category: str,
        attribute_id: str,
        context: AttributeContext,
    ) -> Optional[Any]:
        """Extract attribute directly from context.
        
        Args:
            category: Attribute category
            attribute_id: Specific attribute
            context: Attribute context
            
        Returns:
            Attribute value or None
        """
        if category == "subject":
            return self._extract_subject_attribute(attribute_id, context)
        elif category == "resource":
            return self._extract_resource_attribute(attribute_id, context)
        elif category == "action":
            return self._extract_action_attribute(attribute_id, context)
        elif category == "environment":
            return self._extract_environment_attribute(attribute_id, context)
        
        return None

    def _extract_subject_attribute(
        self,
        attribute_id: str,
        context: AttributeContext,
    ) -> Optional[Any]:
        """Extract subject attribute."""
        if attribute_id == "did":
            return context.subject_did
        
        # Try to get from presentation
        if context.subject_presentation:
            for proof in context.subject_presentation.zkp_proofs:
                if attribute_id in proof.disclosed_values:
                    return proof.disclosed_values[attribute_id]
        
        return None

    def _extract_resource_attribute(
        self,
        attribute_id: str,
        context: AttributeContext,
    ) -> Optional[Any]:
        """Extract resource attribute."""
        if attribute_id == "id":
            return context.resource_id
        
        return context.resource_metadata.get(attribute_id)

    def _extract_action_attribute(
        self,
        attribute_id: str,
        context: AttributeContext,
    ) -> Optional[Any]:
        """Extract action attribute."""
        if attribute_id == "id":
            return context.action
        
        return None

    def _extract_environment_attribute(
        self,
        attribute_id: str,
        context: AttributeContext,
    ) -> Optional[Any]:
        """Extract environment attribute."""
        if attribute_id == "currentTime":
            return context.timestamp
        if attribute_id == "currentHour":
            return context.timestamp.hour
        
        return context.environment.get(attribute_id)


# =============================================================================
# Credential-Based Attribute Source
# =============================================================================

class CredentialAttributeSource(AttributeSource):
    """Attribute source backed by verified credentials."""

    def __init__(self) -> None:
        """Initialize source."""
        self._verified_attributes: Dict[str, Dict[str, Any]] = {}

    def register_verified_attributes(
        self,
        subject_did: str,
        attributes: Dict[str, Any],
    ) -> None:
        """Register verified attributes for a subject.
        
        Args:
            subject_did: DID of the subject
            attributes: Verified attribute values
        """
        if subject_did not in self._verified_attributes:
            self._verified_attributes[subject_did] = {}
        self._verified_attributes[subject_did].update(attributes)

    def get_attribute(
        self,
        category: AttributeCategory,
        attribute_id: str,
        context: Dict[str, Any],
    ) -> Optional[Any]:
        """Get attribute from verified credentials."""
        if category != AttributeCategory.SUBJECT:
            return None
        
        subject_did = context.get("subject_did")
        if not subject_did:
            return None
        
        subject_attrs = self._verified_attributes.get(subject_did, {})
        return subject_attrs.get(attribute_id)

    def get_available_attributes(
        self,
        category: AttributeCategory,
    ) -> List[str]:
        """List available attributes."""
        if category != AttributeCategory.SUBJECT:
            return []
        
        # Collect all unique attribute keys
        all_keys: Set[str] = set()
        for attrs in self._verified_attributes.values():
            all_keys.update(attrs.keys())
        
        return list(all_keys)


# =============================================================================
# Environment Attribute Source
# =============================================================================

class EnvironmentAttributeSource(AttributeSource):
    """Attribute source for environment attributes."""

    def __init__(self) -> None:
        """Initialize source."""
        self._static_attributes: Dict[str, Any] = {}

    def set_static_attribute(
        self,
        attribute_id: str,
        value: Any,
    ) -> None:
        """Set a static environment attribute.
        
        Args:
            attribute_id: Attribute ID
            value: Attribute value
        """
        self._static_attributes[attribute_id] = value

    def get_attribute(
        self,
        category: AttributeCategory,
        attribute_id: str,
        context: Dict[str, Any],
    ) -> Optional[Any]:
        """Get environment attribute."""
        if category != AttributeCategory.ENVIRONMENT:
            return None
        
        # Dynamic attributes
        if attribute_id == "currentTime":
            return utc_now()
        if attribute_id == "currentHour":
            return utc_now().hour
        if attribute_id == "currentDay":
            return utc_now().weekday()
        
        # Static attributes
        return self._static_attributes.get(attribute_id)

    def get_available_attributes(
        self,
        category: AttributeCategory,
    ) -> List[str]:
        """List available attributes."""
        if category != AttributeCategory.ENVIRONMENT:
            return []
        
        return [
            "currentTime",
            "currentHour",
            "currentDay",
            *self._static_attributes.keys(),
        ]
