"""
Unit Tests for Policy Information Point (PIP)

The PIP retrieves and supplies attributes for policy evaluation.
This test module covers:

1. Attribute Resolution Order:
   - Custom resolvers take highest priority
   - Direct extraction from context (subject/resource/action/environment)
   - Registered attribute sources as fallback
   
2. Caching Behavior:
   - Attributes are cached after first retrieval for performance
   - Cache can be cleared for fresh evaluation
   - Same attribute accessed twice returns cached value
   
3. Custom Resolvers:
   - Register custom functions for specific attributes
   - Resolvers receive full AttributeContext
   - Return None if attribute not available
   
4. Attribute Sources:
   - CredentialAttributeSource: verified attributes from credentials
   - EnvironmentAttributeSource: static and dynamic environment attributes
   - Sources implement AttributeSource interface
   
5. Comprehensive Attribute Extraction:
   - Subject: DID, presentation values, DID document info
   - Resource: ID, metadata attributes
   - Action: ID and type
   - Environment: current time, hour, custom attributes
"""

import pytest
from datetime import datetime, timedelta

from arbiter.integrity.abac.pip import (
    PolicyInformationPoint,
    CredentialAttributeSource,
    EnvironmentAttributeSource,
    AttributeContext,
)
from arbiter.integrity.policy_models import AttributeCategory
from arbiter.common.models import (
    VerifiablePresentation,
    ZKProof,
    ProofType,
)
from arbiter.common.utils import utc_now


class TestAttributeResolutionOrder:
    """Test that attribute resolution follows correct priority order.
    
    Priority:
    1. Custom resolver (highest priority)
    2. Direct extraction from context
    3. Registered attribute sources
    """

    def test_custom_resolver_takes_precedence(self):
        """
        Custom resolvers should override context and source values.
        
        Scenario:
        - Register custom resolver for "subject.role"
        - Custom resolver returns "superadmin"
        - Context also has "subject.role" = "admin"
        - Expected: custom resolver value ("superadmin") is returned
        """
        pip = PolicyInformationPoint()

        def custom_role_resolver(context):
            return "superadmin"

        pip.register_resolver("subject.role", custom_role_resolver)

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
        )

        result = pip.get_attribute("subject", "role", ctx)
        assert result == "superadmin"

    def test_direct_extraction_without_custom_resolver(self):
        """
        Direct extraction from context should work when no custom resolver.
        
        Scenario:
        - No custom resolver registered
        - Subject DID in context is "did:arbiter:alice"
        - Expected: get_attribute returns the DID directly
        """
        pip = PolicyInformationPoint()

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
        )

        result = pip.get_attribute("subject", "did", ctx)
        assert result == "did:arbiter:alice"

    def test_fallback_to_registered_source(self):
        """
        Registered sources should be used as fallback when no custom resolver or direct extraction.
        
        Scenario:
        - No custom resolver for "subject.credentials"
        - Context has no direct "credentials" value
        - CredentialAttributeSource has verified attributes
        - Expected: value from source is returned
        """
        pip = PolicyInformationPoint()
        cred_source = CredentialAttributeSource()
        cred_source.register_verified_attributes(
            "did:arbiter:alice",
            {"credentials": ["cert-1", "cert-2"]},
        )
        pip.register_source(AttributeCategory.SUBJECT, cred_source)

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
        )

        result = pip.get_attribute("subject", "credentials", ctx)
        assert result == ["cert-1", "cert-2"]


class TestAttributeCaching:
    """Test caching behavior for performance optimization.
    
    Attributes should be cached after retrieval to avoid
    repeated computation/lookups.
    """

    def test_attribute_cached_after_first_retrieval(self):
        """
        Once an attribute is retrieved, it should be cached.
        
        Scenario:
        - Register a custom resolver that tracks call count
        - Call get_attribute twice for same attribute
        - Expected: resolver called only once, second call returns cached value
        """
        pip = PolicyInformationPoint()
        call_count = {"count": 0}

        def counting_resolver(context):
            call_count["count"] += 1
            return "value-1"

        pip.register_resolver("subject.expensive", counting_resolver)

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
        )

        # First call
        result1 = pip.get_attribute("subject", "expensive", ctx)
        assert result1 == "value-1"
        assert call_count["count"] == 1

        # Second call should return cached value without calling resolver
        result2 = pip.get_attribute("subject", "expensive", ctx)
        assert result2 == "value-1"
        assert call_count["count"] == 1  # Not incremented

    def test_cache_clear_resets_attributes(self):
        """
        clear_cache() should reset the cached attributes.
        
        Scenario:
        - Get an attribute (cached)
        - Clear cache
        - Get same attribute again
        - Expected: resolver called again (cache was reset)
        """
        pip = PolicyInformationPoint()
        call_count = {"count": 0}

        def counting_resolver(context):
            call_count["count"] += 1
            return f"value-{call_count['count']}"

        pip.register_resolver("subject.dynamic", counting_resolver)

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
        )

        # First retrieval
        result1 = pip.get_attribute("subject", "dynamic", ctx)
        assert result1 == "value-1"

        # Clear cache
        pip.clear_cache()

        # Second retrieval (should call resolver again)
        result2 = pip.get_attribute("subject", "dynamic", ctx)
        assert result2 == "value-2"
        assert call_count["count"] == 2


class TestCredentialAttributeSource:
    """Test CredentialAttributeSource for verified credential attributes.
    
    This source stores and retrieves attributes that have been
    verified via credentials (identity layer integration).
    """

    def test_register_and_retrieve_verified_attributes(self):
        """
        Verified attributes should be retrievable after registration.
        
        Scenario:
        - Register verified attributes for a subject DID
        - Query for those attributes via PIP
        - Expected: attributes are returned correctly
        """
        pip = PolicyInformationPoint()
        cred_source = CredentialAttributeSource()

        # Register verified attributes
        verified_attrs = {
            "role": "researcher",
            "level": 3,
            "clearance": "SECRET",
        }
        cred_source.register_verified_attributes("did:arbiter:bob", verified_attrs)
        pip.register_source(AttributeCategory.SUBJECT, cred_source)

        ctx = AttributeContext(
            subject_did="did:arbiter:bob",
            resource_id="res-1",
            action="read",
        )

        assert pip.get_attribute("subject", "role", ctx) == "researcher"
        assert pip.get_attribute("subject", "level", ctx) == 3
        assert pip.get_attribute("subject", "clearance", ctx) == "SECRET"

    def test_list_available_attributes(self):
        """
        CredentialAttributeSource should report available attributes.
        
        Scenario:
        - Register attributes for multiple subjects
        - Query available attributes
        - Expected: all unique attribute keys are returned
        """
        cred_source = CredentialAttributeSource()
        cred_source.register_verified_attributes("did:alice", {"role": "admin", "level": 5})
        cred_source.register_verified_attributes("did:bob", {"role": "user", "dept": "eng"})

        available = cred_source.get_available_attributes(AttributeCategory.SUBJECT)
        # Should have role, level, dept
        assert "role" in available
        assert "level" in available
        assert "dept" in available


class TestEnvironmentAttributeSource:
    """Test EnvironmentAttributeSource for dynamic environment attributes.
    
    This source provides:
    - Dynamic attributes: current time, hour, day
    - Static attributes: set manually and persist
    """

    def test_dynamic_current_time_attribute(self):
        """
        currentTime should return current timestamp.
        
        Scenario:
        - Create EnvironmentAttributeSource
        - Get currentTime attribute
        - Expected: returns datetime close to now (within 1 second)
        """
        env_source = EnvironmentAttributeSource()

        before = utc_now()
        result = env_source.get_attribute(
            AttributeCategory.ENVIRONMENT,
            "currentTime",
            {},
        )
        after = utc_now()

        assert isinstance(result, datetime)
        assert before <= result <= after

    def test_dynamic_current_hour_attribute(self):
        """
        currentHour should return hour of current timestamp.
        
        Scenario:
        - Get currentHour attribute
        - Expected: returns hour (0-23) matching current time
        """
        env_source = EnvironmentAttributeSource()

        result = env_source.get_attribute(
            AttributeCategory.ENVIRONMENT,
            "currentHour",
            {},
        )

        now_hour = utc_now().hour
        assert result == now_hour
        assert 0 <= result <= 23

    def test_static_attribute_setting(self):
        """
        Static attributes should be retrievable after setting.
        
        Scenario:
        - Set static attribute "network" = "internal"
        - Get static attribute
        - Expected: returns the set value
        """
        env_source = EnvironmentAttributeSource()
        env_source.set_static_attribute("network", "internal")

        result = env_source.get_attribute(
            AttributeCategory.ENVIRONMENT,
            "network",
            {},
        )

        assert result == "internal"

    def test_list_available_environment_attributes(self):
        """
        Should report dynamic and static environment attributes.
        
        Scenario:
        - Set static attribute "location"
        - Query available attributes
        - Expected: includes "currentTime", "currentHour", "currentDay", "location"
        """
        env_source = EnvironmentAttributeSource()
        env_source.set_static_attribute("location", "us-west")

        available = env_source.get_available_attributes(AttributeCategory.ENVIRONMENT)
        assert "currentTime" in available
        assert "currentHour" in available
        assert "currentDay" in available
        assert "location" in available


class TestGetAllAttributes:
    """Test comprehensive attribute extraction via get_all_attributes().
    
    This method returns all available attributes organized by category.
    """

    def test_extract_subject_attributes(self):
        """
        Should extract subject DID and presentation values.
        
        Scenario:
        - Create context with subject DID
        - Create ZK proof with disclosed values
        - Call get_all_attributes
        - Expected: subject dict contains DID and proof values
        """
        pip = PolicyInformationPoint()

        proof = ZKProof(
            proof_type=ProofType.CREDENTIAL_VALIDITY,
            challenge=b"test-challenge",
            proof_data=b"proof-data",
            disclosed_values={"role": "admin", "level": 3},
        )

        presentation = VerifiablePresentation(
            holder="did:arbiter:alice",
            challenge=b"challenge",
            domain="example.com",
            zkp_proofs=[proof],
        )

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
            subject_presentation=presentation,
        )

        all_attrs = pip.get_all_attributes(ctx)

        assert all_attrs["subject"]["did"] == "did:arbiter:alice"
        assert all_attrs["subject"]["role"] == "admin"
        assert all_attrs["subject"]["level"] == 3

    def test_extract_resource_attributes(self):
        """
        Should extract resource ID and metadata.
        
        Scenario:
        - Create context with resource metadata
        - Call get_all_attributes
        - Expected: resource dict contains ID and metadata
        """
        pip = PolicyInformationPoint()

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="doc-123",
            action="read",
            resource_metadata={
                "type": "document",
                "sensitivity": "confidential",
                "owner": "did:arbiter:bob",
            },
        )

        all_attrs = pip.get_all_attributes(ctx)

        assert all_attrs["resource"]["id"] == "doc-123"
        assert all_attrs["resource"]["type"] == "document"
        assert all_attrs["resource"]["sensitivity"] == "confidential"

    def test_extract_action_attributes(self):
        """
        Should extract action ID.
        
        Scenario:
        - Create context with action
        - Call get_all_attributes
        - Expected: action dict contains ID
        """
        pip = PolicyInformationPoint()

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="write",
        )

        all_attrs = pip.get_all_attributes(ctx)

        assert all_attrs["action"]["id"] == "write"

    def test_extract_environment_attributes(self):
        """
        Should extract environment attributes (time, hour, custom).
        
        Scenario:
        - Create context with environment data
        - Call get_all_attributes
        - Expected: environment dict contains time, hour, and custom attrs
        """
        pip = PolicyInformationPoint()

        test_time = utc_now()
        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
            timestamp=test_time,
            environment={"location": "us-west", "ipAddress": "192.168.1.1"},
        )

        all_attrs = pip.get_all_attributes(ctx)

        assert all_attrs["environment"]["currentTime"] == test_time
        assert all_attrs["environment"]["currentHour"] == test_time.hour
        assert all_attrs["environment"]["location"] == "us-west"
        assert all_attrs["environment"]["ipAddress"] == "192.168.1.1"


class TestAttributeExtractionFallthrough:
    """Test attribute extraction from different context sources.
    
    Attributes can come from:
    - Direct context fields (subject_did, action, etc.)
    - Resource metadata dictionary
    - Environment attributes dictionary
    - Verifiable presentations (ZK proofs)
    """

    def test_missing_attribute_returns_none(self):
        """
        Non-existent attributes should return None.
        
        Scenario:
        - Query for attribute that doesn't exist anywhere
        - Expected: returns None
        """
        pip = PolicyInformationPoint()

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
        )

        result = pip.get_attribute("subject", "nonexistent", ctx)
        assert result is None

    def test_extraction_from_resource_metadata(self):
        """
        Resource attributes should be extracted from metadata dict.
        
        Scenario:
        - Set resource_metadata with various attributes
        - Query for each attribute
        - Expected: all are returned correctly
        """
        pip = PolicyInformationPoint()

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
            resource_metadata={
                "classification": "public",
                "department": "engineering",
                "createdAt": "2026-02-07",
            },
        )

        assert pip.get_attribute("resource", "classification", ctx) == "public"
        assert pip.get_attribute("resource", "department", ctx) == "engineering"
        assert pip.get_attribute("resource", "createdAt", ctx) == "2026-02-07"

    def test_extraction_from_environment_dict(self):
        """
        Environment attributes should be extracted from environment dict.
        
        Scenario:
        - Set environment attributes
        - Query for each
        - Expected: all are returned correctly
        """
        pip = PolicyInformationPoint()

        ctx = AttributeContext(
            subject_did="did:arbiter:alice",
            resource_id="res-1",
            action="read",
            environment={
                "requestSource": "api",
                "tlsVersion": "1.3",
                "isVPN": True,
            },
        )

        assert pip.get_attribute("environment", "requestSource", ctx) == "api"
        assert pip.get_attribute("environment", "tlsVersion", ctx) == "1.3"
        assert pip.get_attribute("environment", "isVPN", ctx) is True
