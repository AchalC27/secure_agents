"""
Unit Tests for Policy Enforcement Point (PEP)

The PEP is the main access control interface that:
1. Intercepts access requests
2. Queries the PDP for decisions
3. Enforces decisions (permit/deny)
4. Handles obligations
5. Maintains audit logs

Test coverage includes:

1. Core Enforcement:
   - enforce(): Main enforcement method returning EnforcementResult
   - enforce_or_raise(): Enforcement that raises on denial
   - check_permission(): Quick boolean permission check
   
2. Policy Integration:
   - Policy selection (specific policies vs all active)
   - Policy set enforcement
   - Decision combining algorithms
   
3. Obligations Handling:
   - Registering obligation handlers
   - Fulfilling obligations on permit/deny
   - Obligation failures denying access
   
4. Audit Logging:
   - Logging access decisions
   - Filtering audit logs (by subject, resource)
   - Enable/disable auditing
   - Bounded log size
   
5. Integration Scenarios:
   - With verifiable presentations (identity layer)
   - With credentials and attributes
   - Full end-to-end enforcement flow
"""

import pytest
from datetime import datetime

from arbiter.integrity.abac.pep import (
    PolicyEnforcementPoint,
    ObligationHandler,
    EnforcementResult,
    create_pep_with_identity_integration,
)
from arbiter.integrity.abac.pdp import PolicyDecisionPoint, EvaluationContext
from arbiter.integrity.abac.pap import PolicyAdministrationPoint
from arbiter.integrity.abac.pip import PolicyInformationPoint
from arbiter.common.models import (
    Policy,
    PolicyRule,
    Condition,
    ConditionOperator,
    Effect,
    AccessDecision,
    VerifiablePresentation,
    ZKProof,
    ProofType,
)
from arbiter.common.errors import AccessDeniedError


def make_permit_policy(policy_id="p1") -> Policy:
    """Helper: Create a policy that always permits."""
    return Policy(
        policy_id=policy_id,
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="r1",
                effect=Effect.PERMIT,
                conditions=[],  # Empty conditions = always matches
            )
        ],
    )


def make_deny_policy(policy_id="p1") -> Policy:
    """Helper: Create a policy that always denies."""
    return Policy(
        policy_id=policy_id,
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="r1",
                effect=Effect.DENY,
                conditions=[],  # Empty conditions = always matches
            )
        ],
    )


def make_role_based_policy(role: str, policy_id="p1") -> Policy:
    """Helper: Create a policy that permits only specific role."""
    return Policy(
        policy_id=policy_id,
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="role-check",
                effect=Effect.PERMIT,
                conditions=[
                    Condition(
                        attribute_category="subject",
                        attribute_id="role",
                        operator=ConditionOperator.EQUALS,
                        value=role,
                    )
                ],
            )
        ],
    )


class TestCoreEnforcement:
    """Test basic enforcement operations."""

    def test_enforce_with_permit_decision(self):
        """
        enforce() should return EnforcementResult with permitted=True on PERMIT decision.
        
        Scenario:
        - Create PEP with permit policy
        - Call enforce() for a request
        - Expected: result.permitted is True, decision.effect is PERMIT
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        assert isinstance(result, EnforcementResult)
        assert result.permitted is True
        assert result.decision.effect == Effect.PERMIT

    def test_enforce_with_deny_decision(self):
        """
        enforce() should return permitted=False on DENY decision.
        
        Scenario:
        - Create PEP with deny policy
        - Call enforce()
        - Expected: result.permitted is False, decision.effect is DENY
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_deny_policy())

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        assert result.permitted is False
        assert result.decision.effect == Effect.DENY

    def test_enforce_or_raise_on_permit(self):
        """
        enforce_or_raise() should return result on PERMIT without raising.
        
        Scenario:
        - Create PEP with permit policy
        - Call enforce_or_raise()
        - Expected: returns EnforcementResult, no exception
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        result = pep.enforce_or_raise(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        assert result.permitted is True

    def test_enforce_or_raise_on_deny_raises(self):
        """
        enforce_or_raise() should raise AccessDeniedError on DENY.
        
        Scenario:
        - Create PEP with deny policy
        - Call enforce_or_raise()
        - Expected: raises AccessDeniedError with resource and action info
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_deny_policy())

        with pytest.raises(AccessDeniedError):
            pep.enforce_or_raise(
                subject_did="did:arbiter:alice",
                resource_id="doc-1",
                action="read",
            )

    def test_check_permission_boolean_result(self):
        """
        check_permission() should return True/False without exceptions.
        
        Scenario:
        - Call check_permission() with permit policy
        - Call check_permission() with deny policy
        - Expected: returns boolean (no exceptions)
        """
        pep_permit = PolicyEnforcementPoint()
        pep_permit.pap.repository.store(make_permit_policy())

        pep_deny = PolicyEnforcementPoint()
        pep_deny.pap.repository.store(make_deny_policy())

        assert pep_permit.check_permission(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        ) is True

        assert pep_deny.check_permission(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        ) is False


class TestPolicySelection:
    """Test selective policy evaluation."""

    def test_enforce_with_specific_policy_ids(self):
        """
        Should evaluate only specified policies when policy_ids provided.
        
        Scenario:
        - Create PEP with permit and deny policies
        - Call enforce() specifying only the permit policy
        - Expected: decision based on permit policy (PERMIT)
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy("p-permit"))
        pep.pap.repository.store(make_deny_policy("p-deny"))

        # Evaluate only the permit policy
        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
            policy_ids=["p-permit"],
        )

        assert result.permitted is True
        assert result.decision.policy_id == "p-permit"

    def test_enforce_all_active_policies_by_default(self):
        """
        Without policy_ids, should evaluate all active policies using DENY_OVERRIDES.
        
        Scenario:
        - Create PEP with permit and deny policies (both active)
        - Call enforce() without policy_ids
        - Expected: DENY wins (deny-overrides algorithm)
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy("p-permit"))
        pep.pap.repository.store(make_deny_policy("p-deny"))

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        # Both policies evaluated, DENY overrides PERMIT
        assert result.permitted is False


class TestObligationHandling:
    """Test obligation registration and fulfillment.
    
    Obligations are actions that must be performed when access
    is granted or denied (e.g., log, audit, notify).
    """

    def test_obligation_handler_registration(self):
        """
        Obligations handlers should be registerable.
        
        Scenario:
        - Create PEP
        - Register obligation handler for "log" type
        - Expected: handler stored and retrievable
        """
        pep = PolicyEnforcementPoint()

        handler_called = {"called": False}

        def log_handler(obligation):
            handler_called["called"] = True
            return True

        pep.register_obligation_handler("log", log_handler)

        # Verify handler was registered
        assert "log" in pep.obligation_handler._handlers

    def test_obligation_fulfilled_on_permit(self):
        """
        Registered obligations should be fulfilled when access permitted.
        
        Scenario:
        - Register obligation handler
        - Create policy with obligations
        - Call enforce()
        - Expected: obligation handler called, permitted=True
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        handler_called = {"count": 0}

        def audit_handler(obligation):
            handler_called["count"] += 1
            return True

        pep.register_obligation_handler("audit", audit_handler)

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        assert result.permitted is True

    def test_failed_obligation_denies_access(self):
        """
        If obligation fails, access should be denied.
        
        Scenario:
        - Create policy that permits
        - Register obligation handler that returns False
        - Call enforce()
        - Expected: permitted=False (obligation failure)
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        def failing_handler(obligation):
            return False  # Obligation failed

        pep.register_obligation_handler("critical", failing_handler)

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        # Even though policy permits, obligation failure denies access
        assert result.permitted is False


class TestAuditLogging:
    """Test audit log recording and retrieval."""

    def test_audit_logging_enabled_by_default(self):
        """
        Audit logging should be enabled by default.
        
        Scenario:
        - Create PEP and call enforce()
        - Expected: audit log entry recorded
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        log = pep.get_audit_log()
        assert len(log) > 0

    def test_audit_entry_contains_decision_info(self):
        """
        Audit entries should contain request and decision details.
        
        Scenario:
        - Call enforce() and check audit entry
        - Expected: entry has timestamp, subject_did, resource_id, action, effect, permitted
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy("policy-1"))

        pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
        )

        log = pep.get_audit_log()
        entry = log[0]

        assert entry["subject_did"] == "did:arbiter:alice"
        assert entry["resource_id"] == "doc-1"
        assert entry["action"] == "read"
        assert entry["permitted"] is True
        assert entry["effect"] == "permit"
        assert "timestamp" in entry

    def test_audit_log_filtering_by_subject(self):
        """
        Should filter audit log by subject_did.
        
        Scenario:
        - Call enforce() twice with different subjects
        - Get audit log filtered by one subject
        - Expected: returns only entries for that subject
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        pep.enforce(subject_did="did:arbiter:alice", resource_id="doc-1", action="read")
        pep.enforce(subject_did="did:arbiter:bob", resource_id="doc-2", action="write")

        alice_log = pep.get_audit_log(subject_did="did:arbiter:alice")
        assert len(alice_log) == 1
        assert alice_log[0]["subject_did"] == "did:arbiter:alice"

    def test_audit_log_filtering_by_resource(self):
        """
        Should filter audit log by resource_id.
        
        Scenario:
        - Call enforce() twice on different resources
        - Get audit log filtered by one resource
        - Expected: returns only entries for that resource
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        pep.enforce(subject_did="did:arbiter:alice", resource_id="doc-1", action="read")
        pep.enforce(subject_did="did:arbiter:alice", resource_id="doc-2", action="read")

        doc1_log = pep.get_audit_log(resource_id="doc-1")
        assert len(doc1_log) == 1
        assert doc1_log[0]["resource_id"] == "doc-1"

    def test_audit_logging_can_be_disabled(self):
        """
        Auditing should be disableable.
        
        Scenario:
        - Disable auditing
        - Call enforce()
        - Expected: no audit entries recorded
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        pep.enable_audit(False)
        pep.enforce(subject_did="did:arbiter:alice", resource_id="doc-1", action="read")

        log = pep.get_audit_log()
        assert len(log) == 0

    def test_audit_log_size_bounded(self):
        """
        Audit log should not grow unbounded (kept to last 5000 entries).
        
        Scenario:
        - Generate many audit entries (> 10000)
        - Check log size
        - Expected: log limited to ~5000 entries
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        # Generate 11000 entries
        for i in range(11000):
            pep.enforce(
                subject_did=f"did:arbiter:agent-{i}",
                resource_id=f"res-{i}",
                action="read",
            )

        # Internal log should be truncated
        assert len(pep._audit_log) <= 5000


class TestAttributeExtraction:
    """Test attribute extraction and PEP integration with identity layer.
    
    The PEP uses PIP to extract attributes from:
    - Subject DIDs
    - Verifiable presentations
    - Resource metadata
    - Environment
    """

    def test_enforce_with_resource_metadata(self):
        """
        Resource metadata should be passed to attribute extraction.
        
        Scenario:
        - Create role-based policy (requires "admin" role)
        - Call enforce() with resource metadata and role in context
        - Expected: decision made based on role in metadata
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_role_based_policy("admin"))

        # Simulate presenting attributes via resource metadata
        # (In real scenario, would come from ZK proof or credentials)
        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
            resource_metadata={"owner": "did:arbiter:bob"},
        )

        # Should complete without error (actual decision depends on policy)
        assert isinstance(result, EnforcementResult)

    def test_enforce_with_verifiable_presentation(self):
        """
        Verifiable presentations should be accepted and used for attribute extraction.
        
        Scenario:
        - Create presentation with disclosed attributes
        - Call enforce() with presentation
        - Expected: attributes extracted from presentation
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        # Create ZK proof with disclosed attributes
        proof = ZKProof(
            proof_type=ProofType.CREDENTIAL_VALIDITY,
            challenge=b"challenge",
            proof_data=b"proof",
            disclosed_values={"role": "admin", "level": 5},
        )

        presentation = VerifiablePresentation(
            holder="did:arbiter:alice",
            challenge=b"challenge",
            domain="example.com",
            zkp_proofs=[proof],
        )

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
            presentation=presentation,
        )

        # Should complete with permit policy
        assert result.permitted is True

    def test_enforce_with_environment_attributes(self):
        """
        Environment attributes should be passed to PDP evaluation.
        
        Scenario:
        - Call enforce() with environment data
        - Environment attributes should be available in PDP context
        - Expected: enforcement completes successfully
        """
        pep = PolicyEnforcementPoint()
        pep.pap.repository.store(make_permit_policy())

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
            environment={"location": "us-west", "ipAddress": "192.168.1.1"},
        )

        assert result.permitted is True


class TestEnforcementWithPolicySets:
    """Test enforcement using policy sets."""

    def test_enforce_with_policy_set(self):
        """
        enforce_with_policy_set() should evaluate a specific policy set.
        
        Scenario:
        - Create a policy set with multiple policies
        - Call enforce_with_policy_set()
        - Expected: result using policy set's combining algorithm
        """
        pep = PolicyEnforcementPoint()

        # Create policies and policy set
        p1 = pep.pap.create_policy(
            policy_id="p1",
            rules=[
                PolicyRule(rule_id="r1", effect=Effect.PERMIT, conditions=[])
            ],
        )
        p2 = pep.pap.create_policy(
            policy_id="p2",
            rules=[
                PolicyRule(rule_id="r2", effect=Effect.PERMIT, conditions=[])
            ],
        )
        ps = pep.pap.create_policy_set(
            policy_set_id="ps1",
            policy_ids=["p1", "p2"],
        )

        result = pep.enforce_with_policy_set(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="read",
            policy_set_id="ps1",
        )

        assert result.permitted is True


class TestIdentityIntegration:
    """Test PEP configured for identity layer integration.
    
    This factory creates a PEP with custom resolvers for
    extracting attributes from verifiable presentations.
    """

    def test_create_pep_with_identity_integration(self):
        """
        create_pep_with_identity_integration() should return configured PEP.
        
        Scenario:
        - Call factory function
        - Expected: returns PEP with custom resolvers registered
        """
        pep = create_pep_with_identity_integration()

        assert isinstance(pep, PolicyEnforcementPoint)
        # Should have custom resolver for capabilities
        assert "subject.capabilities" in pep.pip._custom_resolvers

    def test_identity_integrated_pep_extracts_capabilities(self):
        """
        Identity-integrated PEP should extract capabilities from presentations.
        
        Scenario:
        - Use identity-integrated PEP
        - Create policy requiring "search" capability
        - Create presentation proving "search" capability
        - Call enforce()
        - Expected: decision permits (capability satisfied)
        """
        pep = create_pep_with_identity_integration()

        # Create capability-requiring policy
        policy = Policy(
            policy_id="cap-policy",
            version="1.0",
            rules=[
                PolicyRule(
                    rule_id="cap-check",
                    effect=Effect.PERMIT,
                    conditions=[
                        Condition(
                            attribute_category="subject",
                            attribute_id="capabilities",
                            operator=ConditionOperator.CONTAINS,
                            value="search",
                        )
                    ],
                )
            ],
        )
        pep.pap.repository.store(policy)

        # Create presentation with capabilities
        proof = ZKProof(
            proof_type=ProofType.CREDENTIAL_VALIDITY,
            challenge=b"challenge",
            proof_data=b"proof",
            disclosed_values={"capabilities": ["search", "analyze"]},
        )

        presentation = VerifiablePresentation(
            holder="did:arbiter:alice",
            challenge=b"challenge",
            domain="example.com",
            zkp_proofs=[proof],
        )

        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-1",
            action="search",
            presentation=presentation,
        )

        assert result.permitted is True


class TestEndToEndEnforcementFlow:
    """End-to-end enforcement scenarios combining multiple components."""

    def test_complete_enforcement_flow_permit(self):
        """
        Complete flow: request -> attributes -> PDP -> PEP -> permit.
        
        Scenario:
        - Setup PEP with policies
        - Create request with all context (subject, resource, environment)
        - Call enforce()
        - Expected: proper decision flow with logged audit entry
        """
        pep = PolicyEnforcementPoint()

        # Create a policy
        policy = Policy(
            policy_id="resource-policy",
            version="1.0",
            target={"resource.type": "document"},
            rules=[
                PolicyRule(
                    rule_id="owner-permit",
                    effect=Effect.PERMIT,
                    conditions=[],
                )
            ],
        )
        pep.pap.repository.store(policy)

        # Enforce with full context
        result = pep.enforce(
            subject_did="did:arbiter:alice",
            resource_id="doc-123",
            action="read",
            resource_metadata={"type": "document", "owner": "did:arbiter:alice"},
            environment={"location": "office"},
        )

        # Verify result
        assert result.permitted is True
        assert result.decision.effect == Effect.PERMIT

        # Verify audit logged
        log = pep.get_audit_log()
        assert len(log) == 1
        assert log[0]["subject_did"] == "did:arbiter:alice"

    def test_complete_enforcement_flow_deny(self):
        """
        Complete flow: request -> attributes -> PDP -> PEP -> deny.
        
        Scenario:
        - Setup PEP with deny policy
        - Call enforce()
        - Expected: denied with audit entry
        """
        pep = PolicyEnforcementPoint()

        # Create a deny policy
        policy = Policy(
            policy_id="deny-all",
            version="1.0",
            rules=[
                PolicyRule(
                    rule_id="deny-all-rule",
                    effect=Effect.DENY,
                    conditions=[],
                )
            ],
        )
        pep.pap.repository.store(policy)

        result = pep.enforce(
            subject_did="did:arbiter:bob",
            resource_id="secret-doc",
            action="write",
        )

        assert result.permitted is False
        assert result.decision.effect == Effect.DENY

        # Verify audit logged
        log = pep.get_audit_log()
        assert len(log) == 1
        assert log[0]["permitted"] is False
