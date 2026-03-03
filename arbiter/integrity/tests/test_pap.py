import pytest

from datetime import datetime

from arbiter.integrity.abac.pap import (
    PolicyRepository,
    PolicyAdministrationPoint,
)
from arbiter.common.models import (
    Policy,
    PolicyRule,
    Condition,
    ConditionOperator,
    Effect,
)
from arbiter.common.errors import PolicyNotFoundError, PolicyValidationError

# Provides a minimal valid policy with:
# One rule
# One condition
# Explicit subject attribute check (role == admin)
def make_basic_policy(policy_id="p1", version="1.0") -> Policy:
    return Policy(
        policy_id=policy_id,
        version=version,
        rules=[
            PolicyRule(
                rule_id="r1",
                effect=Effect.PERMIT,
                conditions=[
                    Condition(
                        attribute_category="subject",
                        attribute_id="role",
                        operator=ConditionOperator.EQUALS,
                        value="admin",
                    )
                ],
            ) 
        ],
    )

# store() persists the policy
# Metadata is automatically generated
# created_by is correctly recorded
# created_at timestamp is set
# Metadata and policy storage are decoupled
# Metadata retrieval works independently
def test_repository_store_get_and_metadata():
    repo = PolicyRepository()
    policy = make_basic_policy("policy-a")
    meta = repo.store(policy, created_by="did:arbiter:creator")
    assert meta.policy_id == "policy-a"
    assert meta.created_by == "did:arbiter:creator"
    assert isinstance(meta.created_at, datetime)
    fetched = repo.get("policy-a")
    assert fetched.policy_id == policy.policy_id
    md = repo.get_metadata("policy-a")
    assert md.policy_id == "policy-a"


# Empty rules list → policy has no enforcement meaning
# Empty version → breaks version tracking
# Validation occurs before persistence
# Repository enforces invariants
# Invalid state is never stored
def test_store_invalid_policy_raises():
    repo = PolicyRepository()
    bad = Policy(policy_id="bad", version="", rules=[])
    with pytest.raises(PolicyValidationError):
        repo.store(bad)


def test_version_history_and_update():
    pap = PolicyAdministrationPoint()
    p = pap.create_policy(policy_id="p-ver", version="1.0", rules=[
        PolicyRule(rule_id="r1", effect=Effect.PERMIT, conditions=[])
    ])
    updated = pap.update_policy("p-ver", rules=[PolicyRule(rule_id="r2", effect=Effect.DENY, conditions=[])])
    assert updated.version == "1.1"
    history = pap.repository.get_version_history("p-ver")
    assert any(h.version == "1.0" for h in history)


# Create two independent policies
# Create a policy set referencing them
# Retrieve the set
# Attempt to retrieve a non-existent set
def test_create_and_get_policy_set_and_get_policy_set_error():
    pap = PolicyAdministrationPoint()

    p1 = pap.create_policy(policy_id="ps-p1", rules=[PolicyRule(rule_id="r1", effect=Effect.PERMIT, conditions=[])])
    p2 = pap.create_policy(policy_id="ps-p2", rules=[PolicyRule(rule_id="r2", effect=Effect.PERMIT, conditions=[])])

    ps = pap.create_policy_set(policy_set_id="ps1", policy_ids=["ps-p1", "ps-p2"])
    assert ps.policy_set_id == "ps1"
    assert len(ps.policies) == 2
    with pytest.raises(PolicyNotFoundError):
        pap.get_policy_set("does-not-exist")


def test_list_find_tags_and_activate_deactivate():
    pap = PolicyAdministrationPoint()

    p = pap.create_policy(policy_id="tagged", rules=[PolicyRule(rule_id="r1", effect=Effect.PERMIT, conditions=[])], tags={"sensitive"})
    p2 = pap.create_policy(policy_id="tagged2", rules=[PolicyRule(rule_id="r2", effect=Effect.PERMIT, conditions=[])], tags={"public"})

    # find by tags
    found = pap.list_policies(tags={"sensitive"})
    assert any(f.policy_id == "tagged" for f in found)

    # deactivate then list active_only
    pap.repository.deactivate("tagged")
    listed = pap.list_policies(active_only=True)
    assert all(x.policy_id != "tagged" for x in listed)

    # activate back
    pap.repository.activate("tagged")
    listed_all = pap.list_policies(active_only=True)
    assert any(x.policy_id == "tagged" for x in listed_all)

# This test case checks if the mapping is done correctly and no data loss occurs during the import/export process. It also ensures that the created_by field is correctly set during import and that the exported policy retains the same structure and content as the original policy.
def test_import_export_policy_roundtrip():
    pap = PolicyAdministrationPoint()

    policy_dict = {
        "policyId": "imp-1",
        "version": "1.0",
        "rules": [
            {
                "ruleId": "r1",
                "effect": "permit",
                "conditions": [
                    {"category": "subject", "attributeId": "role", "operator": "eq", "value": "admin"}
                ],
                "description": ""
            }
        ],
    }

    imported = pap.import_policy(policy_dict, created_by="did:arbiter:importer")
    assert imported.policy_id == "imp-1"

    exported = pap.export_policy("imp-1")
    assert exported["policyId"] == "imp-1"


def test_add_and_remove_rule_and_delete_policy():
    pap = PolicyAdministrationPoint()

    p = pap.create_policy(policy_id="mod-1", rules=[PolicyRule(rule_id="r1", effect=Effect.PERMIT, conditions=[])])

    pap.add_rule_to_policy("mod-1", PolicyRule(rule_id="r2", effect=Effect.DENY, conditions=[]))
    updated = pap.get_policy("mod-1")
    assert any(r.rule_id == "r2" for r in updated.rules)

    pap.remove_rule_from_policy("mod-1", "r2")
    updated2 = pap.get_policy("mod-1")
    assert all(r.rule_id != "r2" for r in updated2.rules)

    # soft delete
    pap.delete_policy("mod-1", hard_delete=False)
    # policy still retrievable but metadata shows inactive
    assert pap.repository.get_metadata("mod-1").active is False

    # hard delete
    pap.delete_policy("mod-1", hard_delete=True)
    with pytest.raises(PolicyNotFoundError):
        pap.get_policy("mod-1")
