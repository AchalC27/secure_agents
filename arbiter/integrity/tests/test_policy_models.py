import pytest

from arbiter.integrity.policy_models import (
    PolicyTemplate,
    validate_policy,
    validate_policy_strict,
)
from arbiter.common.models import Policy, PolicyRule, Condition, ConditionOperator, Effect
from arbiter.common.errors import PolicyValidationError


def test_allow_owner_full_access_template():
    policy = PolicyTemplate.allow_owner_full_access(resource_type="document")

    assert policy.target == {"resource.type": "document"}
    assert len(policy.rules) == 1

    rule = policy.rules[0]
    assert rule.rule_id == "owner-permit"
    assert rule.effect == Effect.PERMIT
    assert len(rule.conditions) == 1

    cond = rule.conditions[0]
    # template uses a reference to resource.owner
    assert cond.value == "${resource.owner}"

    # validate should pass for the generated template
    errors = validate_policy(policy)
    assert errors == []


def test_require_capability_template():
    policy = PolicyTemplate.require_capability(
        capability="search",
        resource_type="dataset",
        action="search",
    )

    assert policy.target["resource.type"] == "dataset"
    assert policy.target["action.id"] == "search"

    rule = policy.rules[0]
    assert rule.effect == Effect.PERMIT
    assert rule.conditions[0].operator == ConditionOperator.CONTAINS
    assert rule.conditions[0].value == "search"


def test_time_based_access_template_structure():
    policy = PolicyTemplate.time_based_access(9, 17, resource_type="service")

    # Should include three rules (deny before, deny after, permit during)
    ids = {r.rule_id for r in policy.rules}
    assert "time-window-deny" in ids
    assert "time-window-deny-2" in ids
    assert "time-window-permit" in ids


def test_validate_policy_and_strict():
    # Create an invalid policy (missing policy_id and version and no rules)
    bad_policy = Policy(policy_id="", version="", rules=[])

    errors = validate_policy(bad_policy)
    assert any("Policy ID is required" in e or "Policy version is required" in e for e in errors)

    with pytest.raises(PolicyValidationError):
        validate_policy_strict(bad_policy)
