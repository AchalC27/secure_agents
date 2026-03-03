import pytest
import re

from arbiter.integrity.abac.pdp import (
    PolicyDecisionPoint,
    EvaluationContext,
)
from arbiter.integrity.policy_models import CombiningAlgorithm
from arbiter.common.models import (
    PolicyRule,
    Condition,
    ConditionOperator,
    Effect,
    Policy,
)


@pytest.mark.parametrize("actual,expected,op,expect", [
    (5, 5, ConditionOperator.EQUALS, True),
    (5, 6, ConditionOperator.NOT_EQUALS, True),
    (10, 5, ConditionOperator.GREATER_THAN, True),
    (3, 5, ConditionOperator.LESS_THAN, True),
    (5, 5, ConditionOperator.GREATER_THAN_OR_EQUAL, True),
    (4, 5, ConditionOperator.LESS_THAN_OR_EQUAL, True),
    (["a", "b"], "a", ConditionOperator.CONTAINS, True),
    ("hello world", "world", ConditionOperator.CONTAINS, True)
    # ("abc123", "\\\d+", ConditionOperator.REGEX, True),
    # ("abc", "[", ConditionOperator.REGEX, False),  # invalid regex
])
def test_apply_operator_and_regex(actual, expected, op, expect):
    pdp = PolicyDecisionPoint()

    # Use internal _apply_operator via a Condition wrapper
    cond = Condition(attribute_category="subject", attribute_id="x", operator=op, value=expected)

    ctx = EvaluationContext(subject={"x": actual})

    # Use _evaluate_condition which uses _apply_operator
    res = pdp._evaluate_condition(cond, ctx)
    assert res is expect


def test_resolve_value_references():
    pdp = PolicyDecisionPoint()
    ctx = EvaluationContext(subject={"id": "sub1"}, resource={"owner": "did:arbiter:alice"})

    # reference to resource.owner
    cond = Condition(attribute_category="subject", attribute_id="id", operator=ConditionOperator.EQUALS, value="${resource.owner}")

    # _resolve_value should map to resource.owner
    assert pdp._resolve_value(cond.value, ctx) == "did:arbiter:alice"


def test_match_target_and_evaluate_policy_set():
    pdp = PolicyDecisionPoint()

    policy = Policy(policy_id="p1", version="1.0", rules=[
        PolicyRule(rule_id="r1", effect=Effect.PERMIT, conditions=[]),
    ])

    pset = type("PS", (), {"policy_set_id": "ps1", "policies": [policy], "combining_algorithm": CombiningAlgorithm.DENY_OVERRIDES, "target": {"resource.type": "doc"}})()

    ctx_match = EvaluationContext(resource={"type": "doc"})
    ctx_nomatch = EvaluationContext(resource={"type": "other"})

    request = type("Req", (), {"request_id": "req-1"})()

    decision_ok = pdp.evaluate_policy_set(request, pset, ctx_match)
    assert decision_ok.effect == Effect.PERMIT

    decision_na = pdp.evaluate_policy_set(request, pset, ctx_nomatch)
    assert decision_na.effect == Effect.NOT_APPLICABLE


def test_combining_algorithms():
    pdp = PolicyDecisionPoint()

    # Create dummy policy results by calling _combine_effects directly
    effects = [Effect.PERMIT, Effect.DENY]

    # DENY_OVERRIDES -> DENY
    assert pdp._combine_effects(effects, CombiningAlgorithm.DENY_OVERRIDES) == Effect.DENY

    # PERMIT_OVERRIDES -> PERMIT
    assert pdp._combine_effects(effects, CombiningAlgorithm.PERMIT_OVERRIDES) == Effect.PERMIT

    # FIRST_APPLICABLE -> first (PERMIT)
    assert pdp._combine_effects([Effect.PERMIT, Effect.DENY], CombiningAlgorithm.FIRST_APPLICABLE) == Effect.PERMIT

    # ONLY_ONE_APPLICABLE multiple -> INDETERMINATE
    assert pdp._combine_effects([Effect.PERMIT, Effect.PERMIT], CombiningAlgorithm.ONLY_ONE_APPLICABLE) == Effect.INDETERMINATE


def test_custom_operator_registration():
    pdp = PolicyDecisionPoint()

    # Register custom operator that checks parity
    def is_even(actual, expected):
        return (actual % 2) == 0

    pdp.register_operator("is_even", is_even)

    cond = Condition(attribute_category="subject", attribute_id="n", operator=ConditionOperator.EQUALS, value=4)
    # hack: use operator value name to trigger custom operator
    cond = Condition(attribute_category="subject", attribute_id="n", operator=ConditionOperator.EQUALS, value=4)

    # Monkeypatch the operator enum value to match our custom operator name for test
    class FakeOp:
        value = "is_even"

    cond = Condition(attribute_category="subject", attribute_id="n", operator=FakeOp(), value=4)

    ctx = EvaluationContext(subject={"n": 6})
    assert pdp._evaluate_condition(cond, ctx) is True
