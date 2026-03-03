"""
Arbiter - Policy Decision Point (PDP)

The PDP evaluates policies against attributes and returns access decisions.

Reference: NIST SP 800-162 - ABAC Architecture

The PDP:
- Evaluates policy rules against provided attributes
- Applies combining algorithms
- Returns deterministic decisions
- Supports obligations and advice

Design Principles:
- Deterministic: Same inputs always produce same output
- Stateless: No memory between evaluations
- Context-aware: Uses all available attributes
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

from arbiter.common.models import (
    Policy,
    PolicyRule,
    Condition,
    ConditionOperator,
    Effect,
    AccessDecision,
    AccessRequest,
)
from arbiter.common.errors import PolicyError
from arbiter.common.utils import utc_now
from arbiter.integrity.policy_models import (
    PolicySet,
    CombiningAlgorithm,
)


# =============================================================================
# Evaluation Context
# =============================================================================

@dataclass
class EvaluationContext:
    """Context for policy evaluation.
    
    Contains all attributes organized by category.
    
    Attributes:
        subject: Subject attributes
        resource: Resource attributes
        action: Action attributes
        environment: Environment attributes
    """
    subject: Dict[str, Any] = field(default_factory=dict)
    resource: Dict[str, Any] = field(default_factory=dict)
    action: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)

    def get_attribute(
        self,
        category: str,
        attribute_id: str,
    ) -> Optional[Any]:
        """Get an attribute value.
        
        Args:
            category: Attribute category
            attribute_id: Attribute ID
            
        Returns:
            Attribute value or None
        """
        attrs = {
            "subject": self.subject,
            "resource": self.resource,
            "action": self.action,
            "environment": self.environment,
        }.get(category, {})
        
        return attrs.get(attribute_id)


# =============================================================================
# Evaluation Result
# =============================================================================

@dataclass
class RuleEvaluationResult:
    """Result of evaluating a single rule.
    
    Attributes:
        rule_id: ID of the evaluated rule
        effect: The rule's effect (if matched)
        matched: Whether the rule conditions matched
        reason: Explanation of the result
    """
    rule_id: str
    effect: Effect
    matched: bool
    reason: str = ""


@dataclass
class PolicyEvaluationResult:
    """Result of evaluating a policy.
    
    Attributes:
        policy_id: ID of the evaluated policy
        effect: Final effect after applying rules
        matched_rules: Rules that matched
        reason: Explanation
    """
    policy_id: str
    effect: Effect
    matched_rules: List[str] = field(default_factory=list)
    reason: str = ""


# =============================================================================
# Policy Decision Point
# =============================================================================

class PolicyDecisionPoint:
    """Evaluates policies and returns access decisions.
    
    The PDP is the core decision-making component that:
    1. Matches requests against policy targets
    2. Evaluates rules in order
    3. Applies combining algorithms
    4. Returns deterministic decisions
    
    All evaluation is deterministic and stateless.
    """

    def __init__(self) -> None:
        """Initialize the PDP."""
        # Custom operators for extensibility
        self._custom_operators: Dict[
            str,
            Callable[[Any, Any], bool]
        ] = {}

    def evaluate(
        self,
        request: AccessRequest,
        policies: List[Policy],
        context: EvaluationContext,
        combining_algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES,
    ) -> AccessDecision:
        """Evaluate an access request against policies.
        
        Args:
            request: The access request
            policies: Policies to evaluate
            context: Evaluation context with attributes
            combining_algorithm: How to combine policy decisions
            
        Returns:
            Final access decision
        """
        if not policies:
            return AccessDecision(
                request_id=request.request_id,
                effect=Effect.NOT_APPLICABLE,
                reason="No policies to evaluate",
            )
        
        # Evaluate each policy
        policy_results: List[PolicyEvaluationResult] = []
        for policy in policies:
            result = self._evaluate_policy(policy, context)
            policy_results.append(result)
        
        # Combine results
        final_effect = self._combine_effects(
            [r.effect for r in policy_results],
            combining_algorithm,
        )
        
        # Find the determining policy
        determining_policy = None
        determining_rule = None
        for result in policy_results:
            if result.effect == final_effect and result.matched_rules:
                determining_policy = result.policy_id
                determining_rule = result.matched_rules[0] if result.matched_rules else None
                break
        
        return AccessDecision(
            request_id=request.request_id,
            effect=final_effect,
            policy_id=determining_policy,
            rule_id=determining_rule,
            reason=self._generate_reason(final_effect, policy_results),
        )

    def evaluate_policy_set(
        self,
        request: AccessRequest,
        policy_set: PolicySet,
        context: EvaluationContext,
    ) -> AccessDecision:
        """Evaluate a policy set.
        
        Args:
            request: Access request
            policy_set: Policy set to evaluate
            context: Evaluation context
            
        Returns:
            Access decision
        """
        # Check policy set target
        if policy_set.target:
            if not self._match_target(policy_set.target, context):
                return AccessDecision(
                    request_id=request.request_id,
                    effect=Effect.NOT_APPLICABLE,
                    reason="Request did not match policy set target",
                )
        
        return self.evaluate(
            request,
            policy_set.policies,
            context,
            policy_set.combining_algorithm,
        )

    def _evaluate_policy(
        self,
        policy: Policy,
        context: EvaluationContext,
    ) -> PolicyEvaluationResult:
        """Evaluate a single policy.
        
        Args:
            policy: Policy to evaluate
            context: Evaluation context
            
        Returns:
            Policy evaluation result
        """
        # Check policy target
        if policy.target:
            if not self._match_target(policy.target, context):
                return PolicyEvaluationResult(
                    policy_id=policy.policy_id,
                    effect=Effect.NOT_APPLICABLE,
                    reason="Request did not match policy target",
                )
        
        # Evaluate rules
        matched_rules: List[str] = []
        applicable_effects: List[Effect] = []
        
        for rule in policy.rules:
            rule_result = self._evaluate_rule(rule, context)
            if rule_result.matched:
                matched_rules.append(rule.rule_id)
                applicable_effects.append(rule.effect)
        
        if not applicable_effects:
            return PolicyEvaluationResult(
                policy_id=policy.policy_id,
                effect=Effect.NOT_APPLICABLE,
                reason="No rules matched",
            )
        
        # Apply rule combining (using deny-overrides within a policy)
        final_effect = self._combine_effects(
            applicable_effects,
            CombiningAlgorithm.DENY_OVERRIDES,
        )
        
        return PolicyEvaluationResult(
            policy_id=policy.policy_id,
            effect=final_effect,
            matched_rules=matched_rules,
            reason=f"Rule(s) matched: {', '.join(matched_rules)}",
        )

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        context: EvaluationContext,
    ) -> RuleEvaluationResult:
        """Evaluate a single rule.
        
        All conditions must match (AND logic).
        
        Args:
            rule: Rule to evaluate
            context: Evaluation context
            
        Returns:
            Rule evaluation result
        """
        # Empty conditions always match (unconditional rule)
        if not rule.conditions:
            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                effect=rule.effect,
                matched=True,
                reason="Unconditional rule",
            )
        
        # All conditions must match
        for condition in rule.conditions:
            if not self._evaluate_condition(condition, context):
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    effect=rule.effect,
                    matched=False,
                    reason=f"Condition not met: {condition.attribute_id}",
                )
        
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            effect=rule.effect,
            matched=True,
            reason="All conditions matched",
        )

    def _evaluate_condition(
        self,
        condition: Condition,
        context: EvaluationContext,
    ) -> bool:
        """Evaluate a single condition.
        
        Args:
            condition: Condition to evaluate
            context: Evaluation context
            
        Returns:
            True if condition is satisfied
        """
        # Get attribute value
        attr_value = context.get_attribute(
            condition.attribute_category,
            condition.attribute_id,
        )
        
        # Handle missing attribute
        if attr_value is None:
            return False
        
        # Resolve reference values (e.g., "${resource.owner}")
        expected_value = self._resolve_value(condition.value, context)
        
        # Apply operator
        return self._apply_operator(
            condition.operator,
            attr_value,
            expected_value,
        )

    def _apply_operator(
        self,
        operator: ConditionOperator,
        actual: Any,
        expected: Any,
    ) -> bool:
        """Apply a comparison operator.
        
        Args:
            operator: The operator to apply
            actual: Actual attribute value
            expected: Expected value from condition
            
        Returns:
            True if condition is satisfied
        """
        # Check custom operators first
        if operator.value in self._custom_operators:
            return self._custom_operators[operator.value](actual, expected)
        
        if operator == ConditionOperator.EQUALS:
            return actual == expected
        
        elif operator == ConditionOperator.NOT_EQUALS:
            return actual != expected
        
        elif operator == ConditionOperator.GREATER_THAN:
            try:
                return actual > expected
            except TypeError:
                return False
        
        elif operator == ConditionOperator.LESS_THAN:
            try:
                return actual < expected
            except TypeError:
                return False
        
        elif operator == ConditionOperator.GREATER_THAN_OR_EQUAL:
            try:
                return actual >= expected
            except TypeError:
                return False
        
        elif operator == ConditionOperator.LESS_THAN_OR_EQUAL:
            try:
                return actual <= expected
            except TypeError:
                return False
        
        elif operator == ConditionOperator.CONTAINS:
            if isinstance(actual, (list, set, tuple)):
                return expected in actual
            elif isinstance(actual, str):
                return str(expected) in actual
            return False
        
        elif operator == ConditionOperator.IN:
            if isinstance(expected, (list, set, tuple)):
                return actual in expected
            return False
        
        elif operator == ConditionOperator.REGEX:
            if isinstance(actual, str) and isinstance(expected, str):
                try:
                    # Use search to match pattern anywhere in the string (not just from start)
                    return bool(re.search(expected, actual))
                except re.error:
                    return False
            return False
        
        return False

    def _resolve_value(
        self,
        value: Any,
        context: EvaluationContext,
    ) -> Any:
        """Resolve a value that may contain attribute references.
        
        References are in the form ${category.attribute}
        
        Args:
            value: Value to resolve
            context: Evaluation context
            
        Returns:
            Resolved value
        """
        if not isinstance(value, str):
            return value
        
        # Check for reference pattern
        if value.startswith("${") and value.endswith("}"):
            ref = value[2:-1]  # Remove ${ and }
            parts = ref.split(".", 1)
            if len(parts) == 2:
                category, attr_id = parts
                return context.get_attribute(category, attr_id)
        
        return value

    def _match_target(
        self,
        target: Dict[str, Any],
        context: EvaluationContext,
    ) -> bool:
        """Check if context matches a target specification.
        
        Args:
            target: Target specification
            context: Evaluation context
            
        Returns:
            True if target matches
        """
        for key, expected_value in target.items():
            parts = key.split(".", 1)
            if len(parts) == 2:
                category, attr_id = parts
                actual = context.get_attribute(category, attr_id)
                if actual != expected_value:
                    return False
        return True

    def _combine_effects(
        self,
        effects: List[Effect],
        algorithm: CombiningAlgorithm,
    ) -> Effect:
        """Combine multiple effects using the specified algorithm.
        
        Args:
            effects: List of effects to combine
            algorithm: Combining algorithm
            
        Returns:
            Combined effect
        """
        if not effects:
            return Effect.NOT_APPLICABLE
        
        # Filter out NOT_APPLICABLE
        applicable = [e for e in effects if e != Effect.NOT_APPLICABLE]
        
        if not applicable:
            return Effect.NOT_APPLICABLE
        
        if algorithm == CombiningAlgorithm.DENY_OVERRIDES:
            # Any DENY wins
            if Effect.DENY in applicable:
                return Effect.DENY
            if Effect.PERMIT in applicable:
                return Effect.PERMIT
            return Effect.NOT_APPLICABLE
        
        elif algorithm == CombiningAlgorithm.PERMIT_OVERRIDES:
            # Any PERMIT wins
            if Effect.PERMIT in applicable:
                return Effect.PERMIT
            if Effect.DENY in applicable:
                return Effect.DENY
            return Effect.NOT_APPLICABLE
        
        elif algorithm == CombiningAlgorithm.FIRST_APPLICABLE:
            # First applicable wins
            return applicable[0]
        
        elif algorithm == CombiningAlgorithm.ONLY_ONE_APPLICABLE:
            # Exactly one must apply
            if len(applicable) == 1:
                return applicable[0]
            elif len(applicable) > 1:
                return Effect.INDETERMINATE
            return Effect.NOT_APPLICABLE
        
        return Effect.NOT_APPLICABLE

    def _generate_reason(
        self,
        effect: Effect,
        results: List[PolicyEvaluationResult],
    ) -> str:
        """Generate explanation for the decision.
        
        Args:
            effect: Final effect
            results: Individual policy results
            
        Returns:
            Human-readable explanation
        """
        if effect == Effect.PERMIT:
            matching = [r for r in results if r.effect == Effect.PERMIT]
            if matching:
                return f"Permitted by policy: {matching[0].policy_id}"
            return "Permitted"
        
        elif effect == Effect.DENY:
            matching = [r for r in results if r.effect == Effect.DENY]
            if matching:
                return f"Denied by policy: {matching[0].policy_id}"
            return "Denied"
        
        elif effect == Effect.NOT_APPLICABLE:
            return "No applicable policy found"
        
        return "Decision made"

    def register_operator(
        self,
        operator_name: str,
        operator_func: Callable[[Any, Any], bool],
    ) -> None:
        """Register a custom operator.
        
        Args:
            operator_name: Operator name
            operator_func: Function taking (actual, expected) -> bool
        """
        self._custom_operators[operator_name] = operator_func
