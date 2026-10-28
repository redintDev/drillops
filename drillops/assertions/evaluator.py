"""Assertion evaluator for database restore verification."""

import time
from typing import Any, List, Tuple
from drillops.engines.base import BaseRestoreEngine
from drillops.models import AssertionResult, AssertionRule


class AssertionEvaluator:
    """Evaluates integrity rules against a restored database instance."""

    def __init__(self, engine: BaseRestoreEngine):
        self.engine = engine

    def verify_tables_exist(self, expected_tables: List[str]) -> List[AssertionResult]:
        """Verify that all required tables are present in the restored database."""
        results = []
        start = time.perf_counter()
        try:
            actual_tables = set(self.engine.list_tables())
            duration = (time.perf_counter() - start) * 1000
            for table in expected_tables:
                passed = table in actual_tables
                results.append(
                    AssertionResult(
                        rule_name=f"table_exists_{table}",
                        passed=passed,
                        actual_value="present" if passed else "missing",
                        expected_value="present",
                        execution_time_ms=round(duration, 2),
                        critical=True,
                        error=None if passed else f"Table '{table}' not found in restored database",
                    )
                )
        except Exception as e:
            results.append(
                AssertionResult(
                    rule_name="table_listing_check",
                    passed=False,
                    actual_value="error",
                    expected_value="present",
                    execution_time_ms=0.0,
                    critical=True,
                    error=f"Failed to query table listing: {str(e)}",
                )
            )
        return results

    def evaluate_rule(self, rule: AssertionRule) -> AssertionResult:
        """Executes a single assertion query and compares with expected threshold."""
        start = time.perf_counter()
        try:
            actual = self.engine.execute_query(rule.query)
            duration = (time.perf_counter() - start) * 1000
            passed = self._compare(actual, rule.operator, rule.expected_value)
            return AssertionResult(
                rule_name=rule.name,
                passed=passed,
                actual_value=actual,
                expected_value=rule.expected_value,
                execution_time_ms=round(duration, 2),
                critical=rule.critical,
                error=None if passed else f"Assertion failed: {actual} {rule.operator} {rule.expected_value}",
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return AssertionResult(
                rule_name=rule.name,
                passed=False,
                actual_value=None,
                expected_value=rule.expected_value,
                execution_time_ms=round(duration, 2),
                critical=rule.critical,
                error=f"Execution error: {str(e)}",
            )

    @staticmethod
    def _compare(actual: Any, operator: str, expected: Any) -> bool:
        if actual is None and operator != "==":
            return False

        try:
            if operator == "==":
                return actual == expected
            elif operator == "!=":
                return actual != expected
            elif operator == ">":
                return float(actual) > float(expected)
            elif operator == ">=":
                return float(actual) >= float(expected)
            elif operator == "<":
                return float(actual) < float(expected)
            elif operator == "<=":
                return float(actual) <= float(expected)
            elif operator == "not_empty":
                if isinstance(actual, (list, dict, str)):
                    return len(actual) > 0
                return actual is not None and actual != 0
            elif operator == "contains":
                return str(expected) in str(actual)
        except (ValueError, TypeError):
            return False

        return False
