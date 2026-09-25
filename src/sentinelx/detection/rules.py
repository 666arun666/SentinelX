import os
import re
from dataclasses import dataclass, field
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)

VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str
    logsource: str
    selection: dict[str, Any]
    condition: str
    status: str = "experimental"

    _compiled_regexes: dict[str, re.Pattern] = field(default_factory=dict, init=False)

    def __post_init__(self):
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}' for rule {self.rule_id}"
            )

        for k, v in self.selection.items():
            if isinstance(v, str) and v.startswith("/") and v.endswith("/"):
                try:
                    self._compiled_regexes[k] = re.compile(v[1:-1])
                except re.error as e:
                    raise ValueError(f"Invalid regex '{v}' in rule {self.rule_id}: {e}")

    def matches(self, event_fields: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        # M3 simplified evaluation: we only support 'selection' or 'all of selection'
        if self.condition != "selection" and self.condition != "all of selection":
            return False, {}

        evidence = {}
        for key, expected in self.selection.items():
            actual = event_fields.get(key)
            if actual is None:
                return False, {}

            actual_str = str(actual)
            is_match = False
            matched_value = None

            if key in self._compiled_regexes:
                if self._compiled_regexes[key].search(actual_str):
                    is_match = True
                    matched_value = expected
            elif isinstance(expected, list):
                # OR condition for list of strings
                for val in expected:
                    if self._evaluate_value(str(val), actual_str):
                        is_match = True
                        matched_value = val
                        break
            else:
                if self._evaluate_value(str(expected), actual_str):
                    is_match = True
                    matched_value = expected

            if not is_match:
                return False, {}

            evidence[key] = {"expected": matched_value, "actual": actual_str}

        return True, evidence

    def _evaluate_value(self, expected: str, actual: str) -> bool:
        """Evaluate exact or wildcard (* substring) match."""
        if expected.startswith("*") and expected.endswith("*"):
            return expected[1:-1] in actual
        elif expected.startswith("*"):
            return actual.endswith(expected[1:])
        elif expected.endswith("*"):
            return actual.startswith(expected[:-1])
        else:
            return expected == actual


def load_rules(rules_dir: str) -> list[Rule]:
    rules = []
    if not os.path.exists(rules_dir):
        logger.warning("rules_dir_missing", path=rules_dir)
        return rules

    for filename in os.listdir(rules_dir):
        if not filename.endswith((".yml", ".yaml")):
            continue

        path = os.path.join(rules_dir, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                logger.warning("rule_malformed_not_dict", file=filename)
                continue

            detection = data.get("detection", {})
            selection = detection.get("selection")
            condition = detection.get("condition")

            if not selection or not condition:
                logger.warning("rule_missing_detection", file=filename)
                continue

            rule = Rule(
                rule_id=data.get("id", filename),
                title=data.get("title", filename),
                severity=data.get("level", "low").lower(),
                logsource=data.get("logsource", {}).get("service", "all"),
                selection=selection,
                condition=condition,
                status=data.get("status", "experimental"),
            )
            rules.append(rule)
            logger.info("rule_loaded", rule_id=rule.rule_id, title=rule.title)
        except Exception as e:  # noqa: BLE001
            logger.error("rule_load_failed", file=filename, error=str(e))

    return rules
