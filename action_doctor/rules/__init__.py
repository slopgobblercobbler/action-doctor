"""Rules registry and exports for action-doctor."""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from action_doctor.rules.base import Rule
from action_doctor.rules.best_practices import (
    MissingFailFastRule,
    MissingJobTimeoutRule,
    MissingStepNameRule,
)
from action_doctor.rules.runners import (
    DeprecatedNodeRuntimeRule,
    DeprecatedRunnerRule,
    LegacyMacRunnerRule,
)
from action_doctor.rules.security import (
    ExcessivePermissionsRule,
    InsecurePullRequestTargetRule,
    MissingPermissionsRule,
    PlaintextSecretInRunRule,
    ScriptInjectionRule,
)
from action_doctor.rules.supply_chain import (
    DeprecatedActionVersionRule,
    MutableBranchRefRule,
    UnpinnedActionShaRule,
)
from action_doctor.rules.syntax import (
    DeprecatedAddPathRule,
    DeprecatedSaveStateRule,
    DeprecatedSetEnvRule,
    DeprecatedSetOutputRule,
)

ALL_RULE_CLASSES: List[Type[Rule]] = [
    # Runners (AD001 - AD009)
    DeprecatedRunnerRule,
    DeprecatedNodeRuntimeRule,
    LegacyMacRunnerRule,
    # Security (AD101 - AD109)
    MissingPermissionsRule,
    ExcessivePermissionsRule,
    InsecurePullRequestTargetRule,
    ScriptInjectionRule,
    PlaintextSecretInRunRule,
    # Supply Chain (AD201 - AD209)
    UnpinnedActionShaRule,
    MutableBranchRefRule,
    DeprecatedActionVersionRule,
    # Syntax & Deprecated Commands (AD301 - AD309)
    DeprecatedSetOutputRule,
    DeprecatedSaveStateRule,
    DeprecatedAddPathRule,
    DeprecatedSetEnvRule,
    # Best Practices (AD401 - AD409)
    MissingJobTimeoutRule,
    MissingStepNameRule,
    MissingFailFastRule,
]

_RULES_BY_ID: Dict[str, Rule] = {}
_RULES_BY_NAME: Dict[str, Rule] = {}

for rule_cls in ALL_RULE_CLASSES:
    rule_instance = rule_cls()
    _RULES_BY_ID[rule_instance.rule_id.upper()] = rule_instance
    _RULES_BY_NAME[rule_instance.name.lower()] = rule_instance


def get_all_rules() -> List[Rule]:
    """Return an instantiated list of all registered audit rules."""
    return list(_RULES_BY_ID.values())


def get_rule(identifier: str) -> Optional[Rule]:
    """Look up rule by its ID (e.g. 'AD001') or name (e.g. 'deprecated-runner')."""
    clean_id = identifier.strip()
    if clean_id.upper() in _RULES_BY_ID:
        return _RULES_BY_ID[clean_id.upper()]
    if clean_id.lower() in _RULES_BY_NAME:
        return _RULES_BY_NAME[clean_id.lower()]
    return None
