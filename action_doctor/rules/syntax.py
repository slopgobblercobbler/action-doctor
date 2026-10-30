"""Deprecated workflow syntax and commands audit rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List

from action_doctor.models import Category, Issue, Severity
from action_doctor.rules.base import Rule


class DeprecatedSetOutputRule(Rule):
    rule_id = "AD301"
    name = "deprecated-set-output"
    category = Category.SYNTAX
    severity = Severity.ERROR
    description = "Detects deprecated '::set-output' command disabled on modern GitHub Actions runners."

    SET_OUTPUT_REGEX = re.compile(
        r"::set-output\s+name=([a-zA-Z0-9_\-]+)::(.*)",
        re.IGNORECASE,
    )

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []

        for idx, line in enumerate(lines):
            match = self.SET_OUTPUT_REGEX.search(line)
            if match:
                var_name = match.group(1)
                issues.append(
                    self.create_issue(
                        message=f"Deprecated workflow command '::set-output name={var_name}::...'. This syntax is disabled and fails in modern runners.",
                        file_path=file_path,
                        line=idx + 1,
                        column=match.start() + 1,
                        fixable=True,
                        suggestion=f'Replace with: echo "{var_name}=<value>" >> "$GITHUB_OUTPUT"',
                        context_line=line.strip(),
                    )
                )

        return issues


class DeprecatedSaveStateRule(Rule):
    rule_id = "AD302"
    name = "deprecated-save-state"
    category = Category.SYNTAX
    severity = Severity.ERROR
    description = "Detects deprecated '::save-state' workflow command."

    SAVE_STATE_REGEX = re.compile(
        r"::save-state\s+name=([a-zA-Z0-9_\-]+)::(.*)",
        re.IGNORECASE,
    )

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []

        for idx, line in enumerate(lines):
            match = self.SAVE_STATE_REGEX.search(line)
            if match:
                var_name = match.group(1)
                issues.append(
                    self.create_issue(
                        message=f"Deprecated workflow command '::save-state name={var_name}::...'.",
                        file_path=file_path,
                        line=idx + 1,
                        column=match.start() + 1,
                        fixable=True,
                        suggestion=f'Replace with: echo "{var_name}=<value>" >> "$GITHUB_STATE"',
                        context_line=line.strip(),
                    )
                )

        return issues


class DeprecatedAddPathRule(Rule):
    rule_id = "AD303"
    name = "deprecated-add-path"
    category = Category.SYNTAX
    severity = Severity.ERROR
    description = "Detects deprecated '::add-path::' workflow command."

    ADD_PATH_REGEX = re.compile(r"::add-path::(.*)", re.IGNORECASE)

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []

        for idx, line in enumerate(lines):
            match = self.ADD_PATH_REGEX.search(line)
            if match:
                issues.append(
                    self.create_issue(
                        message="Deprecated workflow command '::add-path::...'.",
                        file_path=file_path,
                        line=idx + 1,
                        column=match.start() + 1,
                        fixable=True,
                        suggestion='Replace with: echo "<path>" >> "$GITHUB_PATH"',
                        context_line=line.strip(),
                    )
                )

        return issues


class DeprecatedSetEnvRule(Rule):
    rule_id = "AD304"
    name = "deprecated-set-env"
    category = Category.SYNTAX
    severity = Severity.ERROR
    description = "Detects deprecated and insecure '::set-env' workflow command."

    SET_ENV_REGEX = re.compile(
        r"::set-env\s+name=([a-zA-Z0-9_\-]+)::(.*)",
        re.IGNORECASE,
    )

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []

        for idx, line in enumerate(lines):
            match = self.SET_ENV_REGEX.search(line)
            if match:
                var_name = match.group(1)
                issues.append(
                    self.create_issue(
                        message=f"Deprecated and vulnerable workflow command '::set-env name={var_name}::...'.",
                        file_path=file_path,
                        line=idx + 1,
                        column=match.start() + 1,
                        fixable=True,
                        suggestion=f'Replace with: echo "{var_name}=<value>" >> "$GITHUB_ENV"',
                        context_line=line.strip(),
                    )
                )

        return issues
