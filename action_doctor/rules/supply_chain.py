"""Supply chain and action pinning audit rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List

from action_doctor.data.known_actions import DEPRECATED_ACTION_VERSIONS, get_action_pin
from action_doctor.models import Category, Issue, Severity
from action_doctor.rules.base import Rule

SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
MUTABLE_BRANCHES = {"main", "master", "dev", "develop", "latest", "head", "trunk"}


class UnpinnedActionShaRule(Rule):
    rule_id = "AD201"
    name = "unpinned-action-sha"
    category = Category.SUPPLY_CHAIN
    severity = Severity.WARNING
    description = "Actions should be pinned to full 40-character commit SHA to prevent supply-chain poisoning."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        uses_pattern = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^#\n\r]+?)(?:\s*#\s*(.*))?$")

        for idx, line in enumerate(lines):
            match = uses_pattern.match(line)
            if not match:
                continue

            action_ref_full = match.group(1).strip().strip("'\"")
            comment = (match.group(2) or "").strip()

            # Skip local actions and docker images
            if action_ref_full.startswith("./") or action_ref_full.startswith("docker://"):
                continue

            if "@" not in action_ref_full:
                continue

            action_name, ref = action_ref_full.split("@", 1)
            action_name = action_name.strip()
            ref = ref.strip()

            if not SHA_PATTERN.match(ref):
                pin = get_action_pin(action_name, ref)
                fixable = pin is not None
                suggestion = (
                    f"Pin to SHA: '{action_name}@{pin[0]} # {pin[1]}'"
                    if pin
                    else f"Pin '{action_name}' to its immutable 40-character commit SHA"
                )

                issues.append(
                    self.create_issue(
                        message=f"Action '{action_name}@{ref}' is not pinned to a commit SHA. Mutable tags are vulnerable to tag hijacking.",
                        file_path=file_path,
                        line=idx + 1,
                        column=line.find(action_ref_full) + 1,
                        fixable=fixable,
                        suggestion=suggestion,
                        context_line=line.strip(),
                    )
                )

        return issues


class MutableBranchRefRule(Rule):
    rule_id = "AD202"
    name = "mutable-branch-ref"
    category = Category.SUPPLY_CHAIN
    severity = Severity.ERROR
    description = "Detects actions referencing mutable branches (e.g. @main, @master, @latest)."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        uses_pattern = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^#\n\r]+?)(?:\s*#.*)?$")

        for idx, line in enumerate(lines):
            match = uses_pattern.match(line)
            if not match:
                continue

            action_ref_full = match.group(1).strip().strip("'\"")
            if "@" not in action_ref_full:
                continue

            action_name, ref = action_ref_full.split("@", 1)
            ref_lower = ref.strip().lower()

            if ref_lower in MUTABLE_BRANCHES:
                issues.append(
                    self.create_issue(
                        message=f"Action '{action_name}' references mutable branch '@{ref}'. Branch HEAD can change anytime without notice.",
                        file_path=file_path,
                        line=idx + 1,
                        column=line.find(ref) + 1,
                        fixable=False,
                        suggestion="Pin to a specific release commit SHA or tag.",
                        context_line=line.strip(),
                    )
                )

        return issues


class DeprecatedActionVersionRule(Rule):
    rule_id = "AD203"
    name = "deprecated-action-version"
    category = Category.SUPPLY_CHAIN
    severity = Severity.WARNING
    description = "Detects deprecated or sunset action versions (such as upload-artifact@v3 or node12 actions)."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        uses_pattern = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^#\n\r]+?)(?:\s*#\s*(.*))?$")

        for idx, line in enumerate(lines):
            match = uses_pattern.match(line)
            if not match:
                continue

            action_ref_full = match.group(1).strip().strip("'\"")
            comment = (match.group(2) or "").strip()

            if "@" not in action_ref_full:
                continue

            action_name, ref = action_ref_full.split("@", 1)
            action_name = action_name.strip()
            ref = ref.strip()

            # Check if SHA with comment tag
            target_ref = ref
            if SHA_PATTERN.match(ref) and comment.startswith("v"):
                target_ref = comment.split()[0]

            key = f"{action_name}@{target_ref}"
            # Also check prefix if patch version like actions/checkout@v2.3.4 -> v2
            found_dep = None
            if key in DEPRECATED_ACTION_VERSIONS:
                found_dep = DEPRECATED_ACTION_VERSIONS[key]
            else:
                major_key = f"{action_name}@{target_ref.split('.')[0]}"
                if major_key in DEPRECATED_ACTION_VERSIONS:
                    found_dep = DEPRECATED_ACTION_VERSIONS[major_key]

            if found_dep:
                rec_version, reason = found_dep
                issues.append(
                    self.create_issue(
                        message=f"Action '{action_name}@{target_ref}' is deprecated: {reason}",
                        file_path=file_path,
                        line=idx + 1,
                        column=line.find(action_ref_full) + 1,
                        fixable=True,
                        suggestion=f"Upgrade '{action_name}' to '{rec_version}'",
                        context_line=line.strip(),
                    )
                )

        return issues
