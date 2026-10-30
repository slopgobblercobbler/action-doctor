"""Security and permissions audit rules for action-doctor."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List

from action_doctor.models import Category, Issue, Severity
from action_doctor.rules.base import Rule


class MissingPermissionsRule(Rule):
    rule_id = "AD101"
    name = "missing-permissions"
    category = Category.SECURITY
    severity = Severity.ERROR
    description = "Workflows must define an explicit permissions block to enforce least-privilege token access."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        if not isinstance(parsed_yaml, dict):
            return issues

        # Check if top-level permissions exist
        has_top_level_perms = "permissions" in parsed_yaml

        jobs = parsed_yaml.get("jobs", {})
        if not isinstance(jobs, dict):
            return issues

        if not has_top_level_perms:
            # Check if all jobs define permissions
            jobs_missing_perms: List[str] = []
            for job_id, job in jobs.items():
                if isinstance(job, dict) and "permissions" not in job:
                    jobs_missing_perms.append(job_id)

            if jobs_missing_perms:
                issues.append(
                    self.create_issue(
                        message=f"Missing explicit 'permissions' block at top level or in jobs: {', '.join(jobs_missing_perms)}. Defaults may grant full write access.",
                        file_path=file_path,
                        line=1,
                        column=1,
                        fixable=True,
                        suggestion="Add top-level 'permissions: contents: read' or job-level scopes.",
                    )
                )

        return issues


class ExcessivePermissionsRule(Rule):
    rule_id = "AD102"
    name = "excessive-permissions"
    category = Category.SECURITY
    severity = Severity.WARNING
    description = "Detects overly permissive permissions such as 'write-all'."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []

        # Look for 'permissions:\s*write-all'
        pattern = re.compile(r"permissions\s*:\s*write-all\b", re.IGNORECASE)
        for idx, line in enumerate(lines):
            match = pattern.search(line)
            if match:
                issues.append(
                    self.create_issue(
                        message="'permissions: write-all' grants broad write access to repository and packages.",
                        file_path=file_path,
                        line=idx + 1,
                        column=match.start() + 1,
                        fixable=True,
                        suggestion="Specify granular scopes such as 'contents: read', 'issues: write', etc.",
                        context_line=line.strip(),
                    )
                )

        return issues


class InsecurePullRequestTargetRule(Rule):
    rule_id = "AD103"
    name = "insecure-pull-request-target"
    category = Category.SECURITY
    severity = Severity.ERROR
    description = "Detects dangerous checkout of untrusted PR branch code in 'pull_request_target' workflows."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        if not isinstance(parsed_yaml, dict):
            return issues

        # Check triggers
        on_trigger = parsed_yaml.get("on")
        if on_trigger is None and True in parsed_yaml:
            on_trigger = parsed_yaml.get(True)
        has_pr_target = False
        if isinstance(on_trigger, str) and on_trigger == "pull_request_target":
            has_pr_target = True
        elif isinstance(on_trigger, list) and "pull_request_target" in on_trigger:
            has_pr_target = True
        elif isinstance(on_trigger, dict) and "pull_request_target" in on_trigger:
            has_pr_target = True

        if not has_pr_target:
            return issues

        # Check for checkout with untrusted ref
        pwn_pattern = re.compile(
            r"ref:\s*(\${{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*}})",
            re.IGNORECASE,
        )

        for idx, line in enumerate(lines):
            match = pwn_pattern.search(line)
            if match:
                issues.append(
                    self.create_issue(
                        message="Critical security vulnerability: checking out untrusted pull_request_target head code with privileged repository token ('Pwn Request').",
                        file_path=file_path,
                        line=idx + 1,
                        column=match.start() + 1,
                        fixable=False,
                        suggestion="Switch event to 'pull_request' or run untrusted code in an unprivileged separate workflow.",
                        context_line=line.strip(),
                    )
                )

        return issues


class ScriptInjectionRule(Rule):
    rule_id = "AD104"
    name = "script-injection"
    category = Category.SECURITY
    severity = Severity.ERROR
    description = "Detects untrusted GitHub context expressions interpolated directly into shell 'run:' commands."

    DANGEROUS_EXPRESSIONS = [
        r"github\.event\.issue\.title",
        r"github\.event\.issue\.body",
        r"github\.event\.pull_request\.title",
        r"github\.event\.pull_request\.body",
        r"github\.event\.comment\.body",
        r"github\.event\.review\.body",
        r"github\.event\.commits\[.*\]\.message",
        r"github\.head_ref",
    ]

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        combined_pattern = re.compile(
            r"\${{\s*(" + "|".join(self.DANGEROUS_EXPRESSIONS) + r")\s*}}",
            re.IGNORECASE,
        )

        in_run_block = False
        run_indent = 0

        for idx, line in enumerate(lines):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            # Detect run: key
            if re.match(r"^\s*(?:-\s*)?run\s*:", line):
                in_run_block = True
                run_indent = indent
                match = combined_pattern.search(line)
                if match:
                    issues.append(
                        self._make_injection_issue(file_path, idx + 1, match.group(0), line)
                    )
                continue

            if in_run_block:
                if stripped and indent <= run_indent and not stripped.startswith("#"):
                    in_run_block = False
                else:
                    match = combined_pattern.search(line)
                    if match:
                        issues.append(
                            self._make_injection_issue(file_path, idx + 1, match.group(0), line)
                        )

        return issues

    def _make_injection_issue(
        self, file_path: Path, line_num: int, expr: str, line_str: str
    ) -> Issue:
        return self.create_issue(
            message=f"Possible command injection: untrusted expression '{expr}' directly interpolated in shell script.",
            file_path=file_path,
            line=line_num,
            column=1,
            fixable=False,
            suggestion="Pass the value via 'env:' block and reference as environment variable.",
            context_line=line_str.strip(),
        )


class PlaintextSecretInRunRule(Rule):
    rule_id = "AD105"
    name = "plaintext-secret-run"
    category = Category.SECURITY
    severity = Severity.WARNING
    description = "Detects secret expressions passed directly inside inline run script commands."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        secret_pattern = re.compile(r"\${{\s*secrets\.[A-Za-z0-9_]+\s*}}")

        in_run = False
        run_indent = 0

        for idx, line in enumerate(lines):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            if re.match(r"^\s*(?:-\s*)?run\s*:", line):
                in_run = True
                run_indent = indent
                match = secret_pattern.search(line)
                if match:
                    issues.append(
                        self.create_issue(
                            message=f"Secret '{match.group(0)}' referenced directly in run step. May be exposed in command line arguments or traces.",
                            file_path=file_path,
                            line=idx + 1,
                            column=match.start() + 1,
                            fixable=False,
                            suggestion="Map secret to an environment variable in 'env:' instead.",
                            context_line=line.strip(),
                        )
                    )
                continue

            if in_run:
                if stripped and indent <= run_indent and not stripped.startswith("#"):
                    in_run = False
                else:
                    match = secret_pattern.search(line)
                    if match:
                        issues.append(
                            self.create_issue(
                                message=f"Secret '{match.group(0)}' referenced directly in script body.",
                                file_path=file_path,
                                line=idx + 1,
                                column=match.start() + 1,
                                fixable=False,
                                suggestion="Pass secret via 'env:' to prevent process table / execution leakage.",
                                context_line=line.strip(),
                            )
                        )

        return issues
