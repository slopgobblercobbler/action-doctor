"""Runner audit rules for action-doctor."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List

from action_doctor.data.runner_matrix import DEPRECATED_RUNNERS
from action_doctor.models import Category, Issue, Severity
from action_doctor.rules.base import Rule


class DeprecatedRunnerRule(Rule):
    rule_id = "AD001"
    name = "deprecated-runner"
    category = Category.RUNNER
    severity = Severity.ERROR
    description = "Detects deprecated or removed GitHub Actions runner OS images."

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

        jobs = parsed_yaml.get("jobs", {})
        if not isinstance(jobs, dict):
            return issues

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue

            # 1. Check direct runs-on
            runs_on = job.get("runs-on")
            runner_items: List[str] = []
            if isinstance(runs_on, str):
                runner_items.append(runs_on.strip())
            elif isinstance(runs_on, list):
                for item in runs_on:
                    if isinstance(item, str):
                        runner_items.append(item.strip())

            for runner in runner_items:
                if runner in DEPRECATED_RUNNERS:
                    info = DEPRECATED_RUNNERS[runner]
                    line_num, col_num, line_str = self._find_runner_line(lines, runner, job_id)
                    issues.append(
                        self.create_issue(
                            message=f"Job '{job_id}' uses deprecated runner '{runner}'. {info['reason']}",
                            file_path=file_path,
                            line=line_num,
                            column=col_num,
                            fixable=True,
                            suggestion=f"Migrate to '{info['replacement']}' or 'ubuntu-latest'/'windows-latest'/'macos-latest'",
                            context_line=line_str,
                        )
                    )

            # 2. Check matrix strategy
            strategy = job.get("strategy", {})
            if isinstance(strategy, dict):
                matrix = strategy.get("matrix", {})
                if isinstance(matrix, dict):
                    self._check_matrix(matrix, job_id, file_path, lines, issues)

        return issues

    def _check_matrix(
        self,
        matrix: dict,
        job_id: str,
        file_path: Path,
        lines: List[str],
        issues: List[Issue],
    ) -> None:
        for key, vals in matrix.items():
            if isinstance(vals, list):
                for val in vals:
                    if isinstance(val, str) and val in DEPRECATED_RUNNERS:
                        info = DEPRECATED_RUNNERS[val]
                        line_num, col_num, line_str = self._find_runner_line(lines, val, job_id)
                        issues.append(
                            self.create_issue(
                                message=f"Matrix in job '{job_id}' contains deprecated runner '{val}'. {info['reason']}",
                                file_path=file_path,
                                line=line_num,
                                column=col_num,
                                fixable=True,
                                suggestion=f"Replace '{val}' with '{info['replacement']}' in matrix.{key}",
                                context_line=line_str,
                            )
                        )

    def _find_runner_line(
        self, lines: List[str], runner: str, job_id: str
    ) -> tuple[int, int, str]:
        escaped_runner = re.escape(runner)
        for idx, line in enumerate(lines):
            match = re.search(r"\b" + escaped_runner + r"\b", line)
            if match:
                return idx + 1, match.start() + 1, line.strip()
        return 1, 1, ""


class DeprecatedNodeRuntimeRule(Rule):
    rule_id = "AD002"
    name = "deprecated-node-runtime"
    category = Category.RUNNER
    severity = Severity.WARNING
    description = "Detects workarounds forcing deprecated Node.js 12 or 16 runtimes in GitHub Actions."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []

        # Check for ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION
        env_pattern = re.compile(r"ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION", re.IGNORECASE)
        for idx, line in enumerate(lines):
            if env_pattern.search(line):
                issues.append(
                    self.create_issue(
                        message="ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION is set. Workaround forces insecure Node runtimes which are removed in modern runners.",
                        file_path=file_path,
                        line=idx + 1,
                        column=1,
                        fixable=False,
                        suggestion="Upgrade actions to versions supporting Node 20+ and remove this environment variable.",
                        context_line=line.strip(),
                    )
                )

        return issues


class LegacyMacRunnerRule(Rule):
    rule_id = "AD003"
    name = "legacy-mac-runner"
    category = Category.RUNNER
    severity = Severity.WARNING
    description = "Detects legacy x86_64 macOS runners slated for removal."

    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        issues: List[Issue] = []
        legacy_macs = {"macos-11", "macos-12"}

        for idx, line in enumerate(lines):
            for mac in legacy_macs:
                if re.search(r"\b" + re.escape(mac) + r"\b", line):
                    issues.append(
                        self.create_issue(
                            message=f"Legacy Intel macOS runner '{mac}' detected. GitHub has transitioned macOS runners to Apple Silicon (M1/M2).",
                            file_path=file_path,
                            line=idx + 1,
                            column=1,
                            fixable=True,
                            suggestion="Upgrade to 'macos-14' (Apple Silicon) or 'macos-latest'.",
                            context_line=line.strip(),
                        )
                    )

        return issues
