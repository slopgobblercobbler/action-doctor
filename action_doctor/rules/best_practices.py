"""Best practices and reliability audit rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List

from action_doctor.models import Category, Issue, Severity
from action_doctor.rules.base import Rule


class MissingJobTimeoutRule(Rule):
    rule_id = "AD401"
    name = "missing-job-timeout"
    category = Category.BEST_PRACTICE
    severity = Severity.WARNING
    description = "Jobs should define 'timeout-minutes' to prevent hanging builds from exhausting runner quotas."

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

            if "timeout-minutes" not in job:
                # Find line number for job definition
                line_num = 1
                job_pattern = re.compile(r"^\s*" + re.escape(job_id) + r"\s*:\s*$")
                for idx, line in enumerate(lines):
                    if job_pattern.match(line):
                        line_num = idx + 1
                        break

                issues.append(
                    self.create_issue(
                        message=f"Job '{job_id}' does not specify 'timeout-minutes'. Default timeout is 360 minutes (6 hours).",
                        file_path=file_path,
                        line=line_num,
                        column=1,
                        fixable=True,
                        suggestion="Add 'timeout-minutes: 60' to limit execution time.",
                    )
                )

        return issues


class MissingStepNameRule(Rule):
    rule_id = "AD402"
    name = "missing-step-name"
    category = Category.BEST_PRACTICE
    severity = Severity.INFO
    description = "Steps should have a descriptive 'name' property for easier debugging and CI log clarity."

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

            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue

            for s_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "name" not in step:
                    # Anonymous step
                    uses_or_run = step.get("uses") or step.get("run", "")
                    short_desc = (
                        uses_or_run.split("\n")[0][:40]
                        if isinstance(uses_or_run, str)
                        else f"step #{s_idx + 1}"
                    )
                    issues.append(
                        self.create_issue(
                            message=f"Step #{s_idx + 1} in job '{job_id}' is missing a descriptive 'name' ({short_desc}).",
                            file_path=file_path,
                            line=1,
                            column=1,
                            fixable=False,
                            suggestion=f"Add 'name: <description>' to step in job '{job_id}'.",
                        )
                    )

        return issues


class MissingFailFastRule(Rule):
    rule_id = "AD403"
    name = "missing-fail-fast"
    category = Category.BEST_PRACTICE
    severity = Severity.INFO
    description = "Matrix jobs should explicitly declare 'strategy.fail-fast'."

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

            strategy = job.get("strategy")
            if isinstance(strategy, dict) and "matrix" in strategy:
                if "fail-fast" not in strategy:
                    issues.append(
                        self.create_issue(
                            message=f"Job '{job_id}' has a matrix strategy without explicit 'fail-fast'. Default is true (cancels all jobs on first failure).",
                            file_path=file_path,
                            line=1,
                            column=1,
                            fixable=True,
                            suggestion="Add 'fail-fast: false' under strategy to let all matrix jobs complete.",
                        )
                    )

        return issues
