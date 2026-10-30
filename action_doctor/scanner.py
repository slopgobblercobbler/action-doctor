"""Workflow YAML scanner and static analyzer."""

from __future__ import annotations

import glob
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from action_doctor.config import Config
from action_doctor.models import ActionUsage, Category, Issue, Severity, WorkflowReport
from action_doctor.rules import get_all_rules

SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def discover_workflows(paths: Optional[List[str | Path]] = None, root_dir: Optional[Path] = None) -> List[Path]:
    """Locate all GitHub Actions workflow files from specified paths or default patterns."""
    root = root_dir or Path.cwd()
    discovered: List[Path] = []
    seen: Set[Path] = set()

    if paths:
        for p in paths:
            p_str = str(p)
            if any(ch in p_str for ch in ("*", "?", "[", "]")):
                # Handle glob pattern safely without calling Path.is_file() on wildcards
                pattern_path = p_str if Path(p_str).is_absolute() else str(root / p_str)
                for match_str in glob.glob(pattern_path, recursive=True):
                    resolved = Path(match_str).resolve()
                    if resolved.is_file() and resolved not in seen:
                        seen.add(resolved)
                        discovered.append(resolved)
                continue

            path_obj = Path(p) if isinstance(p, (str, Path)) else Path(str(p))
            if not path_obj.is_absolute():
                path_obj = root / path_obj

            try:
                if path_obj.is_file():
                    resolved = path_obj.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        discovered.append(resolved)
                elif path_obj.is_dir():
                    for ext in ("*.yml", "*.yaml"):
                        for match in path_obj.rglob(ext):
                            resolved = match.resolve()
                            if resolved not in seen:
                                seen.add(resolved)
                                discovered.append(resolved)
            except OSError:
                pass
    else:
        # Default to standard GitHub Actions directory
        wf_dir = root / ".github" / "workflows"
        if wf_dir.exists():
            for ext in ("*.yml", "*.yaml"):
                for match in wf_dir.glob(ext):
                    resolved = match.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        discovered.append(resolved)

    return sorted(discovered)


def parse_action_usage(line: str, line_number: int) -> Optional[ActionUsage]:
    """Parse uses: step line into ActionUsage object."""
    uses_pattern = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^#\n\r]+?)(?:\s*#\s*(.*))?$")
    match = uses_pattern.match(line)
    if not match:
        return None

    raw_action = match.group(1).strip().strip("'\"")
    comment = (match.group(2) or "").strip()

    if raw_action.startswith("./") or raw_action.startswith("docker://"):
        return None

    if "@" not in raw_action:
        return None

    action_name, ref = raw_action.split("@", 1)
    is_sha = bool(SHA_PATTERN.match(ref.strip()))

    return ActionUsage(
        action=action_name.strip(),
        ref=ref.strip(),
        is_sha=is_sha,
        line=line_number,
        column=line.find(raw_action) + 1,
        pinned_comment=comment or None,
    )


def extract_runners(parsed_yaml: Any) -> List[str]:
    """Extract list of all runner labels referenced in the workflow."""
    runners: Set[str] = set()
    if not isinstance(parsed_yaml, dict):
        return []

    jobs = parsed_yaml.get("jobs", {})
    if isinstance(jobs, dict):
        for _, job in jobs.items():
            if isinstance(job, dict):
                runs_on = job.get("runs-on")
                if isinstance(runs_on, str):
                    runners.add(runs_on.strip())
                elif isinstance(runs_on, list):
                    for r in runs_on:
                        if isinstance(r, str):
                            runners.add(r.strip())
                # Check matrix
                strategy = job.get("strategy", {})
                if isinstance(strategy, dict):
                    matrix = strategy.get("matrix", {})
                    if isinstance(matrix, dict):
                        for key in ("os", "runner", "runs-on"):
                            vals = matrix.get(key)
                            if isinstance(vals, list):
                                for v in vals:
                                    if isinstance(v, str):
                                        runners.add(v.strip())

    return sorted(list(runners))


def calculate_health_score(issues: List[Issue]) -> tuple[float, str]:
    """Calculate health score (0-100) and letter grade."""
    score = 100.0
    for issue in issues:
        if issue.severity == Severity.ERROR:
            score -= 15.0
        elif issue.severity == Severity.WARNING:
            score -= 5.0
        elif issue.severity == Severity.INFO:
            score -= 1.0

    score = max(0.0, min(100.0, score))

    if score >= 95.0:
        grade = "A+"
    elif score >= 85.0:
        grade = "A"
    elif score >= 75.0:
        grade = "B"
    elif score >= 65.0:
        grade = "C"
    elif score >= 50.0:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def scan_workflow(file_path: Path, config: Optional[Config] = None) -> WorkflowReport:
    """Audit a single GitHub Actions workflow YAML file."""
    cfg = config or Config()
    report = WorkflowReport(file_path=file_path)

    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except Exception as e:
        report.valid_yaml = False
        report.error_message = f"Failed to read file: {e}"
        report.score = 0.0
        report.grade = "F"
        return report

    lines = raw_text.splitlines()

    # Parse YAML
    parsed_yaml: Any = None
    try:
        parsed_yaml = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        report.valid_yaml = False
        report.error_message = f"Invalid YAML: {exc}"
        line_num = getattr(exc, "problem_mark", None)
        line_idx = line_num.line + 1 if line_num else 1
        col_idx = line_num.column + 1 if line_num else 1
        syntax_issue = Issue(
            rule_id="YAML_SYNTAX",
            message=f"YAML parsing error: {exc}",
            file_path=file_path,
            line=line_idx,
            column=col_idx,
            severity=Severity.ERROR,
            category=Category.SYNTAX,
            fixable=False,
        )
        report.issues.append(syntax_issue)
        report.score = 0.0
        report.grade = "F"
        return report

    if not isinstance(parsed_yaml, dict):
        report.valid_yaml = True
        report.score = 100.0
        report.grade = "A+"
        return report

    # Extract metadata
    jobs = parsed_yaml.get("jobs", {})
    report.job_count = len(jobs) if isinstance(jobs, dict) else 0
    report.permissions_defined = "permissions" in parsed_yaml
    report.runners_used = extract_runners(parsed_yaml)

    # Extract action usages
    for idx, line in enumerate(lines):
        usage = parse_action_usage(line, idx + 1)
        if usage:
            report.actions_used.append(usage)

    # Run audit rules
    all_rules = get_all_rules()
    for rule in all_rules:
        if rule.rule_id.upper() in cfg.ignore_rules or rule.name.lower() in cfg.ignore_rules:
            continue

        try:
            detected = rule.check(file_path, raw_text, lines, parsed_yaml)
            report.issues.extend(detected)
        except Exception as e:
            # Catch rule execution issues gracefully
            continue

    # Sort issues by line then column
    report.issues.sort(key=lambda x: (x.line, x.column))

    # Calculate overall health score
    score, grade = calculate_health_score(report.issues)
    report.score = score
    report.grade = grade

    return report
