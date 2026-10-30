"""Repository-wide GitHub Actions security and hygiene auditor."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from action_doctor.config import Config
from action_doctor.models import AuditSummary, Category, Severity, WorkflowReport
from action_doctor.scanner import discover_workflows, scan_workflow


def audit_repository(
    paths: Optional[List[str | Path]] = None,
    config: Optional[Config] = None,
    root_dir: Optional[Path] = None,
) -> AuditSummary:
    """Perform comprehensive repository-wide audit of all GitHub Actions workflows."""
    cfg = config or Config()
    root = root_dir or Path.cwd()

    workflow_files = discover_workflows(paths, root_dir=root)
    summary = AuditSummary(
        total_files=len(workflow_files),
        scanned_files=0,
    )

    actions_inv: Dict[str, Dict[str, Any]] = {}
    runners_inv: Dict[str, int] = {}
    category_penalties: Dict[str, float] = {
        Category.RUNNER.value: 0.0,
        Category.SECURITY.value: 0.0,
        Category.SUPPLY_CHAIN.value: 0.0,
        Category.SYNTAX.value: 0.0,
        Category.BEST_PRACTICE.value: 0.0,
    }

    reports: List[WorkflowReport] = []

    for wf_path in workflow_files:
        report = scan_workflow(wf_path, config=cfg)
        reports.append(report)
        summary.scanned_files += 1
        summary.total_issues += len(report.issues)
        summary.error_count += report.error_count
        summary.warning_count += report.warning_count
        summary.info_count += report.info_count
        summary.fixable_count += report.fixable_count

        # Inventory runners
        for runner in report.runners_used:
            runners_inv[runner] = runners_inv.get(runner, 0) + 1

        # Inventory actions
        rel_path = str(wf_path)
        try:
            rel_path = str(wf_path.relative_to(root))
        except ValueError:
            pass

        for usage in report.actions_used:
            act_name = usage.action
            if act_name not in actions_inv:
                actions_inv[act_name] = {
                    "total_usages": 0,
                    "pinned_usages": 0,
                    "unpinned_usages": 0,
                    "versions": set(),
                    "files": set(),
                }

            entry = actions_inv[act_name]
            entry["total_usages"] += 1
            if usage.is_sha:
                entry["pinned_usages"] += 1
            else:
                entry["unpinned_usages"] += 1
            entry["versions"].add(usage.ref)
            entry["files"].add(rel_path)

        # Track category penalties
        for issue in report.issues:
            weight = 15.0 if issue.severity == Severity.ERROR else (5.0 if issue.severity == Severity.WARNING else 1.0)
            cat_key = issue.category.value
            category_penalties[cat_key] = category_penalties.get(cat_key, 0.0) + weight

    # Convert sets to sorted lists in inventory
    cleaned_actions_inv: Dict[str, Dict[str, Any]] = {}
    for act_name, entry in sorted(actions_inv.items()):
        cleaned_actions_inv[act_name] = {
            "total_usages": entry["total_usages"],
            "pinned_usages": entry["pinned_usages"],
            "unpinned_usages": entry["unpinned_usages"],
            "pinned_percentage": round((entry["pinned_usages"] / entry["total_usages"]) * 100.0, 1) if entry["total_usages"] else 100.0,
            "versions": sorted(list(entry["versions"])),
            "files": sorted(list(entry["files"])),
        }

    # Calculate overall score and grade
    if summary.scanned_files > 0:
        avg_score = sum(r.score for r in reports) / len(reports)
    else:
        avg_score = 100.0

    summary.overall_score = avg_score
    if avg_score >= 95.0:
        summary.letter_grade = "A+"
    elif avg_score >= 85.0:
        summary.letter_grade = "A"
    elif avg_score >= 75.0:
        summary.letter_grade = "B"
    elif avg_score >= 65.0:
        summary.letter_grade = "C"
    elif avg_score >= 50.0:
        summary.letter_grade = "D"
    else:
        summary.letter_grade = "F"

    # Category health scores (normalized 0-100)
    category_scores: Dict[str, float] = {}
    for cat_name, penalty in category_penalties.items():
        cat_score = max(0.0, 100.0 - penalty)
        category_scores[cat_name] = cat_score

    summary.reports = reports
    summary.actions_inventory = cleaned_actions_inv
    summary.runners_inventory = dict(sorted(runners_inv.items(), key=lambda x: -x[1]))
    summary.category_scores = category_scores

    return summary
