"""Output formatters for action-doctor: text, json, markdown, sarif, github."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from action_doctor.models import AuditSummary, Issue, Severity, WorkflowReport

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


def format_text(
    reports: List[WorkflowReport],
    summary: Optional[AuditSummary] = None,
    color: bool = True,
    root_dir: Optional[Path] = None,
) -> str:
    """Format reports and audit summary into human-readable terminal output."""
    root = root_dir or Path.cwd()
    out: List[str] = []

    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    total_issues = sum(len(r.issues) for r in reports)

    out.append("")
    out.append(c(BOLD + CYAN, "action-doctor") + c(DIM, " — GitHub Actions Workflow Health & Security Audit"))
    out.append("=" * 72)

    if not reports:
        out.append(c(YELLOW, "No workflow files discovered."))
        return "\n".join(out)

    for report in reports:
        try:
            rel_path = str(report.file_path.relative_to(root))
        except ValueError:
            rel_path = str(report.file_path)

        grade_color = GREEN if report.grade in ("A+", "A") else (YELLOW if report.grade in ("B", "C") else RED)
        status_line = f"\n{c(BOLD, rel_path)}  [{c(grade_color, f'Score: {report.score:.1f}% ({report.grade})')}]"
        out.append(status_line)
        out.append("-" * len(rel_path))

        if not report.valid_yaml:
            out.append(f"  {c(RED, '✖ FATAL:')} {report.error_message}")
            continue

        if not report.issues:
            out.append(f"  {c(GREEN, '✔ All checks passed!')} Clean security posture.")
            continue

        for issue in report.issues:
            if issue.severity == Severity.ERROR:
                sev_badge = c(RED + BOLD, "ERROR")
            elif issue.severity == Severity.WARNING:
                sev_badge = c(YELLOW + BOLD, "WARN ")
            else:
                sev_badge = c(CYAN, "INFO ")

            fix_tag = c(GREEN, " [fixable]") if issue.fixable else ""
            loc = f"{rel_path}:{issue.line}:{issue.column}"
            out.append(f"  {sev_badge} {c(DIM, loc)}  {c(BOLD, issue.rule_id)}: {issue.message}{fix_tag}")

            if issue.context_line:
                out.append(f"    {c(DIM, '>')} {issue.context_line}")

            if issue.suggestion:
                out.append(f"    {c(GREEN, '↳')} {issue.suggestion}")

    out.append("")
    out.append("=" * 72)

    # Summary section
    if summary:
        overall_grade_color = GREEN if summary.letter_grade in ("A+", "A") else (YELLOW if summary.letter_grade in ("B", "C") else RED)
        out.append(
            f"Overall Grade: {c(overall_grade_color + BOLD, f'{summary.letter_grade} ({summary.overall_score:.1f}%)')}  |  "
            f"Workflows: {summary.scanned_files}  |  "
            f"Issues: {total_issues} "
            f"({c(RED, str(summary.error_count))} errors, "
            f"{c(YELLOW, str(summary.warning_count))} warnings, "
            f"{c(CYAN, str(summary.info_count))} info)"
        )

        if summary.actions_inventory:
            out.append("")
            out.append(c(BOLD, "Action Inventory:"))
            for act_name, entry in summary.actions_inventory.items():
                pin_pct = entry["pinned_percentage"]
                pct_col = GREEN if pin_pct >= 100.0 else (YELLOW if pin_pct >= 50.0 else RED)
                vers = ", ".join(entry["versions"][:3])
                out.append(f"  • {c(CYAN, act_name)} ({vers}) — {c(pct_col, f'{pin_pct:.0f}% pinned')} ({entry['pinned_usages']}/{entry['total_usages']})")
    else:
        errs = sum(r.error_count for r in reports)
        warns = sum(r.warning_count for r in reports)
        infos = sum(r.info_count for r in reports)
        out.append(
            f"Scanned {len(reports)} workflows: {total_issues} issues found "
            f"({c(RED, str(errs))} errors, {c(YELLOW, str(warns))} warnings, {c(CYAN, str(infos))} info)"
        )

    out.append("")
    return "\n".join(out)


def format_json(reports: List[WorkflowReport], summary: Optional[AuditSummary] = None) -> str:
    """Format results as JSON."""
    if summary:
        return json.dumps(summary.to_dict(), indent=2)
    return json.dumps([r.to_dict() for r in reports], indent=2)


def format_markdown(reports: List[WorkflowReport], summary: Optional[AuditSummary] = None) -> str:
    """Format results as clean Markdown (ideal for PR comments or GITHUB_STEP_SUMMARY)."""
    lines: List[str] = []
    lines.append("# 🩺 Action Doctor Audit Report\n")

    if summary:
        lines.append(f"### Repository Health Score: **{summary.letter_grade}** ({summary.overall_score:.1f}%)\n")
        lines.append("| Metric | Value |")
        lines.append("| :--- | :--- |")
        lines.append(f"| 📁 Workflows Scanned | {summary.scanned_files} |")
        lines.append(f"| 🚨 Total Issues | {summary.total_issues} |")
        lines.append(f"| 🛑 Errors | {summary.error_count} |")
        lines.append(f"| ⚠️ Warnings | {summary.warning_count} |")
        lines.append(f"| ℹ️ Info | {summary.info_count} |")
        lines.append(f"| 🔧 Fixable Automatically | {summary.fixable_count} |\n")

        # Category scores
        if summary.category_scores:
            lines.append("### Category Breakdown\n")
            lines.append("| Category | Score |")
            lines.append("| :--- | :--- |")
            for cat, score in summary.category_scores.items():
                emoji = "🟢" if score >= 85 else ("🟡" if score >= 60 else "🔴")
                lines.append(f"| {cat.title()} | {emoji} {score:.1f}% |")
            lines.append("")

    lines.append("## Workflow Diagnostics\n")
    for report in reports:
        lines.append(f"### `{report.file_path.name}` — Score: **{report.grade}** ({report.score:.1f}%)\n")
        if not report.issues:
            lines.append("✅ No issues detected. Clean security posture.\n")
            continue

        lines.append("| Severity | Rule | Location | Description | Fixable |")
        lines.append("| :---: | :--- | :--- | :--- | :---: |")
        for issue in report.issues:
            sev_badge = "🔴 Error" if issue.severity == Severity.ERROR else ("🟡 Warning" if issue.severity == Severity.WARNING else "ℹ️ Info")
            fix_str = "✅ Yes" if issue.fixable else "❌ No"
            lines.append(f"| {sev_badge} | `{issue.rule_id}` | L{issue.line}:{issue.column} | {issue.message} | {fix_str} |")
        lines.append("")

    return "\n".join(lines)


def format_github(reports: List[WorkflowReport]) -> str:
    """Format issues as GitHub Actions workflow log commands (annotations)."""
    commands: List[str] = []
    for report in reports:
        for issue in report.issues:
            cmd = "error" if issue.severity == Severity.ERROR else ("warning" if issue.severity == Severity.WARNING else "notice")
            commands.append(
                f"::{cmd} file={report.file_path},line={issue.line},col={issue.column},title={issue.rule_id}::{issue.message}"
            )
    return "\n".join(commands)


def format_sarif(reports: List[WorkflowReport]) -> str:
    """Format issues in OASIS standard SARIF v2.1.0 format."""
    rules_dict = {}
    results = []

    for report in reports:
        for issue in report.issues:
            if issue.rule_id not in rules_dict:
                rules_dict[issue.rule_id] = {
                    "id": issue.rule_id,
                    "shortDescription": {"text": issue.message.split(".")[0]},
                    "defaultConfiguration": {
                        "level": "error" if issue.severity == Severity.ERROR else ("warning" if issue.severity == Severity.WARNING else "note")
                    },
                }

            level = "error" if issue.severity == Severity.ERROR else ("warning" if issue.severity == Severity.WARNING else "note")
            results.append({
                "ruleId": issue.rule_id,
                "level": level,
                "message": {"text": issue.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(report.file_path).replace("\\", "/")},
                            "region": {
                                "startLine": issue.line,
                                "startColumn": issue.column,
                            },
                        }
                    }
                ],
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "action-doctor",
                        "informationUri": "https://github.com/slopggobblercobbler81/action-doctor",
                        "semanticVersion": "0.1.0",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2)
