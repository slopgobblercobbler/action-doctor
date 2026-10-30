"""Command Line Interface for action-doctor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from action_doctor.auditor import audit_repository
from action_doctor.config import Config
from action_doctor.fixer import fix_workflow
from action_doctor.formatter import (
    format_github,
    format_json,
    format_markdown,
    format_sarif,
    format_text,
)
from action_doctor.models import Severity
from action_doctor.scanner import discover_workflows, scan_workflow

__version__ = "0.1.0"


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="action-doctor",
        description="action-doctor: Audit, diagnose, and auto-fix GitHub Actions workflow YAML files.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: check
    check_parser = subparsers.add_parser(
        "check",
        help="Audit workflow files for deprecations, security risks, and unpinned actions.",
    )
    check_parser.add_argument(
        "paths",
        nargs="*",
        help="Workflow files or directories to check (default: .github/workflows/*.yml).",
    )
    check_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "markdown", "sarif", "github"],
        default="text",
        help="Output format (default: text).",
    )
    check_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write output to specified file.",
    )
    check_parser.add_argument(
        "--fail-on",
        choices=["error", "warning", "info"],
        default="error",
        help="Severity threshold causing non-zero exit code (default: error).",
    )
    check_parser.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode: exit with failure on any warning or error.",
    )
    check_parser.add_argument(
        "--ignore-rules",
        help="Comma-separated list of rule IDs to ignore (e.g. AD001,AD401).",
    )
    check_parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to custom config file.",
    )
    check_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )

    # Command: fix
    fix_parser = subparsers.add_parser(
        "fix",
        help="Automatically fix deprecated runners, unpinned action SHAs, missing permissions, and syntax.",
    )
    fix_parser.add_argument(
        "paths",
        nargs="*",
        help="Workflow files or directories to fix (default: .github/workflows/*.yml).",
    )
    fix_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview fixes without modifying files on disk.",
    )
    fix_parser.add_argument(
        "--rules",
        help="Comma-separated list of specific rule IDs to fix (e.g. AD001,AD101).",
    )
    fix_parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to custom config file.",
    )
    fix_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )

    # Command: audit
    audit_parser = subparsers.add_parser(
        "audit",
        help="Generate repository-wide security health score, action inventory, and compliance report.",
    )
    audit_parser.add_argument(
        "paths",
        nargs="*",
        help="Workflow files or directories to audit (default: .github/workflows/*.yml).",
    )
    audit_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "markdown", "sarif", "github"],
        default="text",
        help="Output format (default: text).",
    )
    audit_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write report to specified file.",
    )
    audit_parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum required overall score (0-100); fails if repository score is below threshold.",
    )
    audit_parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to custom config file.",
    )
    audit_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )

    return parser


def handle_check(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    if args.ignore_rules:
        for r in args.ignore_rules.split(","):
            config.ignore_rules.add(r.strip().upper())
    if args.strict:
        config.strict = True
        config.fail_on = Severity.WARNING
    elif args.fail_on:
        config.fail_on = Severity(args.fail_on)

    files = discover_workflows(args.paths if args.paths else None)
    if not files:
        msg = "No GitHub Actions workflows found.\n"
        sys.stderr.write(msg)
        return 0

    reports = [scan_workflow(f, config=config) for f in files]

    # Render format
    fmt = args.format
    color = not args.no_color and sys.stdout.isatty()

    if fmt == "json":
        output_str = format_json(reports)
    elif fmt == "markdown":
        output_str = format_markdown(reports)
    elif fmt == "sarif":
        output_str = format_sarif(reports)
    elif fmt == "github":
        output_str = format_github(reports)
    else:
        output_str = format_text(reports, color=color)

    if args.output:
        args.output.write_text(output_str, encoding="utf-8")
    else:
        print(output_str)

    # Determine exit code based on fail_on threshold
    fail = False
    for r in reports:
        if not r.valid_yaml:
            fail = True
            break
        for issue in r.issues:
            if config.fail_on == Severity.INFO:
                fail = True
                break
            elif config.fail_on == Severity.WARNING and issue.severity in (Severity.WARNING, Severity.ERROR):
                fail = True
                break
            elif config.fail_on == Severity.ERROR and issue.severity == Severity.ERROR:
                fail = True
                break
        if fail:
            break

    return 1 if fail else 0


def handle_fix(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    allowed_rules = None
    if args.rules:
        allowed_rules = {r.strip().upper() for r in args.rules.split(",") if r.strip()}

    files = discover_workflows(args.paths if args.paths else None)
    if not files:
        sys.stderr.write("No workflow files found to fix.\n")
        return 0

    total_fixed_files = 0
    total_fixes_count = 0

    prefix = "[DRY-RUN] " if args.dry_run else ""
    color = not args.no_color

    for f in files:
        result = fix_workflow(f, config=config, allowed_rules=allowed_rules, dry_run=args.dry_run)
        if result.fixes_applied:
            total_fixed_files += 1
            total_fixes_count += result.fixed_count
            print(f"{prefix}Fixed {f.name}:")
            for fix_item in result.fixes_applied:
                print(f"  ✔ {fix_item}")

    if total_fixes_count == 0:
        print(f"{prefix}All workflows are already compliant. No fixes needed.")
    else:
        action_word = "Would apply" if args.dry_run else "Successfully applied"
        print(f"\n{prefix}{action_word} {total_fixes_count} fixes across {total_fixed_files} file(s).")

    return 0


def handle_audit(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    summary = audit_repository(args.paths if args.paths else None, config=config)

    fmt = args.format
    color = not args.no_color and sys.stdout.isatty()

    if fmt == "json":
        output_str = format_json(summary.reports, summary=summary)
    elif fmt == "markdown":
        output_str = format_markdown(summary.reports, summary=summary)
    elif fmt == "sarif":
        output_str = format_sarif(summary.reports)
    elif fmt == "github":
        output_str = format_github(summary.reports)
    else:
        output_str = format_text(summary.reports, summary=summary, color=color)

    if args.output:
        args.output.write_text(output_str, encoding="utf-8")
    else:
        print(output_str)

    if args.min_score > 0 and summary.overall_score < args.min_score:
        sys.stderr.write(
            f"\nAudit failed: Score {summary.overall_score:.1f}% is below required minimum {args.min_score:.1f}%\n"
        )
        return 1

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "check":
        return handle_check(args)
    elif args.command == "fix":
        return handle_fix(args)
    elif args.command == "audit":
        return handle_audit(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
