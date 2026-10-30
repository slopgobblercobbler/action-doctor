"""Unit tests for action-doctor scanner and discoverer."""

from pathlib import Path
import pytest

from action_doctor.config import Config
from action_doctor.scanner import (
    calculate_health_score,
    discover_workflows,
    extract_runners,
    parse_action_usage,
    scan_workflow,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_discover_workflows_fixtures():
    workflows = discover_workflows([FIXTURES_DIR])
    assert len(workflows) >= 5
    file_names = [f.name for f in workflows]
    assert "clean_workflow.yml" in file_names
    assert "deprecated_runner.yml" in file_names


def test_scan_clean_workflow():
    report = scan_workflow(FIXTURES_DIR / "clean_workflow.yml")
    assert report.valid_yaml is True
    assert report.score == 100.0
    assert report.grade == "A+"
    assert len(report.issues) == 0
    assert report.job_count == 1
    assert "ubuntu-latest" in report.runners_used
    assert len(report.actions_used) == 2
    assert all(a.is_sha for a in report.actions_used)


def test_scan_deprecated_runner_workflow():
    report = scan_workflow(FIXTURES_DIR / "deprecated_runner.yml")
    assert report.valid_yaml is True
    assert report.score < 100.0
    runner_issues = [i for i in report.issues if i.rule_id == "AD001"]
    assert len(runner_issues) >= 2


def test_scan_missing_permissions():
    report = scan_workflow(FIXTURES_DIR / "missing_permissions.yml")
    assert report.valid_yaml is True
    assert any(i.rule_id == "AD101" for i in report.issues)


def test_scan_unpinned_actions():
    report = scan_workflow(FIXTURES_DIR / "unpinned_action.yml")
    assert any(i.rule_id == "AD201" for i in report.issues)
    assert any(i.rule_id == "AD203" for i in report.issues)


def test_scan_invalid_yaml():
    report = scan_workflow(FIXTURES_DIR / "invalid_yaml.yml")
    assert report.valid_yaml is False
    assert report.score == 0.0
    assert report.grade == "F"
    assert len(report.issues) == 1
    assert report.issues[0].rule_id == "YAML_SYNTAX"


def test_scan_with_ignore_rules():
    cfg = Config(ignore_rules={"AD101", "AD401"})
    report = scan_workflow(FIXTURES_DIR / "missing_permissions.yml", config=cfg)
    assert not any(i.rule_id == "AD101" for i in report.issues)


def test_parse_action_usage_helper():
    usage = parse_action_usage("      - uses: actions/checkout@v4 # pinned", 10)
    assert usage is not None
    assert usage.action == "actions/checkout"
    assert usage.ref == "v4"
    assert usage.is_sha is False
    assert usage.pinned_comment == "pinned"

    # Local action should return None
    assert parse_action_usage("      - uses: ./.github/actions/local", 12) is None


def test_extract_runners_helper():
    parsed = {
        "jobs": {
            "test": {"runs-on": "ubuntu-22.04"},
            "matrix": {
                "runs-on": "${{ matrix.os }}",
                "strategy": {"matrix": {"os": ["windows-2022", "macos-14"]}},
            },
        }
    }
    runners = extract_runners(parsed)
    assert "ubuntu-22.04" in runners
    assert "windows-2022" in runners
    assert "macos-14" in runners
