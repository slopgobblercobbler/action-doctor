"""Extended unit tests covering edge cases, CLI combinations, formatters, and models."""

from pathlib import Path
import json
import pytest
import shutil

from action_doctor.cli import main
from action_doctor.config import Config
from action_doctor.data.known_actions import get_action_pin
from action_doctor.fixer import WorkflowFixer, fix_workflow
from action_doctor.models import (
    ActionUsage,
    AuditSummary,
    Category,
    FixResult,
    Issue,
    Severity,
    WorkflowReport,
)
from action_doctor.scanner import (
    calculate_health_score,
    discover_workflows,
    scan_workflow,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# =========================================================================
# 1. Models and Serialization
# =========================================================================

def test_models_to_dict():
    issue = Issue(
        rule_id="AD001",
        message="Deprecated runner",
        file_path=Path("test.yml"),
        line=10,
        column=5,
        severity=Severity.ERROR,
        category=Category.RUNNER,
        fixable=True,
        suggestion="Use ubuntu-22.04",
        context_line="runs-on: ubuntu-18.04",
    )
    issue_dict = issue.to_dict()
    assert issue_dict["rule_id"] == "AD001"
    assert issue_dict["severity"] == "error"
    assert issue_dict["category"] == "runner"
    assert issue_dict["fixable"] is True
    assert issue_dict["context_line"] == "runs-on: ubuntu-18.04"

    usage = ActionUsage(
        action="actions/checkout",
        ref="11bd71901bbe5b1630ceea73d27597364c9af683",
        is_sha=True,
        line=15,
        column=7,
        pinned_comment="v4.2.2",
    )
    assert usage.full_reference == "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    usage_dict = usage.to_dict()
    assert usage_dict["full_reference"] == usage.full_reference
    assert usage_dict["is_sha"] is True
    assert usage_dict["pinned_comment"] == "v4.2.2"

    fix_res = FixResult(
        file_path=Path("wf.yml"),
        fixed_count=2,
        fixes_applied=["Fixed AD001", "Fixed AD101"],
        content_changed=True,
    )
    fix_dict = fix_res.to_dict()
    assert fix_dict["fixed_count"] == 2
    assert fix_dict["content_changed"] is True

    report = WorkflowReport(
        file_path=Path("wf.yml"),
        issues=[issue],
        actions_used=[usage],
        runners_used=["ubuntu-22.04"],
    )
    assert report.error_count == 1
    assert report.warning_count == 0
    assert report.info_count == 0
    assert report.fixable_count == 1
    rep_dict = report.to_dict()
    assert rep_dict["error_count"] == 1
    assert len(rep_dict["issues"]) == 1

    summary = AuditSummary(
        total_files=1,
        scanned_files=1,
        total_issues=1,
        error_count=1,
        reports=[report],
        category_scores={"runner": 85.0},
    )
    sum_dict = summary.to_dict()
    assert sum_dict["overall_score"] == 100.0
    assert sum_dict["category_scores"]["runner"] == 85.0


# =========================================================================
# 2. Scanner and Health Scoring Edge Cases
# =========================================================================

def test_calculate_health_score_grades():
    # A+ (>= 95)
    s, g = calculate_health_score([])
    assert s == 100.0 and g == "A+"

    # A (85 - 94)
    s, g = calculate_health_score([
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.WARNING),
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.WARNING),
    ])
    assert s == 90.0 and g == "A"

    # B (75 - 84)
    s, g = calculate_health_score([
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.ERROR),
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.WARNING),
    ])
    assert s == 80.0 and g == "B"

    # C (65 - 74)
    s, g = calculate_health_score([
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.ERROR),
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.ERROR),
    ])
    assert s == 70.0 and g == "C"

    # D (50 - 64)
    s, g = calculate_health_score([
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.ERROR)
        for _ in range(3)
    ])
    assert s == 55.0 and g == "D"

    # F (< 50)
    s, g = calculate_health_score([
        Issue(rule_id="X", message="m", file_path=Path("f"), severity=Severity.ERROR)
        for _ in range(8)
    ])
    assert s == 0.0 and g == "F"


def test_scan_nonexistent_file(tmp_path):
    missing_file = tmp_path / "does_not_exist.yml"
    report = scan_workflow(missing_file)
    assert report.valid_yaml is False
    assert "Failed to read file" in report.error_message
    assert report.score == 0.0
    assert report.grade == "F"


def test_scan_non_dict_yaml(tmp_path):
    raw_file = tmp_path / "scalar.yml"
    raw_file.write_text("just a plain scalar string\n", encoding="utf-8")
    report = scan_workflow(raw_file)
    assert report.valid_yaml is True
    assert report.score == 100.0
    assert report.job_count == 0


def test_discover_workflows_glob_pattern(tmp_path):
    sub = tmp_path / ".github" / "workflows"
    sub.mkdir(parents=True)
    f1 = sub / "build.yml"
    f2 = sub / "deploy.yaml"
    f3 = sub / "notes.txt"
    f1.write_text("name: Build\n", encoding="utf-8")
    f2.write_text("name: Deploy\n", encoding="utf-8")
    f3.write_text("Notes\n", encoding="utf-8")

    # Discover with wildcard pattern
    glob_pattern = str(sub / "*.y*ml")
    results = discover_workflows([glob_pattern])
    assert len(results) == 2
    assert f1.resolve() in results
    assert f2.resolve() in results

    # Discover default location
    default_results = discover_workflows(None, root_dir=tmp_path)
    assert len(default_results) == 2


# =========================================================================
# 3. Known Actions Lookup & Config Loading
# =========================================================================

def test_get_action_pin_fallback():
    # Exact match
    pin = get_action_pin("actions/checkout", "v4")
    assert pin is not None
    assert pin[0] == "11bd71901bbe5b1630ceea73d27597364c9af683"

    # Prefix match (e.g. v4.2.0 matching v4)
    pin_prefix = get_action_pin("actions/checkout", "v4.2.0")
    assert pin_prefix is not None
    assert pin_prefix[0] == "11bd71901bbe5b1630ceea73d27597364c9af683"

    # Unknown action returns None
    assert get_action_pin("unknown/custom-action", "v1") is None


def test_config_search_candidates(tmp_path):
    # Candidate .action-doctor.yml in root_dir
    cfg_file = tmp_path / ".action-doctor.yml"
    cfg_file.write_text("fail_on: info\nstrict: true\n", encoding="utf-8")

    loaded = Config.load(root_dir=tmp_path)
    assert loaded.strict is True
    assert loaded.fail_on == Severity.WARNING


def test_config_corrupted_file(tmp_path):
    bad_cfg = tmp_path / ".action-doctor.json"
    bad_cfg.write_text("{invalid json", encoding="utf-8")

    loaded = Config.load(bad_cfg)
    assert loaded.fail_on == Severity.ERROR
    assert len(loaded.ignore_rules) == 0


# =========================================================================
# 4. Fixer Edge Cases
# =========================================================================

def test_fix_nonexistent_file(tmp_path):
    missing_file = tmp_path / "no_file.yml"
    res = fix_workflow(missing_file)
    assert res.content_changed is False
    assert any("Error reading file" in msg for msg in res.fixes_applied)


def test_fix_custom_pins_config(tmp_path):
    target = tmp_path / "custom_pin.yml"
    target.write_text(
        """name: Custom Pin
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: my-corp/internal-action@v2
""",
        encoding="utf-8",
    )

    custom_sha = "0123456789abcdef0123456789abcdef01234567"
    cfg = Config(custom_pins={"my-corp/internal-action@v2": custom_sha})
    res = fix_workflow(target, config=cfg)
    assert res.content_changed is True
    fixed = target.read_text(encoding="utf-8")
    assert custom_sha in fixed


def test_fix_unquoted_commands(tmp_path):
    target = tmp_path / "unquoted_cmds.yml"
    target.write_text(
        """name: Unquoted
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo ::set-output name=result::success
          echo ::save-state name=step_id::123
          echo ::add-path::/opt/mytools
          echo ::set-env name=MY_VAR::hello
""",
        encoding="utf-8",
    )

    res = fix_workflow(target)
    assert res.content_changed is True
    fixed = target.read_text(encoding="utf-8")
    assert "::set-output" not in fixed
    assert '$GITHUB_OUTPUT"' in fixed
    assert "::save-state" not in fixed
    assert '$GITHUB_STATE"' in fixed
    assert "::add-path" not in fixed
    assert '$GITHUB_PATH"' in fixed
    assert "::set-env" not in fixed
    assert '$GITHUB_ENV"' in fixed


def test_fix_already_compliant(tmp_path):
    target = tmp_path / "clean.yml"
    shutil.copyfile(FIXTURES_DIR / "clean_workflow.yml", target)
    res = fix_workflow(target)
    assert res.content_changed is False
    assert res.fixed_count == 0


# =========================================================================
# 5. CLI Comprehensive Combinations
# =========================================================================

def test_cli_check_no_workflows(tmp_path, capsys):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    exit_code = main(["check", str(empty_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "No GitHub Actions workflows found" in captured.err


def test_cli_fix_no_workflows(tmp_path, capsys):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    exit_code = main(["fix", str(empty_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "No workflow files found to fix" in captured.err


def test_cli_check_strict_mode(capsys):
    # Warning file should fail in strict mode
    target = str(FIXTURES_DIR / "missing_permissions.yml")
    exit_code = main(["check", target, "--strict", "--no-color"])
    assert exit_code == 1


def test_cli_check_ignore_rules(capsys):
    target = str(FIXTURES_DIR / "deprecated_runner.yml")
    exit_code = main(["check", target, "--ignore-rules", "AD001,AD003", "--no-color"])
    assert exit_code == 0


def test_cli_check_format_github(capsys):
    target = str(FIXTURES_DIR / "deprecated_runner.yml")
    exit_code = main(["check", target, "--format", "github"])
    captured = capsys.readouterr()
    assert "::error " in captured.out


def test_cli_fix_specific_rules(tmp_path, capsys):
    target = tmp_path / "mixed.yml"
    target.write_text(
        """name: Mixed
on: [push]
jobs:
  test:
    runs-on: ubuntu-20.04
    steps:
      - run: echo ::set-output name=val::1
""",
        encoding="utf-8",
    )

    # Only fix AD001 (runner), skip commands
    exit_code = main(["fix", str(target), "--rules", "AD001", "--no-color"])
    assert exit_code == 0
    fixed = target.read_text(encoding="utf-8")
    assert "ubuntu-22.04" in fixed
    # ::set-output should remain since AD301 was not requested
    assert "::set-output" in fixed


def test_cli_audit_output_file_and_formats(tmp_path):
    out_json = tmp_path / "audit.json"
    exit_code = main(["audit", str(FIXTURES_DIR), "--format", "json", "-o", str(out_json)])
    assert exit_code == 0
    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert "overall_score" in data

    out_md = tmp_path / "audit.md"
    exit_code = main(["audit", str(FIXTURES_DIR), "--format", "markdown", "-o", str(out_md)])
    assert exit_code == 0
    assert out_md.exists()
    assert "# 🩺 Action Doctor Audit Report" in out_md.read_text(encoding="utf-8")
