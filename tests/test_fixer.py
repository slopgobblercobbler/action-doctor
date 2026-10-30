"""Unit tests for action-doctor automated fixes."""

from pathlib import Path
import pytest
import shutil

from action_doctor.config import Config
from action_doctor.fixer import WorkflowFixer, fix_workflow

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_fix_deprecated_runners(tmp_path):
    target = tmp_path / "deprecated_runner.yml"
    shutil.copyfile(FIXTURES_DIR / "deprecated_runner.yml", target)

    result = fix_workflow(target, allowed_rules={"AD001", "AD003"})
    assert result.content_changed is True
    assert result.fixed_count >= 2

    fixed_text = target.read_text(encoding="utf-8")
    assert "ubuntu-20.04" not in fixed_text
    assert "ubuntu-22.04" in fixed_text
    assert "windows-2019" not in fixed_text
    assert "windows-2022" in fixed_text
    assert "macos-11" not in fixed_text
    assert "macos-14" in fixed_text


def test_fix_deprecated_commands(tmp_path):
    target = tmp_path / "deprecated_commands.yml"
    shutil.copyfile(FIXTURES_DIR / "deprecated_commands.yml", target)

    result = fix_workflow(target)
    assert result.content_changed is True
    assert result.fixed_count >= 4

    fixed_text = target.read_text(encoding="utf-8")
    assert "::set-output" not in fixed_text
    assert '$GITHUB_OUTPUT"' in fixed_text
    assert "::save-state" not in fixed_text
    assert '$GITHUB_STATE"' in fixed_text
    assert "::add-path" not in fixed_text
    assert '$GITHUB_PATH"' in fixed_text
    assert "::set-env" not in fixed_text
    assert '$GITHUB_ENV"' in fixed_text


def test_fix_missing_permissions(tmp_path):
    target = tmp_path / "missing_permissions.yml"
    shutil.copyfile(FIXTURES_DIR / "missing_permissions.yml", target)

    result = fix_workflow(target, allowed_rules={"AD101"})
    assert result.content_changed is True
    fixed_text = target.read_text(encoding="utf-8")
    assert "permissions:" in fixed_text
    assert "contents: read" in fixed_text


def test_fix_action_pins(tmp_path):
    target = tmp_path / "unpinned_action.yml"
    shutil.copyfile(FIXTURES_DIR / "unpinned_action.yml", target)

    result = fix_workflow(target, allowed_rules={"AD201", "AD203"})
    assert result.content_changed is True

    fixed_text = target.read_text(encoding="utf-8")
    # actions/checkout@v4 should be pinned to SHA
    assert "11bd71901bbe5b1630ceea73d27597364c9af683" in fixed_text
    # upload-artifact@v3 should be upgraded to v4 or pinned
    assert "upload-artifact@v4" in fixed_text or "upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1" in fixed_text


def test_fix_missing_job_timeout(tmp_path):
    target = tmp_path / "missing_permissions.yml"
    shutil.copyfile(FIXTURES_DIR / "missing_permissions.yml", target)

    result = fix_workflow(target, allowed_rules={"AD401"})
    assert result.content_changed is True
    fixed_text = target.read_text(encoding="utf-8")
    assert "timeout-minutes: 60" in fixed_text


def test_fix_dry_run(tmp_path):
    target = tmp_path / "deprecated_commands.yml"
    shutil.copyfile(FIXTURES_DIR / "deprecated_commands.yml", target)
    original_text = target.read_text(encoding="utf-8")

    result = fix_workflow(target, dry_run=True)
    assert result.content_changed is True
    assert result.fixed_count >= 4
    # File on disk should be completely unchanged
    assert target.read_text(encoding="utf-8") == original_text
