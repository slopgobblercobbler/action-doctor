"""Unit and integration tests for action-doctor CLI."""

from pathlib import Path
import pytest
import shutil

from action_doctor.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "action-doctor" in captured.out
    assert "check" in captured.out
    assert "fix" in captured.out
    assert "audit" in captured.out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "0.1.0" in captured.out


def test_cli_no_args(capsys):
    exit_code = main([])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "action-doctor" in captured.out


def test_cli_check_clean(capsys):
    clean_path = str(FIXTURES_DIR / "clean_workflow.yml")
    exit_code = main(["check", clean_path, "--no-color"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "All checks passed" in captured.out


def test_cli_check_failing(capsys):
    bad_path = str(FIXTURES_DIR / "deprecated_runner.yml")
    exit_code = main(["check", bad_path, "--fail-on", "error", "--no-color"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "AD001" in captured.out


def test_cli_check_formats(tmp_path, capsys):
    clean_path = str(FIXTURES_DIR / "clean_workflow.yml")

    # JSON format
    exit_code = main(["check", clean_path, "--format", "json"])
    assert exit_code == 0
    out_json = capsys.readouterr().out
    assert "[" in out_json and "file_path" in out_json

    # Markdown format
    exit_code = main(["check", clean_path, "--format", "markdown"])
    assert exit_code == 0
    out_md = capsys.readouterr().out
    assert "# 🩺 Action Doctor Audit Report" in out_md

    # SARIF format to output file
    sarif_file = tmp_path / "results.sarif"
    exit_code = main(["check", clean_path, "--format", "sarif", "-o", str(sarif_file)])
    assert exit_code == 0
    assert sarif_file.exists()
    assert "2.1.0" in sarif_file.read_text(encoding="utf-8")


def test_cli_fix_dry_run(tmp_path, capsys):
    target = tmp_path / "deprecated_commands.yml"
    shutil.copyfile(FIXTURES_DIR / "deprecated_commands.yml", target)

    exit_code = main(["fix", str(target), "--dry-run", "--no-color"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "[DRY-RUN]" in captured.out
    assert "Would apply" in captured.out


def test_cli_fix_live(tmp_path, capsys):
    target = tmp_path / "deprecated_commands.yml"
    shutil.copyfile(FIXTURES_DIR / "deprecated_commands.yml", target)

    exit_code = main(["fix", str(target), "--no-color"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Successfully applied" in captured.out
    assert "$GITHUB_OUTPUT" in target.read_text(encoding="utf-8")


def test_cli_audit(capsys):
    exit_code = main(["audit", str(FIXTURES_DIR), "--min-score", "0.0", "--no-color"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Overall Grade:" in captured.out
    assert "Action Inventory:" in captured.out


def test_cli_audit_failing_min_score(capsys):
    bad_path = str(FIXTURES_DIR / "deprecated_runner.yml")
    exit_code = main(["audit", bad_path, "--min-score", "99.0", "--no-color"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Audit failed: Score" in captured.err
