"""Unit tests for action-doctor output formatters."""

import json
from pathlib import Path
import pytest

from action_doctor.auditor import audit_repository
from action_doctor.formatter import (
    format_github,
    format_json,
    format_markdown,
    format_sarif,
    format_text,
)
from action_doctor.scanner import scan_workflow

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_reports():
    return [
        scan_workflow(FIXTURES_DIR / "clean_workflow.yml"),
        scan_workflow(FIXTURES_DIR / "deprecated_runner.yml"),
    ]


@pytest.fixture
def sample_summary():
    return audit_repository([FIXTURES_DIR])


def test_format_text(sample_reports, sample_summary):
    out_plain = format_text(sample_reports, summary=sample_summary, color=False)
    assert "action-doctor" in out_plain
    assert "Overall Grade:" in out_plain
    assert "Action Inventory:" in out_plain

    out_color = format_text(sample_reports, summary=sample_summary, color=True)
    assert "\033[" in out_color


def test_format_json(sample_reports, sample_summary):
    json_str = format_json(sample_reports, summary=sample_summary)
    parsed = json.loads(json_str)
    assert "overall_score" in parsed
    assert "letter_grade" in parsed
    assert "reports" in parsed
    assert "actions_inventory" in parsed


def test_format_markdown(sample_reports, sample_summary):
    md_str = format_markdown(sample_reports, summary=sample_summary)
    assert "# 🩺 Action Doctor Audit Report" in md_str
    assert "| 📁 Workflows Scanned |" in md_str
    assert "## Workflow Diagnostics" in md_str


def test_format_sarif(sample_reports):
    sarif_str = format_sarif(sample_reports)
    parsed = json.loads(sarif_str)
    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"]) == 1
    run = parsed["runs"][0]
    assert run["tool"]["driver"]["name"] == "action-doctor"
    assert len(run["results"]) > 0


def test_format_github(sample_reports):
    gh_str = format_github(sample_reports)
    assert "::error " in gh_str or "::warning " in gh_str
