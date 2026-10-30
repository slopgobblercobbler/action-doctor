"""Unit tests for repository-wide auditor."""

from pathlib import Path
import pytest

from action_doctor.auditor import audit_repository
from action_doctor.config import Config

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_audit_repository_fixtures():
    summary = audit_repository([FIXTURES_DIR])
    assert summary.scanned_files >= 5
    assert summary.total_issues > 0
    assert summary.error_count > 0
    assert summary.warning_count > 0
    assert summary.fixable_count > 0
    assert summary.overall_score >= 0.0
    assert summary.letter_grade in ("A+", "A", "B", "C", "D", "F")

    # Check actions inventory
    assert "actions/checkout" in summary.actions_inventory
    checkout_meta = summary.actions_inventory["actions/checkout"]
    assert checkout_meta["total_usages"] > 0
    assert "versions" in checkout_meta
    assert "pinned_percentage" in checkout_meta

    # Check runners inventory
    assert len(summary.runners_inventory) > 0

    # Check category scores
    assert "runner" in summary.category_scores
    assert "security" in summary.category_scores
    assert "supply-chain" in summary.category_scores
    assert "syntax" in summary.category_scores
    assert "best-practice" in summary.category_scores


def test_audit_empty_directory(tmp_path):
    summary = audit_repository([tmp_path])
    assert summary.scanned_files == 0
    assert summary.total_issues == 0
    assert summary.overall_score == 100.0
    assert summary.letter_grade == "A+"
