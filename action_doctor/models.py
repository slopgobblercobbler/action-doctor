"""Data models for action-doctor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Category(str, Enum):
    RUNNER = "runner"
    SECURITY = "security"
    SUPPLY_CHAIN = "supply-chain"
    SYNTAX = "syntax"
    BEST_PRACTICE = "best-practice"


@dataclass
class Issue:
    rule_id: str
    message: str
    file_path: Path
    line: int = 1
    column: int = 1
    severity: Severity = Severity.WARNING
    category: Category = Category.BEST_PRACTICE
    fixable: bool = False
    suggestion: Optional[str] = None
    context_line: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "file_path": str(self.file_path),
            "line": self.line,
            "column": self.column,
            "severity": self.severity.value,
            "category": self.category.value,
            "fixable": self.fixable,
            "suggestion": self.suggestion,
            "context_line": self.context_line,
        }


@dataclass
class ActionUsage:
    action: str
    ref: str
    is_sha: bool
    line: int
    column: int = 1
    pinned_comment: Optional[str] = None

    @property
    def full_reference(self) -> str:
        return f"{self.action}@{self.ref}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "ref": self.ref,
            "is_sha": self.is_sha,
            "line": self.line,
            "column": self.column,
            "pinned_comment": self.pinned_comment,
            "full_reference": self.full_reference,
        }


@dataclass
class FixResult:
    file_path: Path
    fixed_count: int = 0
    fixes_applied: List[str] = field(default_factory=list)
    content_changed: bool = False
    original_content: str = ""
    new_content: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": str(self.file_path),
            "fixed_count": self.fixed_count,
            "fixes_applied": self.fixes_applied,
            "content_changed": self.content_changed,
        }


@dataclass
class WorkflowReport:
    file_path: Path
    valid_yaml: bool = True
    error_message: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)
    actions_used: List[ActionUsage] = field(default_factory=list)
    runners_used: List[str] = field(default_factory=list)
    permissions_defined: bool = False
    job_count: int = 0
    score: float = 100.0
    grade: str = "A+"

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.INFO)

    @property
    def fixable_count(self) -> int:
        return sum(1 for i in self.issues if i.fixable)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": str(self.file_path),
            "valid_yaml": self.valid_yaml,
            "error_message": self.error_message,
            "score": round(self.score, 1),
            "grade": self.grade,
            "job_count": self.job_count,
            "permissions_defined": self.permissions_defined,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "fixable_count": self.fixable_count,
            "issues": [i.to_dict() for i in self.issues],
            "actions_used": [a.to_dict() for a in self.actions_used],
            "runners_used": self.runners_used,
        }


@dataclass
class AuditSummary:
    total_files: int = 0
    scanned_files: int = 0
    total_issues: int = 0
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    fixable_count: int = 0
    overall_score: float = 100.0
    letter_grade: str = "A+"
    reports: List[WorkflowReport] = field(default_factory=list)
    actions_inventory: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    runners_inventory: Dict[str, int] = field(default_factory=dict)
    category_scores: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "total_issues": self.total_issues,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "fixable_count": self.fixable_count,
            "overall_score": round(self.overall_score, 1),
            "letter_grade": self.letter_grade,
            "category_scores": {k: round(v, 1) for k, v in self.category_scores.items()},
            "actions_inventory": self.actions_inventory,
            "runners_inventory": self.runners_inventory,
            "reports": [r.to_dict() for r in self.reports],
        }
