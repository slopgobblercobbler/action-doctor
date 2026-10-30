"""Base class for action-doctor audit rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, List, Optional

from action_doctor.models import Category, Issue, Severity


class Rule(ABC):
    """Abstract base class for all audit rules."""

    rule_id: str
    name: str
    category: Category
    severity: Severity
    description: str

    @abstractmethod
    def check(
        self,
        file_path: Path,
        raw_text: str,
        lines: List[str],
        parsed_yaml: Any,
    ) -> List[Issue]:
        """Audit workflow and return list of identified issues."""
        pass

    def create_issue(
        self,
        message: str,
        file_path: Path,
        line: int = 1,
        column: int = 1,
        fixable: bool = False,
        suggestion: Optional[str] = None,
        context_line: Optional[str] = None,
        severity_override: Optional[Severity] = None,
    ) -> Issue:
        """Helper to create an Issue instance for this rule."""
        return Issue(
            rule_id=self.rule_id,
            message=message,
            file_path=file_path,
            line=max(1, line),
            column=max(1, column),
            severity=severity_override or self.severity,
            category=self.category,
            fixable=fixable,
            suggestion=suggestion,
            context_line=context_line,
        )
