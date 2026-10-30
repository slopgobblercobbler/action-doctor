"""action-doctor: GitHub Actions Workflow Security & Hygiene Auditing Utility."""

from action_doctor.auditor import audit_repository
from action_doctor.config import Config
from action_doctor.fixer import fix_workflow
from action_doctor.models import (
    ActionUsage,
    AuditSummary,
    Category,
    FixResult,
    Issue,
    Severity,
    WorkflowReport,
)
from action_doctor.scanner import discover_workflows, scan_workflow

__version__ = "0.1.0"

__all__ = [
    "scan_workflow",
    "fix_workflow",
    "audit_repository",
    "discover_workflows",
    "Config",
    "Issue",
    "WorkflowReport",
    "AuditSummary",
    "ActionUsage",
    "FixResult",
    "Severity",
    "Category",
    "__version__",
]
