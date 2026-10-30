"""Configuration handling for action-doctor."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from action_doctor.models import Severity


@dataclass
class Config:
    ignore_rules: Set[str] = field(default_factory=set)
    fail_on: Severity = Severity.ERROR
    strict: bool = False
    preferred_runner: str = "ubuntu-latest"
    default_timeout: int = 60
    custom_pins: Dict[str, str] = field(default_factory=dict)
    include_paths: List[str] = field(default_factory=lambda: [".github/workflows/*.yml", ".github/workflows/*.yaml"])
    exclude_paths: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, config_path: Optional[Path] = None, root_dir: Optional[Path] = None) -> "Config":
        """Load configuration from specified file or search default locations."""
        root = root_dir or Path.cwd()

        if config_path and config_path.exists():
            return cls._load_file(config_path)

        candidates = [
            root / ".action-doctor.yml",
            root / ".action-doctor.yaml",
            root / ".action-doctor.json",
            root / "action-doctor.json",
        ]

        for cand in candidates:
            if cand.exists():
                return cls._load_file(cand)

        # Check pyproject.toml
        pyproject_file = root / "pyproject.toml"
        if pyproject_file.exists():
            try:
                import tomli  # standard in python 3.11, or tomli if installed
                with open(pyproject_file, "rb") as f:
                    pyproj = tomli.load(f)
                    ad_cfg = pyproj.get("tool", {}).get("action-doctor", {})
                    if ad_cfg:
                        return cls._from_dict(ad_cfg)
            except Exception:
                pass

        return cls()

    @classmethod
    def _load_file(cls, path: Path) -> "Config":
        try:
            content = path.read_text(encoding="utf-8")
            if path.suffix.lower() == ".json":
                data = json.loads(content)
            else:
                data = yaml.safe_load(content) or {}
            return cls._from_dict(data)
        except Exception:
            return cls()

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "Config":
        ignore_rules = {r.strip().upper() for r in data.get("ignore_rules", [])}
        fail_on_str = str(data.get("fail_on", "error")).lower()
        fail_on = Severity.WARNING if fail_on_str == "warning" else (
            Severity.INFO if fail_on_str == "info" else Severity.ERROR
        )
        strict = bool(data.get("strict", False))
        if strict:
            fail_on = Severity.WARNING

        return cls(
            ignore_rules=ignore_rules,
            fail_on=fail_on,
            strict=strict,
            preferred_runner=str(data.get("preferred_runner", "ubuntu-latest")),
            default_timeout=int(data.get("default_timeout", 60)),
            custom_pins=data.get("custom_pins", {}),
            include_paths=data.get("include_paths", [".github/workflows/*.yml", ".github/workflows/*.yaml"]),
            exclude_paths=data.get("exclude_paths", []),
        )
