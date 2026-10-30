"""Unit tests for action-doctor configuration loading."""

import json
from pathlib import Path
import pytest

from action_doctor.config import Config
from action_doctor.models import Severity


def test_default_config():
    cfg = Config()
    assert cfg.fail_on == Severity.ERROR
    assert cfg.strict is False
    assert cfg.default_timeout == 60
    assert cfg.preferred_runner == "ubuntu-latest"
    assert len(cfg.ignore_rules) == 0


def test_load_from_yaml_file(tmp_path):
    cfg_file = tmp_path / ".action-doctor.yml"
    cfg_file.write_text(
        """
ignore_rules:
  - AD001
  - ad401
fail_on: warning
strict: false
default_timeout: 45
preferred_runner: ubuntu-22.04
custom_pins:
  "my-org/my-action@v1": "abcdef1234567890abcdef1234567890abcdef12"
""",
        encoding="utf-8",
    )

    cfg = Config.load(cfg_file)
    assert "AD001" in cfg.ignore_rules
    assert "AD401" in cfg.ignore_rules
    assert cfg.fail_on == Severity.WARNING
    assert cfg.default_timeout == 45
    assert cfg.preferred_runner == "ubuntu-22.04"
    assert "my-org/my-action@v1" in cfg.custom_pins


def test_load_from_json_file(tmp_path):
    cfg_file = tmp_path / ".action-doctor.json"
    data = {
        "ignore_rules": ["AD101"],
        "strict": True,
        "default_timeout": 30,
    }
    cfg_file.write_text(json.dumps(data), encoding="utf-8")

    cfg = Config.load(cfg_file)
    assert "AD101" in cfg.ignore_rules
    assert cfg.strict is True
    assert cfg.fail_on == Severity.WARNING
    assert cfg.default_timeout == 30
