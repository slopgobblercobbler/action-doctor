"""Unit tests for action-doctor audit rules."""

from pathlib import Path
import pytest
import yaml

from action_doctor.models import Category, Severity
from action_doctor.rules import get_all_rules, get_rule
from action_doctor.rules.best_practices import (
    MissingFailFastRule,
    MissingJobTimeoutRule,
    MissingStepNameRule,
)
from action_doctor.rules.runners import (
    DeprecatedNodeRuntimeRule,
    DeprecatedRunnerRule,
    LegacyMacRunnerRule,
)
from action_doctor.rules.security import (
    ExcessivePermissionsRule,
    InsecurePullRequestTargetRule,
    MissingPermissionsRule,
    PlaintextSecretInRunRule,
    ScriptInjectionRule,
)
from action_doctor.rules.supply_chain import (
    DeprecatedActionVersionRule,
    MutableBranchRefRule,
    UnpinnedActionShaRule,
)
from action_doctor.rules.syntax import (
    DeprecatedAddPathRule,
    DeprecatedSaveStateRule,
    DeprecatedSetEnvRule,
    DeprecatedSetOutputRule,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_registry_lookup():
    assert get_rule("AD001") is not None
    assert get_rule("deprecated-runner") is not None
    assert get_rule("AD101") is not None
    assert get_rule("missing-permissions") is not None
    assert get_rule("non-existent") is None
    assert len(get_all_rules()) >= 15


def test_deprecated_runner_rule():
    rule = DeprecatedRunnerRule()
    doc = """
jobs:
  build:
    runs-on: ubuntu-20.04
  matrix_job:
    strategy:
      matrix:
        os: [windows-2019, macos-latest]
    runs-on: ${{ matrix.os }}
"""
    parsed = yaml.safe_load(doc)
    lines = doc.splitlines()
    issues = rule.check(Path("workflow.yml"), doc, lines, parsed)
    assert len(issues) == 2
    rule_ids = [i.rule_id for i in issues]
    assert all(r == "AD001" for r in rule_ids)
    assert any("ubuntu-20.04" in i.message for i in issues)
    assert any("windows-2019" in i.message for i in issues)


def test_deprecated_node_runtime_rule():
    rule = DeprecatedNodeRuntimeRule()
    doc = "env:\n  ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION: true\n"
    lines = doc.splitlines()
    issues = rule.check(Path("wf.yml"), doc, lines, {})
    assert len(issues) == 1
    assert issues[0].rule_id == "AD002"


def test_legacy_mac_runner_rule():
    rule = LegacyMacRunnerRule()
    doc = "jobs:\n  test:\n    runs-on: macos-12\n"
    lines = doc.splitlines()
    issues = rule.check(Path("wf.yml"), doc, lines, {})
    assert len(issues) == 1
    assert issues[0].rule_id == "AD003"


def test_missing_permissions_rule():
    rule = MissingPermissionsRule()
    # Missing top-level and in job
    doc = "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    parsed = yaml.safe_load(doc)
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), parsed)
    assert len(issues) == 1
    assert issues[0].rule_id == "AD101"

    # Present at top-level
    doc_ok = "permissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    parsed_ok = yaml.safe_load(doc_ok)
    assert len(rule.check(Path("wf.yml"), doc_ok, doc_ok.splitlines(), parsed_ok)) == 0


def test_excessive_permissions_rule():
    rule = ExcessivePermissionsRule()
    doc = "permissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest"
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), yaml.safe_load(doc))
    assert len(issues) == 1
    assert issues[0].rule_id == "AD102"


def test_insecure_pull_request_target_rule():
    rule = InsecurePullRequestTargetRule()
    doc = """
on: pull_request_target
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), yaml.safe_load(doc))
    assert len(issues) == 1
    assert issues[0].rule_id == "AD103"


def test_script_injection_rule():
    rule = ScriptInjectionRule()
    doc = """
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Title: ${{ github.event.issue.title }}"
"""
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), yaml.safe_load(doc))
    assert len(issues) == 1
    assert issues[0].rule_id == "AD104"


def test_plaintext_secret_in_run_rule():
    rule = PlaintextSecretInRunRule()
    doc = """
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -H "Auth: ${{ secrets.GITHUB_TOKEN }}" https://example.com
"""
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), yaml.safe_load(doc))
    assert len(issues) == 1
    assert issues[0].rule_id == "AD105"


def test_unpinned_action_sha_rule():
    rule = UnpinnedActionShaRule()
    doc = """
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
"""
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), yaml.safe_load(doc))
    assert len(issues) == 1
    assert issues[0].rule_id == "AD201"
    assert "actions/checkout@v4" in issues[0].message


def test_mutable_branch_ref_rule():
    rule = MutableBranchRefRule()
    doc = """
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
"""
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), yaml.safe_load(doc))
    assert len(issues) == 1
    assert issues[0].rule_id == "AD202"


def test_deprecated_action_version_rule():
    rule = DeprecatedActionVersionRule()
    doc = """
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v3
"""
    issues = rule.check(Path("wf.yml"), doc, doc.splitlines(), yaml.safe_load(doc))
    assert len(issues) == 1
    assert issues[0].rule_id == "AD203"


def test_deprecated_workflow_commands():
    rule_output = DeprecatedSetOutputRule()
    rule_state = DeprecatedSaveStateRule()
    rule_path = DeprecatedAddPathRule()
    rule_env = DeprecatedSetEnvRule()

    doc = """
jobs:
  build:
    steps:
      - run: echo "::set-output name=foo::bar"
      - run: echo "::save-state name=foo::bar"
      - run: echo "::add-path::/usr/bin"
      - run: echo "::set-env name=VAR::val"
"""
    lines = doc.splitlines()
    assert len(rule_output.check(Path("wf.yml"), doc, lines, {})) == 1
    assert len(rule_state.check(Path("wf.yml"), doc, lines, {})) == 1
    assert len(rule_path.check(Path("wf.yml"), doc, lines, {})) == 1
    assert len(rule_env.check(Path("wf.yml"), doc, lines, {})) == 1


def test_best_practices_rules():
    r_timeout = MissingJobTimeoutRule()
    r_name = MissingStepNameRule()
    r_failfast = MissingFailFastRule()

    doc = """
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - run: echo "hello"
"""
    parsed = yaml.safe_load(doc)
    lines = doc.splitlines()

    assert len(r_timeout.check(Path("wf.yml"), doc, lines, parsed)) == 1
    assert len(r_name.check(Path("wf.yml"), doc, lines, parsed)) == 1
    assert len(r_failfast.check(Path("wf.yml"), doc, lines, parsed)) == 1
