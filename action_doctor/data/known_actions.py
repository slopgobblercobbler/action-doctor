"""Known actions reference database, secure SHA pins, and deprecation catalog."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# Mapping of popular action tags to secure commit SHAs and tag comments
# Format: "owner/repo@tag": ("sha", "tag_comment")
KNOWN_ACTION_PINS: Dict[str, Tuple[str, str]] = {
    "actions/checkout@v4": (
        "11bd71901bbe5b1630ceea73d27597364c9af683",
        "v4.2.2",
    ),
    "actions/checkout@v3": (
        "f43a0e5ff2bd294095638e18286ca9a3d1956744",
        "v3.6.0",
    ),
    "actions/setup-python@v5": (
        "42375524e23c412d93fb67b49958b491fce71c38",
        "v5.4.0",
    ),
    "actions/setup-python@v4": (
        "65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236",
        "v4.7.1",
    ),
    "actions/setup-node@v4": (
        "1e60f620b9541d16abce94cb522027ec595dacd5",
        "v4.2.0",
    ),
    "actions/setup-node@v3": (
        "e33196f7421987e6884a0da4c67c8a8464455dd3",
        "v3.8.2",
    ),
    "actions/setup-go@v5": (
        "f111f330730b5538a6e512304957eb1a1034d6f6",
        "v5.3.0",
    ),
    "actions/setup-java@v4": (
        "3a4f6e1af504cf6a31855fa899c6aa5355ba6c12",
        "v4.7.0",
    ),
    "actions/upload-artifact@v4": (
        "4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1",
        "v4.6.1",
    ),
    "actions/download-artifact@v4": (
        "cc203385981b70ca67e1ab38864c36d12902f70f",
        "v4.1.9",
    ),
    "actions/cache@v4": (
        "d4323d4df104b026a6aa633fdb11d772115f6ec1",
        "v4.2.2",
    ),
    "actions/cache@v3": (
        "88522ab9f39a2ea568f7027eddc7d8d8bc9d59c8",
        "v3.3.3",
    ),
    "actions/github-script@v7": (
        "60a0d83039c74a4aee543508d2ffcb1c3799cdea",
        "v7.0.1",
    ),
    "actions/stale@v9": (
        "285f38638116b450150524cb6f6fbe7e74e85f81",
        "v9.0.0",
    ),
    "codecov/codecov-action@v4": (
        "0565863a31f2c77d4bf9d4b644c00030721ab6c3",
        "v4.6.0",
    ),
    "codecov/codecov-action@v5": (
        "13ce06bfc6bbe3ecf90edbbf1bc32fe5978ca1d3",
        "v5.3.1",
    ),
    "docker/login-action@v3": (
        "9780b0c442fbb1117ed29e0efdff1e18412f7567",
        "v3.3.0",
    ),
    "docker/build-push-action@v6": (
        "471d1dc4e07e5cdedd4c2171150001c434f0b7a4",
        "v6.15.0",
    ),
    "docker/setup-buildx-action@v3": (
        "b5ca514310cf82afeedbe0f5f4f7d17418ce5107",
        "v3.10.0",
    ),
    "pypa/gh-action-pypi-publish@release/v1": (
        "76f52e6691c99b6650c96133304a6b57d005f97d",
        "v1.12.4",
    ),
    "github/codeql-action/init@v3": (
        "b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d",
        "v3.28.10",
    ),
    "github/codeql-action/analyze@v3": (
        "b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d",
        "v3.28.10",
    ),
}

# Sunset / deprecated action versions
# Format: "action_prefix@tag": ("recommended_tag", "reason")
DEPRECATED_ACTION_VERSIONS: Dict[str, Tuple[str, str]] = {
    "actions/checkout@v1": (
        "v4",
        "actions/checkout@v1 uses deprecated Node.js 12 runtime and lacks modern Git optimization.",
    ),
    "actions/checkout@v2": (
        "v4",
        "actions/checkout@v2 uses deprecated Node.js 12 runtime.",
    ),
    "actions/checkout@v3": (
        "v4",
        "actions/checkout@v3 is superseded by v4 with improved performance and modern runtime.",
    ),
    "actions/setup-node@v1": (
        "v4",
        "actions/setup-node@v1 uses deprecated Node.js 12 runtime.",
    ),
    "actions/setup-node@v2": (
        "v4",
        "actions/setup-node@v2 uses deprecated Node.js 12 runtime.",
    ),
    "actions/setup-node@v3": (
        "v4",
        "actions/setup-node@v3 is superseded by v4 with modern caching improvements.",
    ),
    "actions/setup-python@v1": (
        "v5",
        "actions/setup-python@v1 uses deprecated Node.js 12 runtime.",
    ),
    "actions/setup-python@v2": (
        "v5",
        "actions/setup-python@v2 uses deprecated Node.js 12 runtime.",
    ),
    "actions/setup-python@v3": (
        "v5",
        "actions/setup-python@v3 is outdated; migrate to setup-python@v5.",
    ),
    "actions/setup-python@v4": (
        "v5",
        "actions/setup-python@v4 is superseded by v5 with Python 3.12+ and modern caching.",
    ),
    "actions/upload-artifact@v1": (
        "v4",
        "actions/upload-artifact@v1 is sunset; Artifacts v1-v3 are shut down by GitHub.",
    ),
    "actions/upload-artifact@v2": (
        "v4",
        "actions/upload-artifact@v2 is sunset; Artifacts v1-v3 are shut down by GitHub.",
    ),
    "actions/upload-artifact@v3": (
        "v4",
        "actions/upload-artifact@v3 is sunset; Artifacts v1-v3 are shut down by GitHub.",
    ),
    "actions/download-artifact@v1": (
        "v4",
        "actions/download-artifact@v1 is sunset; Artifacts v1-v3 are shut down by GitHub.",
    ),
    "actions/download-artifact@v2": (
        "v4",
        "actions/download-artifact@v2 is sunset; Artifacts v1-v3 are shut down by GitHub.",
    ),
    "actions/download-artifact@v3": (
        "v4",
        "actions/download-artifact@v3 is sunset; Artifacts v1-v3 are shut down by GitHub.",
    ),
    "actions/cache@v1": (
        "v4",
        "actions/cache@v1 uses deprecated Node.js 12 runtime.",
    ),
    "actions/cache@v2": (
        "v4",
        "actions/cache@v2 uses deprecated Node.js 12 runtime.",
    ),
    "actions/cache@v3": (
        "v4",
        "actions/cache@v3 uses deprecated Node.js 16 runtime; upgrade to v4 (Node 20).",
    ),
}


def get_action_pin(action_name: str, ref: str) -> Optional[Tuple[str, str]]:
    """Lookup known commit SHA and version tag for action."""
    key = f"{action_name}@{ref}"
    if key in KNOWN_ACTION_PINS:
        return KNOWN_ACTION_PINS[key]

    # Check without patch or minor version
    for known_key, pin in KNOWN_ACTION_PINS.items():
        known_action, known_ref = known_key.split("@", 1)
        if action_name == known_action:
            if ref.startswith(known_ref) or known_ref.startswith(ref):
                return pin

    return None
