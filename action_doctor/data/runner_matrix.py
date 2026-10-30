"""Runner deprecation database and replacement mappings."""

from __future__ import annotations

from typing import Dict, Set

# Deprecated runners mapping to (replacement, reason)
DEPRECATED_RUNNERS: Dict[str, Dict[str, str]] = {
    "ubuntu-16.04": {
        "replacement": "ubuntu-22.04",
        "reason": "ubuntu-16.04 was sunset in September 2021 and is completely removed.",
    },
    "ubuntu-18.04": {
        "replacement": "ubuntu-22.04",
        "reason": "ubuntu-18.04 was sunset in December 2022 and is completely removed.",
    },
    "ubuntu-20.04": {
        "replacement": "ubuntu-22.04",
        "reason": "ubuntu-20.04 has reached end-of-life on GitHub Actions; migrate to ubuntu-22.04 or ubuntu-latest.",
    },
    "macos-10.15": {
        "replacement": "macos-14",
        "reason": "macos-10.15 was sunset in August 2022 and is completely removed.",
    },
    "macos-11": {
        "replacement": "macos-14",
        "reason": "macos-11 was sunset in June 2023 and is completely removed.",
    },
    "macos-12": {
        "replacement": "macos-14",
        "reason": "macos-12 is deprecated on GitHub Actions; migrate to macos-14 (Apple Silicon) or macos-latest.",
    },
    "windows-2016": {
        "replacement": "windows-2022",
        "reason": "windows-2016 was sunset in March 2022 and is completely removed.",
    },
    "windows-2019": {
        "replacement": "windows-2022",
        "reason": "windows-2019 is deprecated on GitHub Actions; migrate to windows-2022 or windows-latest.",
    },
}

SUPPORTED_HOSTED_RUNNERS: Set[str] = {
    "ubuntu-latest",
    "ubuntu-24.04",
    "ubuntu-22.04",
    "windows-latest",
    "windows-2025",
    "windows-2022",
    "macos-latest",
    "macos-15",
    "macos-14",
    "macos-13",
    "macos-latest-xlarge",
    "macos-14-xlarge",
    "macos-13-xlarge",
    "macos-latest-large",
    "macos-14-large",
    "macos-13-large",
}
