from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import httpx


@dataclass(frozen=True)
class ApiCheck:
    """Declarative API check definition."""

    name: str
    path: str
    validator: Callable[[Any], bool]


def _is_placeholder(checks: list[ApiCheck]) -> bool:
    return all("REPLACE_ME" in check.path for check in checks)


def verify_api_state(base_url: str = "http://localhost:8000") -> None:
    """
    Verify that workflow results are present via the REST API.

    Replace the placeholder checks below with project-specific endpoints and validations.
    """
    checks: list[ApiCheck] = [
        ApiCheck(
            name="TODO: verify Nmap results",
            path="/api/REPLACE_ME/nmap",
            validator=lambda data: True,
        ),
        ApiCheck(
            name="TODO: verify EASM results",
            path="/api/REPLACE_ME/easm",
            validator=lambda data: True,
        ),
        ApiCheck(
            name="TODO: verify CVE/Nuclei/component results",
            path="/api/REPLACE_ME/cve-nuclei-components",
            validator=lambda data: True,
        ),
    ]

    if _is_placeholder(checks):
        print(
            "API checks are still placeholders. Update `test/e2e/api_checks.py` with real endpoints "
            "and validations to assert E2E data."
        )
        return

    with httpx.Client(base_url=base_url, timeout=60.0) as client:
        for check in checks:
            response = client.get(check.path)
            if response.status_code >= 400:
                msg = f"API check '{check.name}' failed with HTTP {response.status_code} at {check.path}"
                raise RuntimeError(msg)

            payload: Any
            try:
                payload = response.json()
            except ValueError:
                payload = response.text

            if not check.validator(payload):
                msg = f"API check '{check.name}' validator returned False for {check.path}"
                raise AssertionError(msg)

