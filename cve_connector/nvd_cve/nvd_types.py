from __future__ import annotations

from typing import Any

import msgspec


class NvdVulnerabilityItem(msgspec.Struct, frozen=True):
    cve: dict[str, Any]


class NvdCvesApiResponse(msgspec.Struct, frozen=True):
    vulnerabilities: list[NvdVulnerabilityItem] = msgspec.field(default_factory=list)
    startIndex: int | None = None
    resultsPerPage: int | None = None
    totalResults: int | None = None
