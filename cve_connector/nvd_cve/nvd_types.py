from __future__ import annotations

from enum import StrEnum
from typing import Any

import msgspec


class NvdVulnerabilityItem(msgspec.Struct, frozen=True):
    cve: dict[str, Any]


class NvdCvesApiResponse(msgspec.Struct, frozen=True):
    vulnerabilities: list[NvdVulnerabilityItem] = msgspec.field(default_factory=list)
    startIndex: int | None = None
    resultsPerPage: int | None = None
    totalResults: int | None = None


class VulnerabilityStatus(StrEnum):
    ESTIMATED = "estimated"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    ASSESSED = "assessed"
    REASSESSED = "reassessed"
    RESOLVED = "resolved"
    CLOSED = "closed"
    NOT_FOUND = "not_found"
