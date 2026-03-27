from __future__ import annotations

from enum import StrEnum
from typing import Any

import msgspec


class VulnerabilityStatus(StrEnum):
    ESTIMATED = "estimated"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    ASSESSED = "assessed"
    REASSESSED = "reassessed"
    RESOLVED = "resolved"
    CLOSED = "closed"
    NOT_FOUND = "not_found"


class NvdVulnerabilityItem(msgspec.Struct, frozen=True):
    cve: dict[str, Any]


class NvdCvesApiResponse(msgspec.Struct, frozen=True):
    vulnerabilities: list[NvdVulnerabilityItem] = msgspec.field(default_factory=list)
    startIndex: int | None = None
    resultsPerPage: int | None = None
    totalResults: int | None = None


class GraphqlVulnerabilityStatus(msgspec.Struct, frozen=True):
    status: list[str] = msgspec.field(default_factory=list)


class GetVulnerabilityStatusData(msgspec.Struct, frozen=True):
    vulnerabilities: list[GraphqlVulnerabilityStatus] = msgspec.field(default_factory=list)


class GetVulnerabilityStatusResponse(msgspec.Struct, frozen=True):
    data: GetVulnerabilityStatusData | None = None
    errors: list[dict[str, Any]] = msgspec.field(default_factory=list)


class UpdateVulnerabilitiesPayload(msgspec.Struct, frozen=True):
    vulnerabilities: list[GraphqlVulnerabilityStatus] = msgspec.field(default_factory=list)


class UpdateVulnerabilityStatusData(msgspec.Struct, frozen=True):
    update_vulnerabilities: UpdateVulnerabilitiesPayload | None = msgspec.field(
        default=None,
        name="updateVulnerabilities",
    )


class UpdateVulnerabilityStatusResponse(msgspec.Struct, frozen=True):
    data: UpdateVulnerabilityStatusData | None = None
    errors: list[dict[str, Any]] = msgspec.field(default_factory=list)


class SoftwareVersionRow(msgspec.Struct, frozen=True):
    version: str
    cve_timestamp: str | None


class SoftwareVersionNode(msgspec.Struct, frozen=True):
    version: str


class ProductSoftwareRow(msgspec.Struct, frozen=True):
    software: SoftwareVersionNode
