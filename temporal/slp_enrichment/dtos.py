from typing import Any, Literal

import msgspec


class ISIMIpItem(msgspec.Struct):
    address: str
    tag: list[str] | None = None


class ISIMSubnetItem(msgspec.Struct):
    range: str | None = None


class ISIMDomainItem(msgspec.Struct):
    domain_name: str | None = None
    tag: list[str] | None = None


#  TODO: This needs a further rework because ISIM api responses aren't clearly typed
ISIMIpsResponse = tuple[ISIMIpItem, ISIMSubnetItem | None, ISIMDomainItem | None, Any, Any]


# Local aggregation structure for linking domains to IPs from DB
class DomainItem(msgspec.Struct):
    domain_name: str | None
    found: bool
    subnet: str | None


# SLP API models via msgspec.Struct
class IP2ASNRecord(msgspec.Struct):
    ip: str | None = None
    ip_ptr: str | None = None
    subnet: str | None = None
    sp_risk_score: int | str | None = None


class SLPBulkResponseBody(msgspec.Struct):
    ip2asn: list[IP2ASNRecord]


class SLPBulkResponse(msgspec.Struct):
    status_code: int
    error: Any
    response: SLPBulkResponseBody


# Records we persist back to ISIM
class SLPRecord(msgspec.Struct):
    ip: str
    domain: str | None
    subnet: str | None
    sp_risk_score: int | str
    tag: Literal["SLP", "SLP_no"]
