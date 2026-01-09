from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal

import httpx
import msgspec
from temporalio import activity

from config import ISIMConfig


# ISIM API models via msgspec.Struct
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
    domain_name: str
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
    error: bool
    response: SLPBulkResponseBody


# Records we persist back to ISIM
class SLPRecord(msgspec.Struct):
    ip: str
    domain: str
    subnet: str
    sp_risk_score: int | str
    tag: Literal["SLP", "SLP_no"]


class SLPEnrichmentActivities:
    """
    Activities for performing enrichment of information about assets obtained from SLP.
    """

    def __init__(self, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config

    @activity.defn
    async def get_asset_info(self) -> list[ISIMIpsResponse]:
        """
        This method gets information about assets necessary for obtaining data from SLP.
        The most important are IP addresses, domain names, and subnets.
        :return: a list of assets from the ISIM's REST API
        """
        unprocessed_addresses: list[ISIMIpsResponse] = []
        last_item_found: bool = False
        offset: int = 0
        limit: int = 100

        while len(unprocessed_addresses) < 100 and not last_item_found:
            params: dict[str, int] = {"limit": limit, "offset": offset}
            response = httpx.get(f"{self.isim_config.url}/ips", params=params)  # noqa: ASYNC210
            # Decode into typed structs
            decoded: list[ISIMIpsResponse] = msgspec.json.decode(response.content, type=list[ISIMIpsResponse])
            if len(decoded) < limit:
                last_item_found = True
            unprocessed_addresses += [
                item
                for item in decoded
                if not (item[0].tag is not None and "SLP" in item[0].tag)
            ][: 100 - len(unprocessed_addresses)]
            offset += limit
        return unprocessed_addresses

    @activity.defn
    async def get_data_from_slp(self, response_json: list[ISIMIpsResponse], x_api_key: str) -> list[SLPRecord]:
        """Obtains enrichment data from SLP - IP addresses, domain names, risk score, and subnets."""
        domains_ips_from_database = self._build_ip_domain_mapping(response_json)
        ip_addresses = list(domains_ips_from_database.keys())

        slp_records = await self._fetch_slp_data(ip_addresses, x_api_key)
        self._mark_found_domains(slp_records, domains_ips_from_database)

        return self._merge_records(slp_records, domains_ips_from_database)

    def _build_ip_domain_mapping(self, response_json: list[ISIMIpsResponse]) -> dict[str, list[DomainItem]]:
        """Builds mapping of IP addresses to domain items from response."""
        mapping: dict[str, list[DomainItem]] = {}

        for asset_info in response_json:
            ip_address = asset_info[0].address
            if ip_address == "127.0.0.1":
                continue

            if ip_address not in mapping:
                mapping[ip_address] = []

            domain_name = asset_info[2].domain_name if asset_info[2] else ""
            subnet = asset_info[1].range if asset_info[1] else "0.0.0.0/0"

            mapping[ip_address].append(DomainItem(domain_name=domain_name, found=False, subnet=subnet))

        return mapping

    async def _fetch_slp_data(self, ip_addresses: list[str], x_api_key: str) -> list[SLPRecord]:
        """Fetches enrichment data from SLP API."""
        headers = {"Content-Type": "application/json", "X-API-KEY": x_api_key}
        data = {"ips": ip_addresses}

        response = httpx.post(  # noqa: ASYNC210
            "https://api.silentpush.com/api/v1/merge-api/explore/bulk/ip2asn/ipv4",
            json=data,
            headers=headers,
            timeout=None,
        )
        slp_response = msgspec.json.decode(response.content, type=SLPBulkResponse)

        if slp_response.status_code != 200 or slp_response.error:
            return []

        return [
            SLPRecord(
                ip=record.ip or "",
                domain=record.ip_ptr or "",
                subnet=record.subnet or "0.0.0.0/0",
                sp_risk_score=record.sp_risk_score if record.sp_risk_score is not None else "null",
                tag="SLP",
            )
            for record in slp_response.response.ip2asn
        ]

    def _mark_found_domains(
        self,
        slp_records: list[SLPRecord],
        domains_mapping: dict[str, list[DomainItem]],
    ) -> None:
        """Marks domains as found if they exist in SLP records."""
        for record in slp_records:
            if not record.ip or record.ip not in domains_mapping:
                continue

            for domain_item in domains_mapping[record.ip]:
                if domain_item.domain_name == record.domain:
                    domain_item.found = True

    def _merge_records(
        self,
        slp_records: list[SLPRecord],
        domains_mapping: dict[str, list[DomainItem]],
    ) -> list[SLPRecord]:
        """Merges SLP records with unfound domains from mapping."""
        result = slp_records.copy()

        for ip_address, domain_items in domains_mapping.items():
            if ip_address == "127.0.0.1":
                continue

            for domain_item in domain_items:
                if domain_item.found:
                    continue

                record = SLPRecord(
                    ip=ip_address,
                    domain=domain_item.domain_name,
                    tag="SLP_no",
                    sp_risk_score="null",
                    subnet=domain_item.subnet,
                )
                if record not in result:
                    result.append(record)

        return result

    @activity.defn
    async def store_data_from_slp(self, data: list[SLPRecord]) -> str:
        """
        This method stores data from SLP by calling a dedicated ISIM's REST API endpoint.
        :param data: data for storing
        :return: textual response obtained from the ISIM's REST API
        """
        async with httpx.AsyncClient() as client:
            payload = msgspec.to_builtins(data)
            response = await client.post(f"{self.isim_config.url}/slp_enrichment", json=payload)
            return response.text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.get_asset_info, self.get_data_from_slp, self.store_data_from_slp]
