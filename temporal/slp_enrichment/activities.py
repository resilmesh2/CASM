from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal, TypedDict

import httpx
import msgspec
from temporalio import activity

from config import ISIMConfig
from temporal.slp_enrichment import dtos

#  TODO: This needs a further rework because ISIM api responses aren't clearly typed
ISIMIpsResponse = tuple[dtos.ISIMIpItem, dtos.ISIMSubnetItem | None, dtos.ISIMDomainItem | None, Any, Any]


class SLPRecordTD(TypedDict):
    ip: str | None
    domain: str | None
    subnet: str | None
    sp_risk_score: int | str
    tag: Literal["SLP", "SLP_no"]


class SLPApiError(Exception): ...


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
                item for item in decoded if not (item[0].tag is not None and "SLP" in item[0].tag)
            ][: 100 - len(unprocessed_addresses)]
            offset += limit
        return unprocessed_addresses

    @activity.defn
    async def get_data_from_slp(self, response_json: list[ISIMIpsResponse], x_api_key: str) -> list[SLPRecordTD]:
        """Obtains enrichment data from SLP - IP addresses, domain names, risk score, and subnets."""
        domains_ips_from_database = self._build_ip_domain_mapping(response_json)
        ip_addresses = list(domains_ips_from_database.keys())

        slp_records = await self._fetch_slp_data(ip_addresses, x_api_key)
        self._mark_found_domains(slp_records, domains_ips_from_database)

        return self._merge_records(slp_records, domains_ips_from_database)

    def _build_ip_domain_mapping(self, response_json: list[ISIMIpsResponse]) -> dict[str, list[dtos.DomainItem]]:
        """Builds mapping of IP addresses to domain items from response."""
        mapping: dict[str, list[dtos.DomainItem]] = {}

        for asset_info in response_json:
            ip_address = asset_info[0].address
            if ip_address == "127.0.0.1":
                continue

            if ip_address not in mapping:
                mapping[ip_address] = []

            domain_name = asset_info[2].domain_name if asset_info[2] else ""
            subnet = asset_info[1].range if asset_info[1] else "0.0.0.0/0"

            mapping[ip_address].append(dtos.DomainItem(domain_name=domain_name, found=False, subnet=subnet))

        return mapping

    async def _fetch_slp_data(self, ip_addresses: list[str], x_api_key: str) -> list[dtos.SLPRecord]:
        """Fetches enrichment data from SLP API."""
        headers = {"Content-Type": "application/json", "X-API-KEY": x_api_key}
        data = {"ips": ip_addresses}
        url = "https://api.silentpush.com/api/v1/merge-api/explore/bulk/ip2asn/ipv4"

        response = httpx.post(  # noqa: ASYNC210
            url,
            json=data,
            headers=headers,
            timeout=None,
        )
        slp_response = msgspec.json.decode(response.content, type=dtos.SLPBulkResponse)

        if response.status_code != 200:
            raise SLPApiError(
                f"Request to {url} failed with status code: {response.status_code} and content: {response.content}"
            )

        error = response.json().get("errors") or slp_response.error
        if error is not None:
            raise SLPApiError(f"Request to {url} failed with status code: {response.status_code} and error: {error}")

        return [
            dtos.SLPRecord(
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
        slp_records: list[dtos.SLPRecord],
        domains_mapping: dict[str, list[dtos.DomainItem]],
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
        slp_records: list[dtos.SLPRecord],
        domains_mapping: dict[str, list[dtos.DomainItem]],
    ) -> list[SLPRecordTD]:
        """Merges SLP records with unfound domains from mapping."""
        result = slp_records.copy()

        for ip_address, domain_items in domains_mapping.items():
            if ip_address == "127.0.0.1":
                continue

            for domain_item in domain_items:
                if domain_item.found:
                    continue

                record = dtos.SLPRecord(
                    ip=ip_address,
                    domain=domain_item.domain_name,
                    tag="SLP_no",
                    sp_risk_score="null",
                    subnet=domain_item.subnet,
                )
                if record not in result:
                    result.append(record)

        return msgspec.to_builtins(result)

    @activity.defn
    async def store_data_from_slp(self, data: list[SLPRecordTD]) -> str:
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
