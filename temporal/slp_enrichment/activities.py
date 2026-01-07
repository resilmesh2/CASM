from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal

import httpx
import msgspec

from config import ISIMConfig
from temporalio import activity


# ISIM API models via msgspec.Struct
class ISIMIpItem(msgspec.Struct):
    address: str
    tag: str | None = None


class ISIMSubnetItem(msgspec.Struct):
    range: str | None = None


class ISIMDomainItem(msgspec.Struct):
    domain_name: str | None = None


AssetTriplet = tuple[ISIMIpItem, ISIMSubnetItem | None, ISIMDomainItem | None]


# Local aggregation structure for linking domains to IPs from DB
class DomainItem(msgspec.Struct):
    domain_name: str
    found: bool
    subnet: str


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
    async def get_asset_info(self) -> list[AssetTriplet]:
        """
        This method gets information about assets necessary for obtaining data from SLP.
        The most important are IP addresses, domain names, and subnets.
        :return: a list of assets from the ISIM's REST API
        """
        unprocessed_addresses: list[AssetTriplet] = []
        last_item_found: bool = False
        offset: int = 0
        limit: int = 100

        while len(unprocessed_addresses) < 100 and not last_item_found:
            params: dict[str, int] = {"limit": limit, "offset": offset}
            response = httpx.get(f"{self.isim_config.url}/ips", params=params)
            # Decode into typed structs
            decoded: list[AssetTriplet] = msgspec.json.decode(response.content, type=list[AssetTriplet])
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
    async def get_data_from_slp(
        self, response_json: list[AssetTriplet], x_api_key: str
    ) -> list[SLPRecord]:
        """
        This method obtains enrichment data from SLP - IP addresses, domain names,
        risk score, and subnets.
        :param response_json: contains a list of assets from the ISIM's REST API
        :param x_api_key: a key for the SLP's API
        :return: a list of assets from the SLP
        """
        domains_ips_for_storing: list[SLPRecord] = []
        ip_addresses_in_database: list[str] = []
        domains_ips_from_database: dict[str, list[DomainItem]] = {}

        for asset_info in response_json:
            ip_address: str = asset_info[0].address
            if ip_address == "127.0.0.1":
                # cannot obtain external information about localhost
                continue
            ip_addresses_in_database.append(ip_address)
            if ip_address not in domains_ips_from_database:
                domains_ips_from_database[ip_address] = []
            domain_name = asset_info[2].domain_name if asset_info[2] else ""
            subnet = asset_info[1].range if asset_info[1] else "0.0.0.0/0"
            domains_ips_from_database[ip_address].append(
                DomainItem(
                    domain_name=domain_name or "",
                    found=False,
                    subnet=subnet,
                )
            )

        headers = {"Content-Type": "application/json", "X-API-KEY": x_api_key}
        data: dict[str, list[str]] = {"ips": ip_addresses_in_database}

        response = httpx.post(
            "https://api.silentpush.com/api/v1/merge-api/explore/bulk/ip2asn/ipv4",
            json=data,
            headers=headers,
            timeout=None,
        )
        slp_response = msgspec.json.decode(response.content, type=SLPBulkResponse)

        if slp_response.status_code == 200 and not slp_response.error:
            for record in slp_response.response.ip2asn:
                tmp_record = SLPRecord(
                    ip=record.ip or "",
                    domain=record.ip_ptr or "",
                    subnet=record.subnet or "0.0.0.0/0",
                    sp_risk_score=record.sp_risk_score if record.sp_risk_score is not None else "null",
                    tag="SLP",
                )
                domains_ips_for_storing.append(tmp_record)

        for record in list(domains_ips_for_storing):
            tmp_ip_address = record.ip
            tmp_domain_name = record.domain
            if not tmp_ip_address:
                continue
            if tmp_ip_address in domains_ips_from_database:
                for domain_item in domains_ips_from_database[tmp_ip_address]:
                    if domain_item.domain_name == tmp_domain_name:
                        domain_item.found = True

        for ip_address in list(domains_ips_from_database.keys()):
            domains_ips_from_database[ip_address] = [i for i in domains_ips_from_database[ip_address] if not i.found]
        for ip_address in domains_ips_from_database:
            if ip_address == "127.0.0.1":
                # cannot obtain external information about it
                continue
            for ip_item in domains_ips_from_database[ip_address]:
                tmp_record = SLPRecord(
                    ip=ip_address,
                    domain=ip_item.domain_name,
                    tag="SLP_no",
                    sp_risk_score="null",
                    subnet=ip_item.subnet,
                )
                if tmp_record not in domains_ips_for_storing:
                    domains_ips_for_storing.append(tmp_record)

        return domains_ips_for_storing

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
