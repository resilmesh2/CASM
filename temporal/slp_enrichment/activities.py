from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal, TypedDict

import httpx
import msgspec

from config import ISIMConfig
from temporal.slp_enrichment import dtos
from temporalio import activity


class ISIMIpItemTD(TypedDict):
    address: str
    tag: list[str] | None


class ISIMSubnetItemTD(TypedDict):
    range: str | None


class ISIMDomainItemTD(TypedDict):
    domain_name: str | None
    tag: list[str] | None


class ISIMOrganizationUnitItemTD(TypedDict):
    name: str


class ISIMUriItemTD(TypedDict):
    identifier: str


#  TODO: This needs a further rework because ISIM api responses aren't clearly typed
ISIMIpsResponseType = tuple[
    ISIMIpItemTD,
    ISIMSubnetItemTD | None,
    ISIMDomainItemTD | None,
    ISIMOrganizationUnitItemTD | None,
    ISIMUriItemTD | None,
]


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
    async def get_asset_info(self) -> list[ISIMIpsResponseType]:
        """
        This method gets information about assets necessary for obtaining data from SLP.
        The most important are IP addresses, domain names, and subnets.
        :return: a list of assets from the ISIM's REST API
        """
        unprocessed_addresses: list[dtos.ISIMIpsResponse] = []
        last_item_found: bool = False
        offset: int = 0
        limit: int = 100

        while len(unprocessed_addresses) < 100 and not last_item_found:
            params: dict[str, int] = {"limit": limit, "offset": offset}
            response = httpx.get(f"{self.isim_config.url}/ips", params=params)  # noqa: ASYNC210
            # Decode into typed structs
            decoded = msgspec.json.decode(response.content, type=list[dtos.ISIMIpsResponse])
            if len(decoded) < limit:
                last_item_found = True
            unprocessed_addresses += [
                item for item in decoded if not (item[0].tag is not None and "SLP" in item[0].tag)
            ][: 100 - len(unprocessed_addresses)]
            offset += limit

        return msgspec.to_builtins(unprocessed_addresses)

    @activity.defn
    async def get_data_from_slp(self, response_json: list[ISIMIpsResponseType], x_api_key: str) -> list[SLPRecordTD]:
        """
        Obtain enrichment data from Silent Push (SLP) for a set of assets and return the
        combined result.

        Workflow:
        - Convert the loosely-typed `response_json` (coming from ISIM) into typed structs.
        - Build a mapping of IP -> potential domain candidates from ISIM data.
        - Query SLP bulk API for enrichment (domain `PTR`, subnet, risk score) for all IPs.
        - Mark domains that SLP confirmed as found.
        - Merge SLP records with any still-unmatched domain candidates so that every input
          IP/domain is represented in the output (unmatched items are tagged `SLP_no`).

        :param response_json: List of ISIM assets in tuple form
                              `(ISIMIpItemTD, ISIMSubnetItemTD | None, ISIMDomainItemTD | None,
                               ISIMOrganizationUnitItemTD | None, ISIMUriItemTD | None)`.
        :param x_api_key: API key for SLP passed as `X-API-KEY` header.
        :return: List of SLP records ready to be stored back to ISIM. Each record contains
                 `ip`, `domain`, `subnet`, `sp_risk_score`, and `tag` (either `SLP` for
                 SLP-confirmed or `SLP_no` for items not found by SLP).
        :raises SLPApiError: If the SLP API returns a non-200 status or an error payload.
        """
        isim_response_struct = msgspec.convert(response_json, type=list[dtos.ISIMIpsResponse])
        domains_ips_from_database = self._build_ip_domain_mapping(isim_response_struct)
        ip_addresses = list(domains_ips_from_database.keys())

        slp_records = await self._fetch_slp_data(ip_addresses, x_api_key)
        self._mark_found_domains(slp_records, domains_ips_from_database)

        return self._merge_records(slp_records, domains_ips_from_database)

    def _build_ip_domain_mapping(self, response_json: list[dtos.ISIMIpsResponse]) -> dict[str, list[dtos.DomainItem]]:
        """
        Build a mapping of IP addresses to candidate domain items derived from ISIM data.

        For each asset tuple, the method:
        - Skips loopback `127.0.0.1` as it is not a real external asset.
        - Uses the IP address as the key.
        - Extracts the domain name (may be empty string if absent) and subnet (defaults to `0.0.0.0/0`).
        - Initializes each domain candidate as not found (`found=False`).

        :param response_json: Typed list of ISIM asset tuples as `dtos.ISIMIpsResponse`.
        :return: Dict mapping `ip -> list[DomainItem]` where each `DomainItem` holds
                 `domain_name`, `found` flag, and `subnet`.
        """
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
        """
        Fetch enrichment data from the Silent Push bulk IP2ASN endpoint.

        Sends a single bulk request for all provided IPv4 addresses. The response is decoded
        using `msgspec` into `SLPBulkResponse`, validated for HTTP and payload errors, and then
        converted to a list of `dtos.SLPRecord` items (normalized for downstream storage).

        Notes:
        - `sp_risk_score` is preserved when present; otherwise the string "null" is used.
        - `subnet` defaults to `0.0.0.0/0` if not provided by SLP.
        - `domain` is sourced from `ip_ptr` field of the SLP response record.

        :param ip_addresses: List of IPv4 addresses to enrich.
        :param x_api_key: API key to be used in the `X-API-KEY` header when calling SLP.
        :return: List of normalized `dtos.SLPRecord` objects with `tag` set to `"SLP"`.
        :raises SLPApiError: When HTTP status is not 200 or payload contains `error`/`errors`.
        """
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
        """
        Update the domain mapping by marking candidates that SLP confirmed as present.

        For each record returned by SLP (already normalized to `dtos.SLPRecord`), if the
        record's `ip` exists in the `domains_mapping`, the matching `DomainItem` (matched by
        exact `domain_name`) is marked with `found=True`.

        :param slp_records: Records returned from SLP enrichment (tagged as `SLP`).
        :param domains_mapping: Mapping `ip -> list[DomainItem]` built from ISIM inputs.
        :return: None. The `domains_mapping` is updated in-place.
        """
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
        """
        Merge SLP-confirmed records with any remaining domain candidates not found by SLP.

        The result ensures that every input IP/domain candidate is represented:
        - All records returned by SLP are included and tagged `SLP`.
        - For each IP in `domains_mapping`, if a domain candidate has not been marked as found,
          create a synthetic record with `tag='SLP_no'`, `sp_risk_score='null'`, and the
          subnet from the candidate. Duplicate records are avoided.
        - Loopback IP `127.0.0.1` is ignored.

        :param slp_records: Records obtained from SLP (already normalized to `dtos.SLPRecord`).
        :param domains_mapping: Mapping `ip -> list[DomainItem]` with `found` flags updated.
        :return: List of records suitable for persistence, converted to built-in types
                 via `msgspec.to_builtins`.
        """
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
