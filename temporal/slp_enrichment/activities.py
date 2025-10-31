from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import httpx
from temporalio import activity

from config import ISIMConfig


class SLPEnrichmentActivities:
    """
    Activities for performing enrichment of information about assets obtained from SLP.
    """

    def __init__(self, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config

    @activity.defn
    async def get_asset_info(self) -> list[list[dict[str, Any] | None]]:
        """
        This method gets information about assets necessary for obtaining data from SLP.
        The most important are IP addresses, domain names, and subnets.
        :return: a list of assets from the ISIM's REST API
        """
        unprocessed_addresses = []
        last_item_found = False
        offset = 0
        limit = 100

        while len(unprocessed_addresses) < 100 and not last_item_found:
            params = {"limit": limit, "offset": offset}
            response = httpx.get(f"{self.isim_config.url}/ips", params=params)
            response_json = response.json()
            if len(response_json) < limit:
                last_item_found = True
            unprocessed_addresses += [
                item for item in response_json if not ("tag" in item[0] and "SLP" in item[0]["tag"])
            ][: 100 - len(unprocessed_addresses)]
            offset += limit
        return unprocessed_addresses

    @activity.defn
    async def get_data_from_slp(
        self, response_json: list[list[dict[str, Any] | None]], x_api_key: str
    ) -> list[dict[str, Any]]:
        """
        This method obtains enrichment data from SLP - IP addresses, domain names,
        risk score, and subnets.
        :param response_json: contains a list of assets from the ISIM's REST API
        :param x_api_key: a key for the SLP's API
        :return: a list of assets from the SLP
        """
        domains_ips_for_storing = []
        ip_addresses_in_database = []
        domains_ips_from_database = {}

        for asset_info in response_json:
            ip_address = asset_info[0]["address"]
            if ip_address == "127.0.0.1":
                # cannot obtain external information about localhost
                continue
            ip_addresses_in_database.append(ip_address)
            if ip_address not in domains_ips_from_database:
                domains_ips_from_database[ip_address] = []
            domain_name = asset_info[2]["domain_name"] if asset_info[2] and "domain_name" in asset_info[2] else ""
            domains_ips_from_database[ip_address].append(
                {
                    "domain_name": domain_name,
                    "found": False,
                    "subnet": asset_info[1]["range"] if asset_info[1] else ["0.0.0.0/0"],
                }
            )

        headers = {"Content-Type": "application/json", "X-API-KEY": x_api_key}
        data = {"ips": ip_addresses_in_database}

        response = httpx.post(
            "https://api.silentpush.com/api/v1/merge-api/explore/bulk/ip2asn/ipv4",
            json=data,
            headers=headers,
            timeout=None,
        )
        response_json = response.json()

        if response_json["status_code"] == 200 and not response_json["error"]:
            for record in response_json["response"]["ip2asn"]:
                tmp_dictionary = {}
                if "ip" in record:
                    tmp_dictionary["ip"] = record["ip"]
                if "ip_ptr" in record:
                    tmp_dictionary["domain"] = record["ip_ptr"]
                else:
                    tmp_dictionary["domain"] = ""
                if "subnet" in record:
                    tmp_dictionary["subnet"] = record["subnet"]
                else:
                    tmp_dictionary["subnet"] = "0.0.0.0/0"
                if "sp_risk_score" in record:
                    tmp_dictionary["sp_risk_score"] = record["sp_risk_score"]
                else:
                    tmp_dictionary["sp_risk_score"] = "null"
                tmp_dictionary["tag"] = "SLP"
                domains_ips_for_storing.append(tmp_dictionary)

        for record in domains_ips_for_storing:
            if "ip" not in record or "domain" not in record:
                continue
            tmp_ip_address = record["ip"]
            tmp_domain_name = record["domain"]
            if tmp_ip_address in domains_ips_from_database:
                for domain_item in domains_ips_from_database[tmp_ip_address]:
                    if domain_item["domain_name"] == tmp_domain_name:
                        domain_item["found"] = True

        for ip_address in domains_ips_from_database:
            domains_ips_from_database[ip_address] = [i for i in domains_ips_from_database[ip_address] if not i["found"]]
        for ip_address in domains_ips_from_database:
            if ip_address == "127.0.0.1":
                # cannot obtain external information about it
                continue
            for ip_item in domains_ips_from_database[ip_address]:
                tmp_dictionary = {
                    "ip": ip_address,
                    "domain": ip_item["domain_name"],
                    "tag": "SLP_no",
                    "sp_risk_score": "null",
                    "subnet": ip_item["subnet"],
                }
                if tmp_dictionary not in domains_ips_for_storing:
                    domains_ips_for_storing.append(tmp_dictionary)

        return domains_ips_for_storing

    @activity.defn
    async def store_data_from_slp(self, data: list[dict[str, Any]]) -> str:
        """
        This method stores data from SLP by calling a dedicated ISIM's REST API endpoint.
        :param data: data for storing
        :return: textual response obtained from the ISIM's REST API
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.isim_config.url}/slp_enrichment", json=data)
            return response.text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.get_asset_info, self.get_data_from_slp, self.store_data_from_slp]
