from typing import Any, Sequence, Callable, Awaitable
import httpx
from temporalio import activity
from config import ISIMConfig


class SLPEnrichmentActivities:
    def __init__(self, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config

    @activity.defn
    async def get_asset_info(self) -> list[str]:
        response = httpx.get(f"{self.isim_config.url}/asset_info")
        response_json = response.json()
        return response_json

    @activity.defn
    async def get_data_from_slp(self, response_json: list[dict[str, Any]], x_api_key: str) -> list[dict[str, Any]]:
        domains_ips_for_storing = []
        ip_addresses_in_database = []
        domains_ips_from_database = {}
        for asset_info in response_json:
            ip_address = asset_info["ip"]
            ip_addresses_in_database.append(ip_address)
            if ip_address not in domains_ips_from_database:
                domains_ips_from_database[ip_address] = []
            for domain_name in asset_info["domain_names"]:
                domains_ips_from_database[ip_address].append({"domain_name": domain_name, "found": False,
                                                              "subnets": asset_info["subnets"] if asset_info[
                                                                  "subnets"] else ["0.0.0.0/0"]})

        headers = {'Content-Type': 'application/json',
                   'X-API-KEY': x_api_key}
        data = {"ips": ip_addresses_in_database}

        response = httpx.post("https://api.silentpush.com/api/v1/merge-api/explore/bulk/ip2asn/ipv4", json=data,
                              headers=headers, timeout=None)
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
                if "sp_risk_score" in record:
                    tmp_dictionary["sp_risk_score"] = record["sp_risk_score"]
                tmp_dictionary["tag"] = ["SLP"]
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
            for ip_item in domains_ips_from_database[ip_address]:
                for subnet in ip_item["subnets"]:
                    tmp_dictionary = {"ip": ip_address, "domain": ip_item["domain_name"],
                                      "tag": "SLP_no", "sp_risk_score": "null", "subnet": subnet}
                    if tmp_dictionary not in domains_ips_for_storing:
                        domains_ips_for_storing.append(tmp_dictionary)

        return domains_ips_for_storing

    @activity.defn
    async def store_data_from_slp(self, data: list[dict[str, Any]]) -> str:
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.isim_config.url}/slp_enrichment", json=data)
            return response.text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.get_asset_info, self.get_data_from_slp, self.store_data_from_slp]
