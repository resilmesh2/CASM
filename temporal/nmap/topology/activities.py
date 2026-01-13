from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import httpx
from temporalio import activity

from config import ISIMConfig, NmapTopologyConfig
from temporal.lib import util
from temporal.nmap.topology.scanner import topology_scan_neo


class NmapTopologyActivities:
    """
    Activities to validate input, perform nmap traceroute scans, and publish/compute topology metrics in ISIM.
    """

    def __init__(self, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config

    @activity.defn
    async def nmap_topology_validate_input(self, input_: dict[str, Any]) -> NmapTopologyConfig:
        """
        Validate and normalize the incoming nmap topology configuration.

        :param input_: Mapping with fields expected by NmapTopologyConfig (e.g., targets).
        :return: A validated NmapTopologyConfig instance.
        :raises ValueError: If any provided target hostname/IP is invalid.
        """
        obj_input = NmapTopologyConfig(**input_)
        if not all(map(util.validate_input_hostname, obj_input.targets)):
            raise ValueError("Invalid targets!")
        return obj_input

    @activity.defn
    async def run_nmap_traceroute_scan(self, targets: list[str]) -> dict[str, Any]:
        """
        Run nmap in ping + traceroute mode against provided targets and return hop data.

        :param targets: List of hostnames/IPs or CIDR ranges to scan.
        :return: Dictionary with timestamp and connection hop details per destination.
        """
        return topology_scan_neo(targets)

    @activity.defn
    async def nmap_traceroute_neo4j(self, nmap_output: dict[str, Any]) -> str:
        """
        Post-traceroute results to the ISIM topology endpoint.

        :param nmap_output: Output from run_nmap_traceroute_scan to be posted.
        :return: The response body returned by the ISIM API.
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.isim_config.url}/traceroute", json=nmap_output)
            return response.text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [
            self.run_nmap_traceroute_scan,
            self.nmap_traceroute_neo4j,
            self.nmap_topology_validate_input,
        ]
