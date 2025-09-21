from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import httpx

from config import ISIMConfig, NmapTopologyConfig
from temporal.lib import util
from temporal.nmap.topology.scanner import topology_scan_neo
from temporalio import activity


class NmapTopologyActivities:
    def __init__(self, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config

    @activity.defn
    async def nmap_topology_validate_input(self, input_: dict[str, Any]) -> NmapTopologyConfig:
        obj_input = NmapTopologyConfig(**input_)
        if not all(map(util.validate_input_hostname, obj_input.targets)):
            raise ValueError("Invalid targets!")
        return obj_input

    @activity.defn
    async def run_nmap_traceroute_scan(self, targets: list[str]) -> dict[str, Any]:
        return topology_scan_neo(targets)

    @activity.defn
    async def nmap_traceroute_neo4j(self, nmap_output: dict[str, Any]) -> str:
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.isim_config.url}/traceroute", json=nmap_output)
            return response.text

    @activity.defn
    async def compute_criticalities(self) -> None:
        async with httpx.AsyncClient() as client:
            await client.post(f"{self.isim_config.url}/nodes/betweenness_centrality")
            await client.post(f"{self.isim_config.url}/nodes/degree_centrality")

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_nmap_traceroute_scan, self.nmap_traceroute_neo4j, self.compute_criticalities, self.nmap_topology_validate_input]
