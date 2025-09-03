from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import requests

from config import ISIMConfig, Neo4jConfig, NmapTopologyConfig
from temporal.nmap.topology.scanner import topology_scan_neo
from temporalio import activity


class NmapTopologyActivities:
    def __init__(self, topology_config: NmapTopologyConfig, neo4j_config: Neo4jConfig, isim_config: ISIMConfig) -> None:
        self.topology_config = topology_config
        self.neo4j_config = neo4j_config
        self.isim_config = isim_config

    @activity.defn
    async def run_nmap_traceroute_scan(self) -> dict[str, Any]:
        return topology_scan_neo(self.topology_config.targets)

    @activity.defn
    async def nmap_traceroute_neo4j(self, nmap_output: dict[str, Any]) -> str:
        return requests.post(f"{self.isim_config.url}/traceroute", json=nmap_output).content.decode()

    @activity.defn
    async def compute_criticalities(self) -> None:
        requests.post(f"{self.isim_config.url}/nodes/betweenness_centrality")
        requests.post(f"{self.isim_config.url}/nodes/degree_centrality")

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_nmap_traceroute_scan, self.nmap_traceroute_neo4j, self.compute_criticalities]
