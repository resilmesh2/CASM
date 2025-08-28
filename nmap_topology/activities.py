from temporalio import activity
from nmap_topology.scanner import topology_scan_neo
from config import TopologyConfig, Neo4jConfig, ISIMConfig
from typing import Dict, Any
import requests
from collections.abc import Sequence, Callable, Awaitable


class NmapTopologyActivities:
    def __init__(self, topology_config: TopologyConfig, neo4j_config: Neo4jConfig, isim_config: ISIMConfig) -> None:
        self.topology_config = topology_config
        self.neo4j_config = neo4j_config
        self.isim_config = isim_config

    @activity.defn
    async def run_nmap_traceroute_scan(self) -> Dict[str, Any]:
        return topology_scan_neo(self.topology_config.targets)

    @activity.defn
    async def nmap_traceroute_neo4j(self, nmap_output: Dict[str, Any]) -> str:
        return requests.post(f"{self.isim_config.url}/traceroute", json=nmap_output).content.decode()

    @activity.defn
    async def compute_criticalities(self) -> None:
        requests.post(f"{self.isim_config.url}/nodes/betweenness_centrality")
        requests.post(f"{self.isim_config.url}/nodes/degree_centrality")

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_nmap_traceroute_scan, self.nmap_traceroute_neo4j, self.compute_criticalities]