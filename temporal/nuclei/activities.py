from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import ISIMUrlsConfig, Neo4jConfig, RedisConfig
from temporal.lib import redis_handler
from temporal.nuclei import activities_impl
from temporalio import activity


class NucleiActivities:
    """
    Activities to run a basic nmap scan, parse results, and publish them to ISIM.
    """

    def __init__(
        self,
        isim_urls: ISIMUrlsConfig,
        redis_config: RedisConfig,
        neo4j_config: Neo4jConfig,
    ) -> None:
        self.isim_urls = isim_urls
        self.redis_config = redis_config
        self.neo4j_config = neo4j_config
        self.valkey_client = redis_handler.get_redis()

    @activity.defn
    async def update_nuclei(self) -> None:
        await activities_impl.update_nuclei()

    @activity.defn
    async def get_network_service_data(self) -> str:
        return await activities_impl.get_network_service_data(self.isim_urls, self.valkey_client)

    @activity.defn
    async def parse_network_service_data_for_nuclei_run(self, network_service_data_uuid: str) -> str:
        return activities_impl.parse_data_for_nuclei_scan(self.valkey_client, network_service_data_uuid)

    @activity.defn
    async def run_nuclei(self, service_data_for_nuclei_uuid: str) -> str:
        return await activities_impl.run_nuclei_on_all_targets(self.valkey_client, service_data_for_nuclei_uuid)

    @activity.defn
    async def update_cve_lifecycle_info(self, cve_status_uuid: str) -> None:
        activities_impl.update_vulnerability_status(self.neo4j_config, self.valkey_client, cve_status_uuid)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [
            self.update_nuclei,
            self.get_network_service_data,
            self.parse_network_service_data_for_nuclei_run,
            self.run_nuclei,
            self.update_cve_lifecycle_info,
        ]
