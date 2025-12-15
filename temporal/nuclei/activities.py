from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import ISIMConfig, RedisConfig, Neo4jConfig, ISIMGraphqlConfig
from temporalio import activity
from temporal.nuclei import activities_impl
from valkey import Valkey


class NucleiActivities:
    """
    Activities to run a basic nmap scan, parse results, and publish them to ISIM.
    """

    def __init__(self, isim_config: ISIMConfig, isim_graphql_config: ISIMGraphqlConfig, redis_config: RedisConfig, neo4j_config: Neo4jConfig) -> None:
        self.isim_config = isim_config
        self.isim_graphql_config = isim_graphql_config
        self.redis_config = redis_config
        self.neo4j_config = neo4j_config
        self.valkey_client = Valkey(host=redis_config.host, port=redis_config.port, db=3)

    @activity.defn
    async def update_nuclei(self) -> None:
        await activities_impl.update_nuclei()

    @activity.defn
    async def get_network_service_data(self) -> str:
        return await activities_impl.get_network_service_data(self.isim_graphql_config, self.valkey_client)

    @activity.defn
    async def parse_network_service_data_for_nuclei_run(self, network_service_data_uuid: str) -> str:
        return activities_impl.parse_data_for_nuclei_scan(self.valkey_client, network_service_data_uuid)

    @activity.defn
    async def run_nuclei(self, service_data_for_nuclei_uuid: str) -> str:
        return await activities_impl.run_nuclei_on_all_targets(self.valkey_client, service_data_for_nuclei_uuid)

    @activity.defn
    async def update_cve_lifecycle_info(self, cve_status_uuid: str) -> None:
        await activities_impl.update_vulnerability_status(self.neo4j_config, self.valkey_client, cve_status_uuid)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [
            self.update_nuclei,
            self.get_network_service_data,
            self.parse_network_service_data_for_nuclei_run,
            self.run_nuclei,
            self.update_cve_lifecycle_info,
        ]
