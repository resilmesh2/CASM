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
    async def get_network_service_data(self) -> None:
        await activities_impl.get_network_service_data(self.isim_graphql_config, self.valkey_client)

    @activity.defn
    async def parse_network_service_data_for_nuclei_run(self, targets: list[str], arguments: str) -> None: ...
        await activities_impl.parse_data_for_nuclei_scan()
    @activity.defn
    async def run_nuclei(self, targets: list[str], arguments: str) -> NucleiConfig: ...

    @activity.defn
    async def parse_nuclei_results(self) -> None: ...

    @activity.defn
    async def update_cve_lifecycle_info(self) -> None: ...

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [
            self.get_targets,
            self.check_latest_cve_changes,
            self.run_nuclei,
            self.parse_nuclei_results,
            self.update_cve_lifecycle_info,
        ]
