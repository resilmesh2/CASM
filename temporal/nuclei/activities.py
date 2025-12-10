from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import ISIMConfig, NmapBasicConfig
from temporal.nmap.basic.dtos import NmapResults
from temporalio import activity


class NucleiActivities:
    """
    Activities to run a basic nmap scan, parse results, and publish them to ISIM.
    """

    def __init__(self, isim_config: ISIMConfig, redis_config: RedisConfig, neo4j_config: Neo4jConfig) -> None:
        self.isim_config = isim_config
        self.redis_config = redis_config
        self.neo4j_config = neo4j_config


    @activity.defn
    async def validate_input(self, input_: dict[str, Any]) -> NmapBasicConfig: ...

    @activity.defn
    async def get_targets(self, input_: dict[str, Any]) -> NmapBasicConfig: ...

    @activity.defn
    async def check_latest_cve_changes(self, targets: list[str], arguments: str) -> None: ...

    @activity.defn
    async def run_nuclei(self, targets: list[str], arguments: str) -> NmapResults: ...

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
