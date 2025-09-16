from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import RedisConfig
from temporal.easm.passive_enumeration import activities_impl
from temporalio import activity


class PassiveEnumerationActivities:
    def __init__(self, redis_config: RedisConfig) -> None:
        self.redis_config = redis_config

    @activity.defn
    async def run_subfinder(self, domains: list[str]) -> str:
        return await activities_impl.run_subfinder(domains, self.redis_config)

    @activity.defn
    async def run_amass(self, domains: list[str]) -> str:
        return await activities_impl.run_amass(domains, self.redis_config)

    @activity.defn
    async def get_unique_subdomains(self, domains_uuids: list[str]) -> str:
        return await activities_impl.get_unique_subdomains(self.redis_config, domains_uuids)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_amass, self.run_subfinder, self.get_unique_subdomains]
