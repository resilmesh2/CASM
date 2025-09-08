from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import RedisConfig
from temporal.enumeration.passive_enumeration import activities_impl
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

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_amass, self.run_subfinder]
