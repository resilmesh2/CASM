from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import RedisConfig
from temporal.easm.active_enumeration import activities_impl
from temporalio import activity


class ActiveEnumerationActivities:
    def __init__(self, redis_config: RedisConfig) -> None:
        self.redis_config = redis_config

    @activity.defn
    async def run_dnsx_bruteforce(self, passive_scan_domains_uuid: str, wordlist: str, threads: str) -> str:
        return await activities_impl.run_dnsx_bruteforce(passive_scan_domains_uuid, wordlist, threads, self.redis_config)

    @activity.defn
    async def run_alterx(self, dnsx_output_uuid: str) -> str:
        return await activities_impl.run_alterx(dnsx_output_uuid, self.redis_config)

    @activity.defn
    async def run_dnsx_resolver(self, dnsx_output_uuid: str) -> str:
        return await activities_impl.run_dnsx_resolver(dnsx_output_uuid, self.redis_config)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_dnsx_bruteforce, self.run_alterx, self.run_dnsx_resolver]
