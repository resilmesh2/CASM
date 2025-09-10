from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import RedisConfig
from temporal.enumeration.active_enumeration import activities_impl
from temporalio import activity


class ActiveEnumerationActivities:
    def __init__(self, redis_config: RedisConfig) -> None:
        self.redis_config = redis_config

    @activity.defn
    async def active_dnsx(self, passive_scan_domains_uuid: str, wordlist: str) -> str:
        return await activities_impl.active_dnsx(passive_scan_domains_uuid, wordlist, self.redis_config)

    @activity.defn
    async def active_alterx_with_dnsx(self, dnsx_output_uuid: str) -> str:
        return await activities_impl.active_alterx_with_dnsx(dnsx_output_uuid, self.redis_config)

    @activity.defn
    async def active_httpx(self, alterx_domains_uuid: str) -> str:
        return await activities_impl.active_httpx(alterx_domains_uuid, self.redis_config)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.active_dnsx, self.active_httpx, self.active_alterx_with_dnsx]
