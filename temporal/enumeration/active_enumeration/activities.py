import asyncio
import os
from collections.abc import Sequence, Callable, Awaitable
from typing import List, Any
from temporalio import activity
from temporal.lib import util
from temporal.enumeration.active_enumeration import activities_impl


class ActiveEnumerationActivities:
    def __init__(self, redis_config: RedisConfig) -> None:
        self.redis_config = redis_config

    @activity.defn
    async def active_dnsx(self, domains: list[str], wordlist: str) -> str:
        dnsx_result_uuid = await activities_impl.active_dnsx(domains, wordlist, self.redis_config)
        return dnsx_result_uuid

    @activity.defn
    async def active_alterx(self, dnsx_output_uuid: str, redis_config: RedisConfig) -> str:
        alterx_result_uuid = await activities_impl.active_alterx(dnsx_output_uuid, self.redis_config)
        return alterx_result_uuid

    @activity.defn
    async def active_httpx(self, alterx_domains_uuid: str) -> str:
        httpx_result_uuid = await activities_impl.active_httpx(alterx_domains_uuid, self.redis_config)
        return httpx_result_uuid

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.active_dnsx, self.active_httpx, self.active_alterx]