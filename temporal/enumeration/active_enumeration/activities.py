import json
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import httpx

from config import RedisConfig, ISIMConfig
from temporal.enumeration.active_enumeration import activities_impl
from temporalio import activity


class ActiveEnumerationActivities:
    def __init__(self, redis_config: RedisConfig, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config
        self.redis_config = redis_config

    @activity.defn
    async def run_dnsx(self, passive_scan_domains_uuid: str, wordlist: str) -> str:
        return await activities_impl.run_dnsx(passive_scan_domains_uuid, wordlist, self.redis_config)

    @activity.defn
    async def run_alterx_with_dnsx(self, dnsx_output_uuid: str) -> str:
        return await activities_impl.run_alterx_with_dnsx(dnsx_output_uuid, self.redis_config)

    @activity.defn
    async def run_httpx(self, alterx_domains_uuid: str) -> str:
        return await activities_impl.run_httpx(alterx_domains_uuid, self.redis_config)

    @activity.defn
    async def parse_result_and_send_to_api(self, active_httpx_result_uuid: str):
        parsed_httpx = await activities_impl.parse_httpx_output(active_httpx_result_uuid, self.redis_config)
        payload = json.dumps(parsed_httpx)
        headers = {"Content-Type": "application/json"}

        async with httpx.AsyncClient() as conn:
            return (await conn.post(f"{self.isim_config.url}/easm", json=payload, headers=headers)).text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_dnsx, self.run_httpx, self.run_alterx_with_dnsx]
