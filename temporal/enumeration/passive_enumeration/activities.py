import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from redis import Redis

from temporalio import activity

from config import RedisConfig


class PassiveEnumerationActivities:
    def __init__(self, redis_config: RedisConfig, domains: list[str]) -> None:
        self.redis_config = redis_config
        self.domains = domains

    @activity.defn
    async def run_subfinder(self) -> str:
        subfinder_scan_uuid = await activities_impl.run_subfinder(self.domains, self.redis_config)
        return subfinder_scan_uuid

    @activity.defn
    async def run_amass(self) -> str:
        amass_scan_uuid = await activities_impl.run_amass(self.domains, self.redis_config)
        return amass_scan_uuid


    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_amass, self.run_subfinder]
