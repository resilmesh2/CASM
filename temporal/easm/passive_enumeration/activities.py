from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from temporalio import activity

from config import RedisConfig
from temporal.easm.passive_enumeration import activities_impl


class PassiveEnumerationActivities:
    """
    Activities for passive subdomain enumeration using external tools.
    """

    def __init__(self, redis_config: RedisConfig) -> None:
        self.redis_config = redis_config

    @activity.defn
    async def run_subfinder(self, domains: list[str]) -> str:
        """
        Run subfinder in passive mode against the provided root domains.

        :param domains: List of root domains to enumerate.
        :return: Redis key where subfinder output (newline-separated) is stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If subfinder execution fails.
        """
        return await activities_impl.run_subfinder(domains, self.redis_config)

    @activity.defn
    async def run_amass(self, domains: list[str]) -> str:
        """
        Run amass in passive mode against the provided root domains.

        :param domains: List of root domains to enumerate.
        :return: Redis key where amass output (newline-separated) is stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If amass execution fails.
        """
        return await activities_impl.run_amass(domains, self.redis_config)

    @activity.defn
    async def get_unique_subdomains(self, domains_uuids: list[str]) -> str:
        """
        Merge multiple Redis keys with subdomain lists into a unique, de-duplicated set.

        :param domains_uuids: Redis keys containing newline-separated subdomains.
        :return: Redis key where the merged unique subdomains are stored.
        :raises temporal.lib.exceptions.NoDomainsFoundError: If no domains are found in inputs.
        """
        return await activities_impl.get_unique_subdomains(self.redis_config, domains_uuids)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_amass, self.run_subfinder, self.get_unique_subdomains]
