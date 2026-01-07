from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from temporal.easm.passive_enumeration import activities_impl
from temporalio import activity


class PassiveEnumerationActivities:
    """
    Activities for passive subdomain enumeration using external tools.
    """

    @activity.defn
    async def run_subfinder(self, domains: list[str]) -> str:
        """
        Run subfinder in passive mode against the provided root domains.

        :param domains: List of root domains to enumerate.
        :return: Redis key where subfinder output (newline-separated) is stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If subfinder execution fails.
        """
        return await activities_impl.run_subfinder(domains)

    @activity.defn
    async def run_amass(self, domains: list[str]) -> str:
        """
        Run amass in passive mode against the provided root domains.

        :param domains: List of root domains to enumerate.
        :return: Redis key where amass output (newline-separated) is stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If amass execution fails.
        """
        return await activities_impl.run_amass(domains)

    @activity.defn
    async def get_unique_subdomains(self, domains_uuids: list[str]) -> str:
        """
        Merge multiple Redis keys with subdomain lists into a unique, de-duplicated set.

        :param domains_uuids: Redis keys containing newline-separated subdomains.
        :return: Redis key where the merged unique subdomains are stored.
        :raises temporal.lib.exceptions.NoDomainsFoundError: If no domains are found in inputs.
        """
        return await activities_impl.get_unique_subdomains(domains_uuids)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_amass, self.run_subfinder, self.get_unique_subdomains]
