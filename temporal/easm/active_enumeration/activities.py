from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from temporalio import activity

from config import RedisConfig
from temporal.easm.active_enumeration import activities_impl


class ActiveEnumerationActivities:
    def __init__(self, redis_config: RedisConfig) -> None:
        self.redis_config = redis_config

    @activity.defn
    async def run_dnsx_bruteforce(self, passive_scan_domains_uuid: str, wordlist: str, threads: str) -> str:
        """
        Run dnsx in bruteforce mode against passively discovered domains.

        :param passive_scan_domains_uuid: Redis key holding newline-separated domains from passive enum.
        :param wordlist: Path to a subdomain wordlist used for bruteforcing.
        :param threads: Number of threads to use by dnsx.
        :return: Redis key where dnsx bruteforce results are stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If the dnsx command fails.
        """
        return await activities_impl.run_dnsx_bruteforce(
            passive_scan_domains_uuid, wordlist, threads, self.redis_config
        )

    @activity.defn
    async def run_alterx(self, dnsx_output_uuid: str) -> str:
        """
        Generate domain permutations using alterx based on dnsx output and store results.

        :param dnsx_output_uuid: Redis key pointing to dnsx results to feed into alterx.
        :return: Redis key where alterx-generated domains are stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If the alterx command fails.
        """
        return await activities_impl.run_alterx(dnsx_output_uuid, self.redis_config)

    @activity.defn
    async def run_dnsx_resolver(self, dnsx_output_uuid: str) -> str:
        """
        Resolve and validate subdomains produced by bruteforce/alterx using dnsx.

        :param dnsx_output_uuid: Redis key pointing to candidate subdomains.
        :return: Redis key where resolvable/valid subdomains are stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If the dnsx command fails.
        """
        return await activities_impl.run_dnsx_resolver(dnsx_output_uuid, self.redis_config)

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_dnsx_bruteforce, self.run_alterx, self.run_dnsx_resolver]
