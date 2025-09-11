from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from config import AppConfig
from temporal.enumeration.active_enumeration.activities import ActiveEnumerationActivities
from temporal.enumeration.ulitity_activities import UtilityActivities
from temporalio import workflow


@workflow.defn
class ActiveEnumeratonWorkflow:
    @workflow.run
    async def run(self, passive_scan_domains_uuid: str, wordlist: str) -> str:
        # Active bruteforce
        dnsx_result_uuid = await workflow.execute_activity(
            ActiveEnumerationActivities.run_dnsx,
            args=[passive_scan_domains_uuid, wordlist],
            start_to_close_timeout=timedelta(minutes=5),
        )

        # Permutation scan using the results from bruteforce and passive
        alterx_result_uuid = await workflow.execute_activity(
            ActiveEnumerationActivities.run_alterx_with_dnsx,
            args=[dnsx_result_uuid],
            start_to_close_timeout=timedelta(minutes=30),
        )

        return await workflow.execute_activity(
            ActiveEnumerationActivities.run_httpx, args=[alterx_result_uuid], start_to_close_timeout=timedelta(minutes=5)
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        active_enum_activities = ActiveEnumerationActivities(config.redis)
        utility_activities = UtilityActivities(config.redis)
        return [*active_enum_activities.get_activities(), utility_activities.get_unique_subdomains]
