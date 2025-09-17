from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from temporalio.common import RetryPolicy

from config import AppConfig
from temporal.easm.active_enumeration.activities import ActiveEnumerationActivities
from temporalio import workflow


@workflow.defn
class ActiveEnumeratonWorkflow:
    @workflow.run
    async def run(self, passive_scan_domains_uuid: str, wordlist: str, threads: str) -> str:
        # Active bruteforce
        dnsx_result_uuid = await workflow.execute_activity(
            ActiveEnumerationActivities.run_dnsx_bruteforce,
            args=[passive_scan_domains_uuid, wordlist, threads],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=2,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "EnumerationToolError"],
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

        alterx_uuid = await workflow.execute_activity(
            ActiveEnumerationActivities.run_alterx,
            args=[dnsx_result_uuid],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=2,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "EnumerationToolError"],
            ),
            start_to_close_timeout=timedelta(minutes=30),
        )

        return await workflow.execute_activity(
            ActiveEnumerationActivities.run_dnsx_resolver,
            args=[alterx_uuid],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=2,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "EnumerationToolError"],
            ),
            start_to_close_timeout=timedelta(minutes=10),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = ActiveEnumerationActivities(config.redis)
        return [*activities.get_activities()]
