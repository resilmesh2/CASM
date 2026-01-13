import asyncio
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

from config import AppConfig
from temporal.easm.passive_enumeration.activities import PassiveEnumerationActivities


@workflow.defn
class PassiveEnumerationWorkflow:
    @workflow.run
    async def run(self, domains: list[str]) -> str:
        """Runs Subfinder + Amass in parallel for each seed domain, joins the result and outputs CSV file."""

        async with asyncio.TaskGroup() as tg:
            subfinder_task = tg.create_task(
                workflow.execute_activity(
                    PassiveEnumerationActivities.run_subfinder,
                    args=[domains],
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=RetryPolicy(
                        maximum_attempts=1,
                    ),
                )
            )
            amass_task = tg.create_task(
                workflow.execute_activity(
                    PassiveEnumerationActivities.run_amass,
                    args=[domains],
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=RetryPolicy(
                        maximum_attempts=1,
                    ),
                )
            )

        # Gather outputs from both tasks
        subfinder_results_uuid = await subfinder_task
        amass_results_uuid = await amass_task

        # Pass results into get_unique_hosts
        return await workflow.execute_activity(
            PassiveEnumerationActivities.get_unique_subdomains,
            args=[[subfinder_results_uuid, amass_results_uuid]],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=2,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "NoDomainsFoundError"],
            ),
            start_to_close_timeout=timedelta(seconds=60),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = PassiveEnumerationActivities(config.redis)
        return [*activities.get_activities()]
