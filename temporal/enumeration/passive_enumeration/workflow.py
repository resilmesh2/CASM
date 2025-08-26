import asyncio
from datetime import timedelta
from collections.abc import Awaitable, Callable, Sequence

from temporalio import workflow
from temporal.enumeration.passive_enumeration.activities import PassiveEnumerationActivities
from temporal.enumeration.ulitity_activities import UtilityActivities


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
                    start_to_close_timeout=timedelta(seconds=120),
                )
            )
            amass_task = tg.create_task(
                workflow.execute_activity(
                    PassiveEnumerationActivities.run_amass,
                    args=[domains],
                    start_to_close_timeout=timedelta(seconds=240),
                )
            )

        # Gather outputs from both tasks
        subfinder_results = await subfinder_task
        amass_results = await amass_task

        # Pass results into get_unique_hosts
        return await workflow.execute_activity(
            UtilityActivities.get_unique_subdomains,
            args=[subfinder_results, amass_results],
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        passive_enum_activities = PassiveEnumerationActivities(config.redis)
        utility_activities = UtilityActivities()
        return [*activities.get_activities(), utility_activities.get_unique_subdomains]