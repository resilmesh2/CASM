from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import AppConfig
from temporal.enumeration.active_enumeration.activities import ActiveEnumerationActivities
from temporal.enumeration.active_enumeration.workflow import ActiveEnumeratonWorkflow
from temporal.enumeration.passive_enumeration.activities import PassiveEnumerationActivities
from temporal.enumeration.passive_enumeration.workflow import PassiveEnumerationWorkflow
from temporal.enumeration.ulitity_activities import UtilityActivities
from temporalio import workflow


@workflow.defn
class CompleteScanWorkflow:
    @workflow.run
    async def run(self, domains: list[str], wordlist: str,) -> str:
        passive_result = await workflow.execute_child_workflow(
            PassiveEnumerationWorkflow.run,
            args=[domains],
            id=f"passive-{workflow.info().workflow_id}",
            task_queue="subdomain-task-queue",
        )

        # 2) Active
        active_result: str = await workflow.execute_child_workflow(
            ActiveEnumeratonWorkflow.run,
            args=[passive_result, wordlist],
            id=f"active-{workflow.info().workflow_id}",
            task_queue="subdomain-task-queue",
        )

        return active_result

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        passive_enum_activities = PassiveEnumerationActivities(config.redis, config.scanner.domains)
        active_enum_activities = ActiveEnumerationActivities(config.redis)
        utility_activities = UtilityActivities()
        return [*passive_enum_activities.get_activities(), *active_enum_activities.get_activities(), *utility_activities.get_unique_subdomains]
